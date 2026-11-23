/* Offline counterpart to the original CPSC 4240 pcap_analyze.py logic.
 * No network calls, backend, external libraries, or dependencies.
 * Supports classic PCAP and common PCAPNG with Ethernet/IPv4 traffic.
 */
'use strict';
(function (root) {
  const NORMAL_PORTS = new Set([53, 80, 443, 123]);
  const UNSAFE_PORTS = new Map([[21, 'FTP'], [23, 'Telnet'], [80, 'HTTP']]);
  const MAX_BYTES = 50 * 1024 * 1024;
  const BURST_COUNT = 5;
  const BURST_WINDOW = 30;

  function u16(view, off, le) { return view.getUint16(off, le); }
  function u32(view, off, le) { return view.getUint32(off, le); }
  function macIp(view, off) {
    return [0, 1, 2, 3].map(i => view.getUint8(off + i)).join('.');
  }
  function decodeIp(view, offset, length, linkType) {
    const end = offset + length;
    let pos = offset;
    if (linkType === 1) { // Ethernet II, including VLAN tagging
      if (pos + 14 > end) return null;
      let etherType = view.getUint16(pos + 12, false);
      pos += 14;
      for (let tags = 0; tags < 4 && [0x8100, 0x88a8, 0x9100].includes(etherType); tags++) {
        if (pos + 4 > end) return null;
        etherType = view.getUint16(pos + 2, false);
        pos += 4;
      }
      if (etherType !== 0x0800) return null;
    } else if (linkType === 127 || linkType === 105) { // 802.11 / radiotap
      if (linkType === 127) {
        if (pos + 8 > end || view.getUint8(pos) !== 0) return null;
        const radiotapLength = u16(view, pos + 2, true);
        if (radiotapLength < 8 || pos + radiotapLength > end) return null;
        pos += radiotapLength;
      }
      if (pos + 24 > end) return null;
      const fc = u16(view, pos, true);
      const type = (fc >> 2) & 3;
      if (type !== 2 || (fc & 0x4000)) return null; // Only unencrypted data frames
      const ds = (fc >> 8) & 3;
      const qos = ((fc >> 4) & 8) !== 0;
      let headerSize = 24 + (ds === 3 ? 6 : 0) + (qos ? 2 : 0) + (qos && (fc & 0x8000) ? 4 : 0);
      if (pos + headerSize + 8 > end) return null;
      pos += headerSize;
      // LLC/SNAP encapsulation, with EtherType IPv4.
      if (view.getUint8(pos) !== 0xaa || view.getUint8(pos + 1) !== 0xaa ||
          view.getUint8(pos + 2) !== 0x03 || u16(view, pos + 6, false) !== 0x0800) return null;
      pos += 8;
    } else if (linkType === 101 || linkType === 228) { // Raw IPv4
      // IP header begins immediately.
    } else if (linkType === 113) { // Linux cooked v1
      if (pos + 16 > end || u16(view, pos + 14, false) !== 0x0800) return null;
      pos += 16;
    } else if (linkType === 276) { // Linux cooked v2
      if (pos + 20 > end || u16(view, pos, false) !== 0x0800) return null;
      pos += 20;
    } else if (linkType === 0) { // BSD loopback
      if (pos + 4 > end || !([2, 0x02000000].includes(u32(view, pos, true)))) return null;
      pos += 4;
    } else {
      return null;
    }
    if (pos + 20 > end) return null;
    const version = view.getUint8(pos) >> 4;
    const ihl = (view.getUint8(pos) & 15) * 4;
    if (version !== 4 || ihl < 20 || pos + ihl > end) return null;
    const iplen = u16(view, pos + 2, false);
    const ipend = Math.min(end, pos + Math.max(iplen, ihl));
    const src = macIp(view, pos + 12);
    const dst = macIp(view, pos + 16);
    const proto = view.getUint8(pos + 9);
    const fragment = u16(view, pos + 6, false) & 0x1fff;
    let sport = null, dport = null, syn = false, http = false;
    let dns = false;
    const payload = pos + ihl;
    if (fragment === 0 && proto === 6 && payload + 20 <= ipend) {
      sport = u16(view, payload, false);
      dport = u16(view, payload + 2, false);
      syn = view.getUint8(payload + 13) === 2;
      let data = payload + ((view.getUint8(payload + 12) >> 4) * 4);
      if (data <= ipend) {
        if (data + 4 <= ipend) {
          const prefix = String.fromCharCode(view.getUint8(data), view.getUint8(data + 1), view.getUint8(data + 2), view.getUint8(data + 3));
          http = prefix === 'GET ';
        }
        if (!http && data + 5 <= ipend) {
          http = 'POST ' === String.fromCharCode(...Array.from({ length: 5 }, (_, i) => view.getUint8(data + i)));
        }
      }
      dns = sport === 53 || dport === 53;
    } else if (fragment === 0 && proto === 17 && payload + 8 <= ipend) {
      sport = u16(view, payload, false);
      dport = u16(view, payload + 2, false);
      dns = (sport === 53 || dport === 53) && payload + 20 <= ipend;
    }
    return { src, dst, proto, sport, dport, dns, syn, http };
  }

  function parsePcap(view, onPacket) {
    if (view.byteLength < 24) throw new Error('The PCAP header is incomplete.');
    const signature = u32(view, 0, false);
    const le = signature === 0xd4c3b2a1 || signature === 0x4d3cb2a1;
    const be = signature === 0xa1b2c3d4 || signature === 0xa1b23c4d;
    if (!le && !be) throw new Error('Invalid PCAP header.');
    const nano = signature === 0x4d3cb2a1 || signature === 0xa1b23c4d;
    if (u16(view, 4, le) !== 2) throw new Error('Unsupported PCAP version.');
    const link = u32(view, 20, le) & 0xffff;
    let offset = 24;
    let records = 0;
    while (offset + 16 <= view.byteLength) {
      const sec = u32(view, offset, le);
      const fraction = u32(view, offset + 4, le);
      const len = u32(view, offset + 8, le);
      offset += 16;
      if (len > view.byteLength - offset) throw new Error('The capture contains an incomplete packet.');
      const time = sec + fraction / (nano ? 1e9 : 1e6);
      onPacket(time, decodeIp(view, offset, len, link));
      records++;
      offset += len;
    }
    if (offset !== view.byteLength) throw new Error('The capture ends with an incomplete packet header.');
    return records;
  }

  function parsePcapng(view, onPacket) {
    let offset = 0;
    let le = true;
    let interfaces = [];
    let foundSection = false;
    let records = 0;
    while (offset + 12 <= view.byteLength) {
      const isSection = u32(view, offset, false) === 0x0a0d0d0a;
      if (isSection) {
        if (offset + 12 > view.byteLength) throw new Error('Truncated PCAPNG section header.');
        const bom = u32(view, offset + 8, false);
        if (bom !== 0x4d3c2b1a && bom !== 0x1a2b3c4d) throw new Error('Invalid PCAPNG byte order.');
        le = bom === 0x4d3c2b1a;
        interfaces = [];
        foundSection = true;
      } else if (!foundSection) {
        throw new Error('PCAPNG is missing its section header.');
      }
      const type = u32(view, offset, le);
      const len = u32(view, offset + 4, le);
      if (len < 12 || len % 4 !== 0 || len > view.byteLength - offset || u32(view, offset + len - 4, le) !== len) {
        throw new Error('Invalid or incomplete PCAPNG block.');
      }
      if (type === 1) { // Interface Description Block
        if (len < 20) throw new Error('Incomplete PCAPNG interface block.');
        const intf = { link: u16(view, offset + 8, le), resolution: 1e-6 };
        let opt = offset + 16;
        while (opt + 4 <= offset + len - 4) {
          const code = u16(view, opt, le);
          const optLen = u16(view, opt + 2, le);
          opt += 4;
          if (code === 0 || opt + optLen > offset + len - 4) break;
          if (code === 9 && optLen === 1) {
            const raw = view.getUint8(opt);
            intf.resolution = raw & 0x80 ? 2 ** -(raw & 0x7f) : 10 ** -raw;
          }
          opt += (optLen + 3) & ~3;
        }
        interfaces.push(intf);
      } else if (type === 6 && len >= 32) { // Enhanced Packet Block
        const id = u32(view, offset + 8, le);
        const tsHigh = u32(view, offset + 12, le);
        const tsLow = u32(view, offset + 16, le);
        const captured = u32(view, offset + 20, le);
        const intf = interfaces[id];
        if (captured > len - 32) throw new Error('Incomplete PCAPNG enhanced packet.');
        if (intf) {
          const time = (tsHigh * 4294967296 + tsLow) * intf.resolution;
          onPacket(time, decodeIp(view, offset + 28, captured, intf.link));
          records++;
        }
      } else if (type === 3 && len >= 16) { // Simple Packet Block
        const originalLength = u32(view, offset + 8, le);
        const captured = Math.min(len - 16, originalLength);
        if (interfaces[0]) {
          onPacket(null, decodeIp(view, offset + 12, captured, interfaces[0].link));
          records++;
        }
      } else if (type === 2 && len >= 32) { // Deprecated Packet Block
        const id = u16(view, offset + 8, le);
        const high = u32(view, offset + 12, le);
        const low = u32(view, offset + 16, le);
        const captured = u32(view, offset + 20, le);
        if (captured > len - 32) throw new Error('Incomplete PCAPNG packet.');
        if (interfaces[id]) {
          const time = (high * 4294967296 + low) * interfaces[id].resolution;
          onPacket(time, decodeIp(view, offset + 28, captured, interfaces[id].link));
          records++;
        }
      }
      offset += len;
    }
    if (!foundSection) throw new Error('Invalid PCAPNG file.');
    if (offset !== view.byteLength) throw new Error('The PCAPNG file ends with an incomplete block.');
    return records;
  }

  function sortedCounter(map, key) {
    return [...map.entries()].sort((a, b) => b[1] - a[1]).map(([x, count]) => ({ [key]: x, count }));
  }
  function reportText(r) {
    const lines = [
      '========== IoT TRAFFIC REPORT ==========',
      `Device IP:        ${r.device_ip}`,
      `Packets:          ${r.packet_count}`,
      `Capture time:     ${r.duration_seconds.toFixed(1)} seconds`,
      `HTTP requests:    ${r.http_requests}`,
      `Connection tries: ${r.connection_attempts}`,
      '', 'Protocols:',
      ...r.protocols.map(p => `  ${p.name}: ${p.count}`),
      '', 'Destination addresses:',
      ...r.destinations.map(p => `  ${p.address}: ${p.count} packets`),
      '', 'Destination ports:',
      ...r.ports.map(p => `  ${p.port}: ${p.count} packets`),
      '', '================ ALERTS ================',
    ];
    if (!r.alerts.length) lines.push('No alerts. Device looks normal.');
    else r.alerts.forEach(a => lines.push(`[${a.category_id}] ${a.category}: ${a.message}`));
    return lines.join('\n') + '\n';
  }

  async function analyzeOfflinePCAP(file) {
    if (!file || !/\.(pcap|pcapng)$/i.test(file.name)) throw new Error('Choose a .pcap or .pcapng file.');
    if (!file.size) throw new Error('The selected file is empty.');
    if (file.size > MAX_BYTES) throw new Error('Maximum file size is 50 MB.');
    const view = new DataView(await file.arrayBuffer());
    const sources = new Map();
    const packets = [];
    let firstTime = null;
    let lastTime = null;
    let unsupported = 0;
    function onPacket(time, ip) {
      if (time !== null && Number.isFinite(time)) {
        if (firstTime === null) firstTime = time;
        lastTime = time;
      }
      if (ip) {
        sources.set(ip.src, (sources.get(ip.src) || 0) + 1);
        packets.push({ ...ip, time });
      } else unsupported++;
    }
    if (view.byteLength < 4) throw new Error('The file is too short to be a capture.');
    const magic = u32(view, 0, false);
    const total = magic === 0x0a0d0d0a ? parsePcapng(view, onPacket) : parsePcap(view, onPacket);
    if (!total) throw new Error('The capture has no packet records.');
    if (!sources.size) throw new Error('No supported IPv4 traffic found. This tool supports Ethernet, Wi-Fi, Linux-cooked, and raw IPv4 captures.');
    const deviceIp = [...sources.entries()].sort((a, b) => b[1] - a[1])[0][0];
    const protocols = new Map(), destinations = new Map(), ports = new Map();
    const requests = [], connections = [];
    for (const p of packets) {
      const proto = p.dns ? 'DNS' : p.proto === 6 ? 'TCP' : p.proto === 17 ? 'UDP' : 'Other';
      protocols.set(proto, (protocols.get(proto) || 0) + 1);
      if (p.src !== deviceIp) continue;
      destinations.set(p.dst, (destinations.get(p.dst) || 0) + 1);
      if (p.dport !== null) ports.set(p.dport, (ports.get(p.dport) || 0) + 1);
      if (p.proto === 6 && p.syn) connections.push({ dst: p.dst, port: p.dport });
      if (p.proto === 6 && p.http && p.time !== null) requests.push(p.time);
    }
    const uniqueConnections = [...new Map(connections.map(p => [`${p.dst}:${p.port}`, p])).values()]
      .sort((a, b) => a.dst.localeCompare(b.dst) || a.port - b.port);
    const alerts = [];
    const addAlert = (categoryId, category, message) => alerts.push({ category_id: categoryId, category, message, severity: categoryId === 1 ? 'medium' : 'high' });
    for (const p of uniqueConnections) if (!NORMAL_PORTS.has(p.port)) addAlert(0, 'Abnormal Connection', `Connection attempt to unusual port ${p.port} on ${p.dst}`);
    for (const p of uniqueConnections) if (UNSAFE_PORTS.has(p.port)) addAlert(1, 'Unsafe Protocol', `Unencrypted ${UNSAFE_PORTS.get(p.port)} (port ${p.port}) used with ${p.dst}`);
    let i = 0;
    let next = 0;
    while (i < requests.length) {
      // Packet timestamps are normally chronological; use a linear window.
      next = Math.max(next, i);
      while (next < requests.length && requests[next] >= requests[i] && requests[next] <= requests[i] + BURST_WINDOW) next++;
      const count = next - i;
      if (count > BURST_COUNT) {
        const elapsed = firstTime === null ? 0 : requests[i] - firstTime;
        addAlert(2, 'Request Burst', `${count} HTTP requests in ${BURST_WINDOW} seconds (at ${elapsed.toFixed(0)}s into the capture)`);
        i += count;
      } else i++;
    }
    const report = {
      filename: file.name,
      device_ip: deviceIp,
      packet_count: total,
      duration_seconds: +(Math.max(0, (lastTime ?? 0) - (firstTime ?? 0))).toFixed(1),
      http_requests: requests.length,
      connection_attempts: connections.length,
      protocols: sortedCounter(protocols, 'name'),
      destinations: sortedCounter(destinations, 'address'),
      ports: sortedCounter(ports, 'port'),
      alerts,
      analyzed_at: new Date().toISOString(),
      offline: true,
      ignored_packet_count: unsupported,
    };
    report.raw_console = reportText(report);
    return report;
  }
  root.analyzeOfflinePCAP = analyzeOfflinePCAP;
})(typeof window !== 'undefined' ? window : globalThis);
