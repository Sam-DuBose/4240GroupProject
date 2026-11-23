IoT TRAFFIC MONITOR — OFFLINE, READY-TO-USE WEBSITE
===================================================

HOW TO START
1. Extract this ZIP to a folder.
2. Open index.html in Chrome, Edge, or Firefox.
3. Click "Upload a PCAP file" and select your own .pcap or .pcapng file.
4. Use the Explore dropdown to view the analysis and explanations.

No Python, installer, server, internet, or account is required. Works on
Windows, macOS, and Linux with a modern desktop browser. Keep the files
(index.html, sky.jpg, styles.css, app_offline.js, offline_analyzer.js)
together in the same folder. Do not upload any private PCAPs to a website.
This app reads your capture locally in the browser.

"View last analysis" saves the most recent results in your browser's local
storage when the browser allows it. Private browsing modes or strict local
file policies might block that storage; the current results still work and
you can export them as JSON or TXT.

SUPPORTED CAPTURES
- PCAP and common PCAPNG formats, maximum file size 50 MB.
- IPv4 packet details on Ethernet, 802.11/Wi-Fi, Linux cooked, and raw IP.
- Network summary, connections, ports, common DNS traffic, and three basic
  security indicators (unusual connection port, port-based plaintext service,
  and a burst of HTTP GET/POST requests).
- Captures with only encrypted Wi-Fi frames, only IPv6, or other uncommon
  link types will not produce device reports.

IMPORTANT
This offline version runs in JavaScript. It follows the same basic rules as
pcap_analyze.py from the CPSC 4240 project, but uses its own packet parser;
it does NOT execute Python or Scapy and may produce different results for
specialized captures. Security findings are indicators, not proof of an
attack. This is a teaching/demo tool, not full network intrusion detection.

Original project team (Fall 2026): Emma Kropf, Anabel Thompson,
Sam DuBose, Brayden Bennett.

There are NO sample captures and NO test files in this download.
