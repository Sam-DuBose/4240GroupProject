#Group Project for CPSC 4240
#Emma Kropf, Anabel Thompson, Sam DuBose, Brayden Bennett
#this file will analyze the pcap file and print the results to the console
#
#usage: python3 pcap_analyze.py capture.pcap

import sys
from collections import Counter
from scapy.all import rdpcap, IP, TCP, UDP, DNS, Raw

#ports a normal IoT device should use
NORMAL_PORTS = {53, 80, 443, 123}

#protocols that send data without encryption
UNSAFE_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP"}

#more than this many HTTP requests within BURST_WINDOW seconds is a burst
BURST_COUNT = 5
BURST_WINDOW = 30


#Read the pcap file
if len(sys.argv) != 2:
    sys.exit("usage: python3 pcap_analyze.py capture.pcap")

try:
    packets = rdpcap(sys.argv[1])
except Exception:
    sys.exit("Error: could not read the file (missing or empty)")

if len(packets) == 0:
    sys.exit("Error: the pcap file is empty")

#the IoT device is the IP that sends the most packets
device_ip = Counter(p[IP].src for p in packets if IP in p).most_common(1)[0][0]


#create the diagnosis
protocols = Counter()
destinations = Counter()
ports = Counter()
http_times = []
connection_attempts = []  #(destination, port)

for p in packets:
    if IP not in p:
        continue

    #count traffic by protocol used
    if DNS in p:
        protocols["DNS"] += 1
    elif TCP in p:
        protocols["TCP"] += 1
    elif UDP in p:
        protocols["UDP"] += 1
    else:
        protocols["Other"] += 1

    #only look at traffic the device sends out
    if p[IP].src != device_ip:
        continue

    #list the ports and destination addresses
    destinations[p[IP].dst] += 1
    if TCP in p or UDP in p:
        ports[p.dport] += 1

    if TCP in p:
        #outgoing connection attempt = SYN flag without ACK
        if p[TCP].flags == "S":
            connection_attempts.append((p[IP].dst, p[TCP].dport))

        #http request = payload that starts with GET or POST
        if Raw in p and p[Raw].load.startswith((b"GET ", b"POST ")):
            http_times.append(float(p.time))

duration = float(packets[-1].time - packets[0].time)


#check the alert category
#0 = abnormal connection, 1 = unsafe protocol, 2 = request bursts
alerts = []

for dst, port in sorted(set(connection_attempts)):
    if port not in NORMAL_PORTS:
        alerts.append((0, f"Connection attempt to unusual port {port} on {dst}"))

for dst, port in sorted(set(connection_attempts)):
    if port in UNSAFE_PORTS:
        alerts.append((1, f"Unencrypted {UNSAFE_PORTS[port]} (port {port}) used with {dst}"))

i = 0
while i < len(http_times):
    burst = [t for t in http_times if http_times[i] <= t <= http_times[i] + BURST_WINDOW]
    if len(burst) > BURST_COUNT:
        alerts.append((2, f"{len(burst)} HTTP requests in {BURST_WINDOW} seconds "
                          f"(at {http_times[i] - float(packets[0].time):.0f}s into the capture)"))
        i += len(burst)
    else:
        i += 1


#print results
print("========== IoT TRAFFIC REPORT ==========")
print(f"Device IP:        {device_ip}")
print(f"Packets:          {len(packets)}")
print(f"Capture time:     {duration:.1f} seconds")
print(f"HTTP requests:    {len(http_times)}")
print(f"Connection tries: {len(connection_attempts)}")

print("\nProtocols:")
for name, count in protocols.most_common():
    print(f"  {name}: {count}")

print("\nDestination addresses:")
for dst, count in destinations.most_common():
    print(f"  {dst}: {count} packets")

print("\nDestination ports:")
for port, count in ports.most_common():
    print(f"  {port}: {count} packets")

categories = ["Abnormal Connection", "Unsafe Protocol", "Request Burst"]
print("\n================ ALERTS ================")
if not alerts:
    print("No alerts. Device looks normal.")
for category, message in alerts:
    print(f"[{category}] {categories[category]}: {message}")
