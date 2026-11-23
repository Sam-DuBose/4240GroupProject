# IoT Traffic Monitoring and Alerts
CPSC 4240 – Fall 2026 | Emma Kropf, Anabel Thompson, Brayden Bennett, Sam DuBose

An open-source tool that analyzes IoT network traffic (pcap) and alerts on abnormal connections, unsafe protocols, and request bursts.

## Simulated Devices (Wokwi)
1. Go to wokwi.com and select **ESP32** → **Starter Templates** → **ESP32**.
2. Paste the code from `benign.ino` (normal device) or `malicious.ino` (compromised device) into `sketch.ino`.
3. Press the green arrow to compile and run.

| Device | Behavior |
|---|---|
| `benign.ino` | Sends a temperature reading via HTTP GET every 10 seconds |
| `malicious.ino` | Same as benign, plus every 60 seconds: a burst of 10 rapid HTTP requests and connection attempts on ports 23 (Telnet), 2222, and 8080 |

## Traffic Analyzer
*In progress*: Python script that parses the captured pcap and reports diagnostics and red flags.
to run the website run the index file and upload your pcap file
