# Network Intrusion Detection and Prevention System (NIDPS)

## Introduction

This project implements a Network-based Intrusion Detection and Prevention System (NIDPS), combining both signature-based and anomaly-based detection techniques. The IDS monitors network activities to identify, log, and dynamically block potential threats.

## Setup Instructions

### Prerequisites
- Python 3
- Linux OS (for iptables firewall commands)

### Required Python Packages

```sh
sudo apt-get install python3-pip
pip3 install scapy
pip3 install python-nmap
pip3 install numpy
pip3 install sklearn
```

### Execution

Run the IDS with administrative privileges:

```sh
sudo python3 Assignment_3.py
```

## Project Structure
- **Assignment_3.py**: Main IDS logic implementation.
- **ids.log**: Log file containing intrusion detection records.

## Implementation Explanation

### 1. Network Traffic Monitoring
- Utilizes Scapy to sniff live TCP network traffic.
- Captures packet details including timestamps, source/destination IPs, ports, and protocols.

### 2. Intrusion Detection Modules

#### a. Port Scanning Detection (Anomaly-based)
- Detects if a single IP attempts to connect to more than 6 different ports within 15 seconds.
- Logs and dynamically blocks the detected malicious IPs.

#### b. OS Fingerprinting Detection (Signature-based)
- Detects IPs sending different TCP flag combinations (SYN, ACK, FIN) more than 5 times within 20 seconds.
- Logs and blocks suspicious IPs dynamically.

#### c. SYN Flood Detection
- Identifies potential SYN flood attacks by detecting more than 20 SYN packets from a single IP in 10 seconds.
- Logs and dynamically blocks the attacker.

### 3. Intrusion Prevention Mechanism
- Uses Linux iptables commands to block and unblock IP addresses upon detecting malicious activity.

### 4. Alert and Logging System
- Maintains detailed logs of detected intrusions in `ids.log` with the following format:

```
Date(DD-MM-YY) Time(HH:MM:SS) — Intrusion Type — Attacker IP — Targeted Ports/Flags — Time Span Of Attack
```

Example:
```
21-03-25 14:30:12 — Port Scanning — 192.168.1.5 — 22, 80, 443, 8080 — 12s
```

### 5. Management Interface
CLI provides the following functionalities:
- Start/Stop IDS
- View Live Traffic
- View Intrusion Logs
- Display Blocked IPs
- Clear Block List
- Unblock specific IP
- Exit

Example interaction:
```
==== Intrusion Detection System Menu ====
1. Start IDS
2. Stop IDS
3. View Live Traffic
4. View Intrusion Logs
5. Display Blocked IPs
6. Clear Block List
7. Unblock an IP
8. Exit
Enter your choice: 1
```

## Input/Output Examples

### Starting the IDS:
```
Enter your choice: 1
Starting IDS...
```

### Viewing Live Traffic:
```
Enter your choice: 3
23:45:32 - 10.1.37.133 -> 10.1.37.186:443 [Flags: S]
23:45:32 - 10.1.37.133 -> 10.1.37.186:80 [Flags: A]
```

### Intrusion Detection and Prevention:
```
Intrusion Alert: Port Scanning detected
Attacker IP: 10.1.37.133
Details: Ports scanned: {22, 80, 443, 8080, 139, 445}
Time: 2025-04-07 23:45:45
Executing command: sudo iptables -A INPUT -s 10.1.37.133 -j DROP
Blocked IP: 10.1.37.133
```

### Unblocking an IP:
```
Enter your choice: 7
Enter the IP to unblock: 10.1.37.133
Executing command: sudo iptables -D INPUT -s 10.1.37.133 -j DROP
Unblocked IP: 10.1.37.133
```

### Viewing Intrusion Logs:
```
Enter your choice: 4
21-03-25 14:30:12 — Port Scanning — 192.168.1.5 — 22, 80, 443, 8080 — 12s
```