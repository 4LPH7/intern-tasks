# Network Packet Analyzer Tool

## Overview

The Network Packet Analyzer Tool is a Python-based utility for capturing, analyzing, and filtering network packets. It supports both live capture from a network interface and reading packets from a pcap file. The tool can filter packets based on various criteria and provides a summary of the captured traffic.

## Features

- **Live Packet Capture**: Capture packets in real-time from a specified network interface.
- **Pcap File Analysis**: Analyze packets from a pcap file.
- **Packet Filtering**: Filter packets based on protocol, source IP, destination IP, source port, and destination port.
- **Traffic Analysis**: Count the number of packets per protocol.
- **Packet Display**: Display a summary of each packet.

## Usage

### Installation

Ensure you have Python installed on your system. The tool requires the `scapy` library. You can install it using `pip`:

```bash
pip install scapy
```

## Running the Tool
**The tool can be run from the command line. Below are the available options:**

python packet_analyzer.py [OPTIONS]
Options
--live: Capture packets from a live network interface.\
--interface: Network interface to capture packets from (required when using --live).\
--file: Path to a pcap file to analyze.\
--protocol: Protocol to filter by (e.g., TCP, UDP, IP, IPv6).\
--src_ip: Source IP to filter by.\
--dst_ip: Destination IP to filter by.\
--src_port: Source port to filter by.\
--dst_port: Destination port to filter by.\
--count: Number of packets to capture or analyze.

## Examples
****Live Capture****\
Capture 10 packets from the eth0 interface:

```bash
python packet_analyzer.py --live --interface eth0 --count 10
```
Analyze Pcap File
Analyze packets from a pcap file and filter by TCP protocol:

```bash
python packet_analyzer.py --file path/to/file.pcap --protocol TCP
```
## Filter by IP Address
Capture packets from the eth0 interface and filter by source IP:

```bash
python packet_analyzer.py --live --interface eth0 --src_ip 192.168.1.1
```
****Output****:
The tool will display a summary of each packet captured or read from the pcap file. It will also provide a count of packets per protocol in the security analysis section.

## Dependencies
- Python 3.x\
- Scapy