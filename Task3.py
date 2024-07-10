import argparse
from scapy.all import *

def packet_summary(packet):
    """Returns a summary of the packet."""
    return packet.summary()

def parse_packet(packet):
    """Parses relevant information from the packet."""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        payload = packet[IP].payload
        return {
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Protocol": protocol,
            "Payload": payload,
        }
    return {}

def filter_packets(packets, protocol=None, src_ip=None, dst_ip=None, src_port=None, dst_port=None):
    """Filters packets based on given criteria."""
    filtered_packets = []
    for packet in packets:
        if protocol:
            if protocol == "TCP" and not packet.haslayer(TCP):
                continue
            elif protocol == "UDP" and not packet.haslayer(UDP):
                continue
            elif protocol == "IP" and not packet.haslayer(IP):
                continue
            elif protocol == "IPv6" and not packet.haslayer(IPv6):
                continue

        if src_ip and (packet[IP].src if IP in packet else packet[IPv6].src) != src_ip:
            continue
        if dst_ip and (packet[IP].dst if IP in packet else packet[IPv6].dst) != dst_ip:
            continue
        if src_port and packet.sport != src_port:
            continue
        if dst_port and packet.dport != dst_port:
            continue

        filtered_packets.append(packet)
    return filtered_packets

def analyze_traffic(packets):
    """Analyzes traffic for suspicious patterns."""
    protocol_count = {}
    for packet in packets:
        protocol = packet[IP].proto if IP in packet else "IPv6"
        if protocol in protocol_count:
            protocol_count[protocol] += 1
        else:
            protocol_count[protocol] = 1
    return protocol_count

def capture_live(interface, count):
    """Captures packets from a live network interface."""
    try:
        packets = sniff(iface=interface, count=count)
        return packets
    except Exception as e:
        print(f"Error capturing packets: {e}")
        print("Available interfaces:")
        print(get_if_list())
        return []

def capture_from_file(file_path):
    """Captures packets from a pcap file."""
    try:
        packets = rdpcap(file_path)
        return packets
    except Exception as e:
        print(f"Error reading pcap file: {e}")
        return []

def display_packets(packets):
    """Displays packet information."""
    for packet in packets:
        print(packet_summary(packet))

def main():
    parser = argparse.ArgumentParser(description="Network Packet Analyzer Tool")
    parser.add_argument("--live", action="store_true", help="Capture packets from a live network interface.")
    parser.add_argument("--interface", type=str, help="Network interface to capture packets from when --live is used.")
    parser.add_argument("--file", type=str, help="Path to a pcap file to analyze.")
    parser.add_argument("--protocol", type=str, help="Protocol to filter by (e.g., TCP, UDP, IP, IPv6).")
    parser.add_argument("--src_ip", type=str, help="Source IP to filter by.")
    parser.add_argument("--dst_ip", type=str, help="Destination IP to filter by.")
    parser.add_argument("--src_port", type=int, help="Source port to filter by.")
    parser.add_argument("--dst_port", type=int, help="Destination port to filter by.")
    parser.add_argument("--count", type=int, help="Number of packets to capture or analyze.")
    args = parser.parse_args()

    if args.live:
        if not args.interface:
            parser.error("--interface is required when using --live")
        packets = capture_live(args.interface, args.count or 10)
    elif args.file:
        packets = capture_from_file(args.file)
    else:
        parser.error("Either --live or --file is required")

    if not packets:
        print("No packets captured or read.")
        return

    if args.protocol or args.src_ip or args.dst_ip or args.src_port or args.dst_port:
        packets = filter_packets(
            packets,
            protocol=args.protocol.upper() if args.protocol else None,
            src_ip=args.src_ip,
            dst_ip=args.dst_ip,
            src_port=args.src_port,
            dst_port=args.dst_port
        )

    if args.count:
        packets = packets[:args.count]

    print(f"Total packets captured: {len(packets)}")
    display_packets(packets)

    # Perform basic security analysis
    analysis_results = analyze_traffic(packets)
    print("\n--- Security Analysis ---")
    for protocol, count in analysis_results.items():
        print(f"{protocol}: {count} packets")

if __name__ == "__main__":
    main()
