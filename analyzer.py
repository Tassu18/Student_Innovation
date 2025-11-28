from scapy.all import rdpcap, IP
from collections import Counter
from tabulate import tabulate

def analyze_packets():
    try:
        packets = rdpcap("captured_packets.pcap")
    except FileNotFoundError:
        print("❌ No packets captured yet! Run capture first.")
        return

    # Show all packet summaries
    for i, pkt in enumerate(packets, start=1):
        print(f"Packet {i}: {pkt.summary()}")

    print(f"\n📦 Total packets captured: {len(packets)}\n")

    protocols = Counter()
    ip_src = Counter()
    ip_dst = Counter()

    for pkt in packets:
        if IP in pkt:
            proto = pkt[IP].proto
            if proto == 6:
                protocols["TCP"] += 1
            elif proto == 17:
                protocols["UDP"] += 1
            elif proto == 1:
                protocols["ICMP"] += 1
            else:
                protocols["Other"] += 1

            ip_src[pkt[IP].src] += 1
            ip_dst[pkt[IP].dst] += 1

    # Table: Protocol distribution
    proto_table = [[p, c] for p, c in protocols.items()]
    print(tabulate(proto_table, headers=["Protocol", "Count"], tablefmt="grid"))

    # Table: Top 5 source IPs
    src_table = [[ip, c] for ip, c in ip_src.most_common(5)]
    print("\n🌐 Top 5 Source IPs:")
    print(tabulate(src_table, headers=["Source IP", "Packets"], tablefmt="grid"))

    # Table: Top 5 destination IPs
    dst_table = [[ip, c] for ip, c in ip_dst.most_common(5)]
    print("\n🌍 Top 5 Destination IPs:")
    print(tabulate(dst_table, headers=["Destination IP", "Packets"], tablefmt="grid"))

def get_protocol_counts():
    try:
        packets = rdpcap("captured_packets.pcap")
        protocols = Counter()
        for pkt in packets:
            if IP in pkt:
                proto = pkt[IP].proto
                if proto == 6:
                    protocols["TCP"] += 1
                elif proto == 17:
                    protocols["UDP"] += 1
                elif proto == 1:
                    protocols["ICMP"] += 1
                else:
                    protocols["Other"] += 1
        return protocols
    except FileNotFoundError:
        return {}
