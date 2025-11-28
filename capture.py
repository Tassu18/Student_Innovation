from scapy.all import sniff, wrpcap

def capture_packets():
    print("=== Network Sniffer ===")
    print("Select filter type:")
    print("1. All packets")
    print("2. Only TCP packets")
    print("3. Only UDP packets")
    print("4. Only ICMP packets")

    choice = input("Enter choice (1-4): ")

    filters = {
        "1": "",
        "2": "tcp",
        "3": "udp",
        "4": "icmp"
    }

    flt = filters.get(choice, "")
    print(f"\n📡 Capturing packets ({'all' if flt == '' else flt.upper()})... Press Ctrl+C to stop.")

    packets = sniff(filter=flt, count=50)  # capture 50 packets
    wrpcap("captured_packets.pcap", packets)

    print("✅ Packets saved to captured_packets.pcap")

if __name__ == "__main__":
    capture_packets()
