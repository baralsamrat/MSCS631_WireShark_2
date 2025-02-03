import pyshark

def analyze_icmp_packets(pcap_file):
    capture = pyshark.FileCapture(pcap_file, display_filter="icmp")
    for packet in capture:
        print(f"Packet No: {packet.number}")
        print(f"Time: {packet.sniff_time}")
        print(f"Source: {packet.ip.src}, Destination: {packet.ip.dst}")
        print(f"ICMP Type: {packet.icmp.type}, Code: {packet.icmp.code}")
        print("-" * 40)

if __name__ == "__main__":
    pcap_file = "icmp_capture.pcap"  # Path to saved Wireshark capture
    analyze_icmp_packets(pcap_file)
