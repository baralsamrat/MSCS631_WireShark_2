import os
import subprocess
import pyshark
import time

def get_wifi_interface():
    """Automatically detects and returns the correct Wi-Fi interface name."""
    interfaces_output = subprocess.run(["tshark", "-D"], capture_output=True, text=True).stdout.splitlines()
    for interface in interfaces_output:
        if "Wi-Fi" in interface or "Wireless" in interface:
            # Extracts the numeric interface ID (e.g., "4" from "4. Wi-Fi ...")
            return interface.split(" ", 1)[0].strip().replace(".", "")
    print("Error: No Wi-Fi interface found!")
    exit(1)

# Automatically detect the correct Wi-Fi interface ID
INTERFACE = get_wifi_interface()

def start_capture(output_file, duration=10):
    """
    Starts capturing ICMP packets on the detected Wi-Fi interface using tshark.
    The capture is started as a background process so that other commands can run concurrently.
    """
    print(f"📡 Starting packet capture on interface {INTERFACE} for {duration} seconds...")
    # Use a capture filter (-f "icmp") because display filters (-Y) aren't supported when capturing.
    capture_command = f'tshark -i {INTERFACE} -a duration:{duration} -f "icmp" -w {output_file}'
    proc = subprocess.Popen(capture_command, shell=True)
    return proc

def run_ping(target_host):
    """Runs ping command to test connectivity."""
    print(f"📡 Pinging {target_host}...")
    response = subprocess.run(["ping", "-n", "5", target_host], capture_output=True, text=True)
    print(response.stdout)
    return response.stdout

def run_traceroute(target_host):
    """Runs traceroute command to analyze network hops."""
    print(f"📍 Running traceroute to {target_host}...")
    response = subprocess.run(["tracert", target_host], capture_output=True, text=True)
    print(response.stdout)
    return response.stdout

def analyze_icmp_packets(pcap_file, timeout=15):
    """Analyzes captured ICMP packets from the provided PCAP file with a timeout."""
    start_time = time.time()
    while not os.path.exists(pcap_file):
        if time.time() - start_time > timeout:
            print("❌ Error: PCAP file not found, exiting.")
            return {}
        print("⏳ Waiting for PCAP file to appear...")
        time.sleep(2)

    print(f"🔍 Checking if ICMP packets exist in {pcap_file}...")
    tshark_output = subprocess.run(["tshark", "-r", pcap_file, "-Y", "icmp"], capture_output=True, text=True).stdout
    if not tshark_output:
        print("❌ No ICMP packets found in the capture. Exiting analysis.")
        return {}

    print("✅ ICMP packets detected. Proceeding with analysis...")
    capture = pyshark.FileCapture(pcap_file, display_filter="icmp")
    packets = list(capture)
    
    if len(packets) == 0:
        print("❌ No ICMP packets found in the capture. Exiting analysis.")
        return {}

    results = {}
    first_packet = packets[0]  # Extracts source and destination IPs from the first packet
    results['source_ip'] = first_packet.ip.src
    results['destination_ip'] = first_packet.ip.dst
    results['no_ports_reason'] = "ICMP operates at the network layer, no ports needed."
    
    # Identify ICMP Echo Request (Type 8)
    for packet in packets:
        if hasattr(packet, "icmp") and packet.icmp.type == '8':
            results['ping_request_type'] = packet.icmp.type
            results['ping_request_code'] = packet.icmp.code
            break

    # Identify ICMP Echo Reply (Type 0)
    for packet in packets:
        if hasattr(packet, "icmp") and packet.icmp.type == '0':
            results['ping_reply_type'] = packet.icmp.type
            results['ping_reply_code'] = packet.icmp.code
            break

    # Identify ICMP Error Messages (Type 11 - TTL Exceeded)
    for packet in packets:
        if hasattr(packet, "icmp") and packet.icmp.type == '11':
            results['icmp_error_type'] = packet.icmp.type
            results['icmp_error_code'] = packet.icmp.code
            break

    # Additional Analysis
    results['icmp_error_extra_fields'] = "Original IP header and 8 bytes of original payload"
    
    # Retrieve last three captured packets (if available)
    if len(packets) >= 3:
        last_three_types = [packet.icmp.type for packet in packets[-3:]]
        results['last_three_packet_types'] = last_three_types
    else:
        results['last_three_analysis'] = "Not enough packets captured to analyze last three packets."
    
    # Traceroute analysis (determining delay patterns in RTT)
    results['traceroute_delay_analysis'] = "Check RTT in traceroute output for delays."
    
    capture.close()
    return results

if __name__ == "__main__":
    target_host = "8.8.8.8"  # Target for ping and traceroute tests
    pcap_file = os.path.join("data", "icmp_capture.pcap")  # Filename for captured packets

    # Create the directory for the PCAP file if it doesn't exist
    if not os.path.exists("data"):
        os.makedirs("data")

    # Set a capture duration long enough to include the ping/traceroute traffic.
    capture_duration = 20  # Adjust as needed
    capture_proc = start_capture(pcap_file, duration=capture_duration)
    
    # Give the capture process a moment to initialize.
    time.sleep(1)
    
    # Generate ICMP traffic while capture is active.
    ping_output = run_ping(target_host)
    traceroute_output = run_traceroute(target_host)
    
    # Wait for the capture to finish.
    capture_proc.wait()
    
    # Analyze the captured ICMP packets.
    analysis_results = analyze_icmp_packets(pcap_file)
    
    # Display the results.
    print("\n--- ICMP Analysis Results ---")
    for key, value in analysis_results.items():
        print(f"{key}: {value}")
    
    print("\n--- Ping Output ---")
    print(ping_output)
    
    print("\n--- Traceroute Output ---")
    print(traceroute_output)
