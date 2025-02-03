import os

def run_ping(host):
    print(f"Pinging {host}...")
    os.system(f"ping -n 5 {host}")

def run_traceroute(host):
    print(f"Running traceroute to {host}...")
    os.system(f"tracert {host}")

if __name__ == "__main__":
    target_host = "8.8.8.8"  # Google DNS for testing
    run_ping(target_host)
    run_traceroute(target_host)
