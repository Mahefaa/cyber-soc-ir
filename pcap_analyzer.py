import pyshark
from collections import Counter

def analyze_pcap(file_path):
    print(f"[*] Analyzing PCAP: {file_path}")
    try:
        cap = pyshark.FileCapture(file_path, display_filter='http')
        ip_counter = Counter()
        user_agents = set()
        
        for packet in cap:
            if hasattr(packet.http, 'request_uri'):
                ip_counter[packet.ip.src] += 1
                if hasattr(packet.http, 'user_agent'):
                    user_agents.add(packet.http.user_agent)
        
        print("\n--- Top HTTP Requesters (Potential DoS / Scanners) ---")
        for ip, count in ip_counter.most_common(5):
            print(f"{ip}: {count} requests")
            
        print("\n--- Unique User Agents (Detecting curl/python-requests) ---")
        for ua in user_agents:
            print(f"- {ua}")
            
    except FileNotFoundError:
        print(f"[!] File {file_path} not found. Please provide a valid PCAP.")

if __name__ == "__main__":
    analyze_pcap("suspicious_traffic.pcap")
