import pyshark
def analyze_pcap(file_path):
    print(f"[*] Analyzing PCAP: {file_path}")
    cap = pyshark.FileCapture(file_path, display_filter='http')
    for packet in cap:
        print(packet.http.request_full_uri)
