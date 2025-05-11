from scapy.all import sniff, IP, TCP, Raw
from datetime import datetime
import socket
import re

# Auto-get private IP
def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except:
        return "127.0.0.1"
    finally:
        s.close()

MY_IP = get_my_ip()

# Extract and print HTTP activity (GET/POST)
def extract_web_activity(pkt):
    if pkt.haslayer(Raw):
        try:
            raw_data = pkt[Raw].load.decode(errors='ignore')

            # Log HTTP Requests
            if raw_data.startswith("GET") or raw_data.startswith("POST"):
                lines = raw_data.splitlines()
                request_line = lines[0] if lines else ""
                host = ""
                for line in lines:
                    if line.lower().startswith("host:"):
                        host = line.split(":", 1)[1].strip()
                url = f"http://{host}{request_line.split()[1]}" if host else request_line

                print(f"\n🌐 [WEB ACTIVITY] URL Visited ➜ {url}")

            # Extract Login Credentials
            if "user=" in raw_data or "pass=" in raw_data:
                username = re.search(r"(user(name)?|email)=([^&\s]+)", raw_data, re.IGNORECASE)
                password = re.search(r"(pass(word)?|pwd)=([^&\s]+)", raw_data, re.IGNORECASE)
                print(f"\n🔐 [CREDENTIALS FOUND]")
                if username:
                    print(f"   Username ➜ {username.group(3)}")
                if password:
                    print(f"   Password ➜ {password.group(3)}")
                print("-" * 50)

        except Exception as e:
            pass

# Main handler for each packet
def process_packet(pkt):
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return

    ip_layer = pkt[IP]
    tcp_layer = pkt[TCP]

    # Filter only packets from/to your system
    if MY_IP not in [ip_layer.src, ip_layer.dst]:
        return

    timestamp = datetime.now().strftime('%H:%M:%S')
    print(f"\n📦 [{timestamp}] TCP Packet")
    print(f"From ➜ {ip_layer.src}:{tcp_layer.sport} → To ➜ {ip_layer.dst}:{tcp_layer.dport}")
    
    extract_web_activity(pkt)

# Start sniffing
def start_sniffer():
    print(f"🌐 Starting Packet Sniffer on {MY_IP}...")
    print("🕵️ Capturing Web Visits + Credentials (HTTP Only)...\n")
    sniff(filter=f"tcp port 80 and host {MY_IP}", prn=process_packet, store=False)

if __name__ == "__main__":
    start_sniffer()
