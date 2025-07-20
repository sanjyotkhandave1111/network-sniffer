from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

def packet_callback(packet):
    print("="*80)
    print(f"[{datetime.now()}] Packet Captured")

    if IP in packet:
        ip_layer = packet[IP]
        print(f"From: {ip_layer.src} --> To: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        if TCP in packet:
            print("Protocol Type: TCP")
            print(f"Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}")
        elif UDP in packet:
            print("Protocol Type: UDP")
            print(f"Source Port: {packet[UDP].sport}, Destination Port: {packet[UDP].dport}")
        elif ICMP in packet:
            print("Protocol Type: ICMP")
        
        print(f"Payload (first 50 bytes): {bytes(packet[IP].payload)[:50]}")
    else:
        print("Non-IP Packet")

# Start sniffing (may require sudo/admin)
print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=0)