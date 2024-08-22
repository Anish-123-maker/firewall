from scapy.all import *
import os

# Define the IP addresses and ports to block
blocked_ips = ["192.168.1.100", "192.168.1.101"]
blocked_ports = [80, 443]

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        # Check if the packet has a TCP layer
        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport

            # Block the packet if the source or destination IP is in the blocked list
            if ip_src in blocked_ips or ip_dst in blocked_ips:
                print(f"Blocked IP packet: {ip_src} -> {ip_dst}")
                return

            # Block the packet if the source or destination port is in the blocked list
            if tcp_sport in blocked_ports or tcp_dport in blocked_ports:
                print(f"Blocked TCP packet on port {tcp_sport} or {tcp_dport}: {ip_src} -> {ip_dst}")
                return

    # If the packet is not blocked, forward it
    send(packet)

def main():
    # Run the firewall
    print("Firewall is running...")
    sniff(filter="ip", prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
