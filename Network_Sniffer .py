from scapy.all import sniff , Raw
from scapy.layers.inet import IP ,TCP

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer=packet.getlayer(IP)
        print(f"[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")
        if packet.haslayer(TCP):
            tcp_layer=packet.getlayer(TCP)
            print(f"[+] TCP Port: {tcp_layer.sport} -> {ip_layer.dport}")
        if packet.haslayer(Raw):
            print(f"[+] Raw Data: {packet[Raw].load}")
            print("starting Network Sniffer...")
            
sniff(prn=packet_callback,stor=0)

