from scapy.all import sniff

def packet_callback(packet):
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        protocol = packet['IP'].proto
        payload = packet['Raw'].load if packet.haslayer('Raw') else None
        
        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol} | Payload: {payload}")

print("Packet sniffer started...")

# Sniff packets
sniff(prn=packet_callback, store=0)
