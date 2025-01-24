from datetime import datetime

def analyze_packet(packet):
    if packet.haslayer('IP'):
        print(f"[{datetime.now()}] Packet: {packet['IP'].src} -> {packet['IP'].dst}")

def save_log(packet):
    with open("data/logs/sniffer_log.txt", "a") as log_file:
        log_file.write(f"{packet.summary()}\n")



