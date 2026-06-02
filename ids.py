from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
from collections import defaultdict
import time

conf.use_pcap = True

# Tracking dictionaries
packet_count = defaultdict(int)
port_scan_tracker = defaultdict(set)
syn_tracker = defaultdict(int)
icmp_tracker = defaultdict(int)
udp_tracker = defaultdict(int)
last_reset = time.time()

def log_alert(alert):
    with open("alerts.log", "a") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {alert}\n")
    print(alert)

def analyze_packet(packet):
    global last_reset

    # Reset counters every 10 seconds
    if time.time() - last_reset > 10:
        packet_count.clear()
        port_scan_tracker.clear()
        syn_tracker.clear()
        icmp_tracker.clear()
        udp_tracker.clear()
        last_reset = time.time()

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Count total packets per IP
        packet_count[src_ip] += 1

        # ── 1. PORT SCAN DETECTION ──────────────────────
        if TCP in packet:
            port = packet[TCP].dport
            port_scan_tracker[src_ip].add(port)
            if len(port_scan_tracker[src_ip]) > 5:
                alert = f"[!! PORT SCAN] {src_ip} targeting {dst_ip} - {len(port_scan_tracker[src_ip])} ports scanned"
                log_alert(alert)

        # ── 2. SYN FLOOD DETECTION ──────────────────────
        if TCP in packet and packet[TCP].flags == 0x02:  # SYN flag
            syn_tracker[src_ip] += 1
            if syn_tracker[src_ip] > 50:
                alert = f"[!! SYN FLOOD] {src_ip} sent {syn_tracker[src_ip]} SYN packets to {dst_ip}"
                log_alert(alert)

        # ── 3. ICMP FLOOD DETECTION ─────────────────────
        if ICMP in packet:
            icmp_tracker[src_ip] += 1
            if icmp_tracker[src_ip] > 20:
                alert = f"[!! ICMP FLOOD] {src_ip} sent {icmp_tracker[src_ip]} ICMP packets"
                log_alert(alert)

        # ── 4. UDP FLOOD DETECTION ──────────────────────
        if UDP in packet:
            udp_tracker[src_ip] += 1
            if udp_tracker[src_ip] > 100:
                alert = f"[!! UDP FLOOD] {src_ip} sent {udp_tracker[src_ip]} UDP packets to {dst_ip}"
                log_alert(alert)

        # ── 5. DOS DETECTION ────────────────────────────
        if packet_count[src_ip] > 200:
            alert = f"[!! DoS ATTACK] {src_ip} sent {packet_count[src_ip]} packets"
            log_alert(alert)

        print(f"[PACKET] {src_ip} --> {dst_ip}")

print("[*] IDS Started - Detecting: Port Scan, SYN Flood, ICMP Flood, UDP Flood, DoS")
sniff(prn=analyze_packet, store=False)