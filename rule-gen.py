import sys
import os
from scapy.all import rdpcap, IP, TCP, UDP, DNS
from collections import Counter

def analyze_pcap(file_path):
    packets = rdpcap(file_path)
    ip_counter = Counter()
    port_counter = Counter()
    dns_counter = Counter()

    for packet in packets:
        if IP in packet:
            ip_counter[packet[IP].src] += 1
            ip_counter[packet[IP].dst] += 1
            if TCP in packet:
                port_counter[packet[TCP].sport] += 1
                port_counter[packet[TCP].dport] += 1
            elif UDP in packet:
                port_counter[packet[UDP].sport] += 1
                port_counter[packet[UDP].dport] += 1
                if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                    if DNS in packet and packet[DNS].qd:
                        dns_query = packet[DNS].qd.qname.decode()
                        dns_counter[dns_query] += 1

    return ip_counter, port_counter, dns_counter

def generate_snort_rules(ip_counter, port_counter, dns_counter):
    rules = []

    # Detect high traffic volume from a single IP
    for ip, count in ip_counter.items():
        if count > 100:  # Threshold for suspicious activity
            rules.append(f"alert ip {ip} any -> any any (msg:\"Suspicious IP {ip}\"; sid:1000001;)")

    # Detect unusual port usage
    for port, count in port_counter.items():
        if port not in [80, 443, 53, 22] and count > 50:  # Common ports
            rules.append(f"alert tcp any any -> any {port} (msg:\"Suspicious port {port}\"; sid:1000002;)")
            rules.append(f"alert udp any any -> any {port} (msg:\"Suspicious port {port}\"; sid:1000003;)")

    # Detect DNS tunneling
    for domain, count in dns_counter.items():
        if count > 10:  # Threshold for suspicious DNS queries
            rules.append(f"alert udp any any -> any 53 (msg:\"Possible DNS tunneling detected for domain {domain}\"; content:\"{domain}\"; sid:1000004;)")

    # Detect port scans
    if any(count > 20 for count in port_counter.values()):  # Threshold for port scan detection
        rules.append("alert tcp any any -> any any (msg:\"Potential port scan detected\"; flags:S; threshold:type both, track by_src, count 5, seconds 60; sid:1000005;)")

    return rules

def main():
    if len(sys.argv) != 2:
        print("Usage: python detect_anomalies.py <pcap_file>")
        sys.exit(1)

    file_path = sys.argv[1]

    if not os.path.isfile(file_path):
        print(f"File {file_path} does not exist.")
        sys.exit(1)

    ip_counter, port_counter, dns_counter = analyze_pcap(file_path)
    snort_rules = generate_snort_rules(ip_counter, port_counter, dns_counter)

    if snort_rules:
        print("Generated Snort rules:")
        for rule in snort_rules:
            print(rule)
    else:
        print("No anomalies detected.")

if __name__ == "__main__":
    main()

