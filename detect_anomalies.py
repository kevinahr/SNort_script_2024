import sys
import os
from scapy.all import rdpcap, IP, TCP, UDP, DNS
from collections import Counter
import csv
from datetime import datetime

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
    
def detect_anomalies(ip_counter, port_counter, dns_counter):
    anomalies = []
    
    for ip, count in ip_counter.items():
        if count > 20:
            anomalies.append({"type" : "Suspicious IP", "IP": ip})
    
    for port, count in port_counter.items():
        if port not in [80, 443, 53, 22] and count > 50:
            anomalies.append({"type" : (f"Suspicious port: {port}"), "IP": ip})
            
    for domain, count in dns_counter.items():
        if count > 10:
            anomalies.append({"type" : (f"Possible DNS tunneling detected for domain: {domain}"), "IP": ip})
    
    if any(count > 20 for count in port_counter.values()):
        anomalies.append({"type" : (f"Potential port scan detected: {port}"), "IP": ip})
        
    return anomalies

def generate_snort_rules(anomalies):
    snort_rules = []
    for anomaly in anomalies:
        if anomaly['type'] == 'Suspicious IP':
            rule = f'alert ip {anomaly["IP"]} any -> any any (msg:"Suspicious IP detected from {anomaly["IP"]}"; sid:1000001; rev:1;)'
        elif anomaly['type'].startswith('Suspicious port'):
            port = anomaly['type'].split(': ')[1]
            rule = f'alert tcp {anomaly["IP"]} any -> any {port} (msg:"Suspicious port {port} detected from {anomaly["IP"]}"; sid:1000002; rev:1;)'
        elif anomaly['type'] == 'Potential port scan detected':
            port = anomaly['IP']
            rule = f'alert tcp any any -> {port} any (msg:"Potential port scan detected to port {port}"; sid:1000003; rev:1;)'
        else:
            # Handle other anomaly types as needed
            continue
        
        snort_rules.append(rule)
    
    return snort_rules
def main():
    if len(sys.argv) != 2:
        print("Usage: python detect_anomalies.py <pcap_file>")
        sys.exit(1)
        
    file_path = sys.argv[1]
    
    if not os.path.isfile(file_path):
        print(f"File {file_path} does not exist.")
        sys.exit(1)
        
    ip_counter, port_counter, dns_counter = analyze_pcap(file_path)
    anomalies_detected = detect_anomalies(ip_counter, port_counter, dns_counter)
    
    if anomalies_detected:
        print("Anomalies detected:")
        for anomaly in anomalies_detected:
            print(anomaly)
        snort_rules = generate_snort_rules(anomalies_detected)
        print("Generated Snort Rules:")
        for rule in snort_rules:
            print(rule)
        with open('snort_rules.txt', 'w') as f:
            for rule in snort_rules:
                f.write(rule + '\n')
    else:
        print("No anomalies detected.")
    
    
if __name__ == "__main__":
    main()
