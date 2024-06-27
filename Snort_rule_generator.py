import csv
from datetime import datetime


def parse_pcap(pcap_file):
    packets = PcapReader(pcap_file)
    parsed_data = []
    for packet in packets:
        data = {
            'Timestamp': datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
        }
        if 'IP' in packet:
            data['ip_src'] = packet['IP'].src
            data['ip_dst'] = packet['IP'].dst
        if 'Ether' in packet:
            data['src_mac'] = packet['Ether'].src
            data['dst_mac'] = packet['Ether'].dst
        if 'TCP' in packet:
            data['protocol'] = 'TCP'
            data['tcp_src'] = packet['TCP'].sport
            data['tcp_dst'] = packet['TCP'].dport
            if packet['TCP'].flags & 0x02:  # SYN flag
                data['suspicious_tcp_syn'] = packet.summary()
        if 'UDP' in packet:
            data['protocol'] = 'UDP'
            data['udp_src'] = packet['UDP'].sport
            data['udp_dst'] = packet['UDP'].dport
        if 'ICMP' in packet:
            data['protocol'] = 'ICMP'
            data['icmp_type'] = packet['ICMP'].type
            data['icmp_code'] = packet['ICMP'].code
        if 'Raw' in packet:
            data['payload'] = str(packet['Raw'].load)
        if 'DNS' in packet:
            data['dns_query_type'] = packet['DNS'].qd.qtype
            data['dns_response'] = packet['DNS'].ns
        parsed_data.append(data)
    return parsed_data


def generate_snort_rules(anomalies):
    snort_rules = []
    for anomaly in anomalies:
        if anomaly['type'] == 'High traffic':
            rule = f'alert ip {anomaly["ip"]} any -> any any (msg:"High traffic detected from {anomaly["ip"]}"; sid:1000001; rev:1;)'
        elif anomaly['type'] == 'Suspicious TCP SYN':
            rule = f'alert tcp {anomaly["ip"]} any -> any any (msg:"Suspicious TCP SYN from {anomaly["ip"]}"; flags:S; sid:1000002; rev:1;)'
        # Add more conditions based on other anomaly types as needed
        snort_rules.append(rule)
    return snort_rules


def main(pcap_file, anomalies):
    parsed_data = parse_pcap(pcap_file)
    snort_rules = generate_snort_rules(anomalies)
    print("Generated Snort Rules:")
    for rule in snort_rules:
        print(rule)
    with open('snort_rules.txt', 'w') as f:
        for rule in snort_rules:
            f.write(rule + '\n')


if __name__ == "__main__":
    pcap_file = 'path_to_your_pcap_file.pcap'
    # Example anomalies, replace with actual detected anomalies
    anomalies = [
        {'ip': '192.168.1.1', 'type': 'High traffic'},
        {'ip': '10.0.0.1', 'type': 'Suspicious TCP SYN'}
    ]
    main(pcap_file, anomalies)
