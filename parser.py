"""
This script declare a parse_pcap function that taking in a pcap file and
parse the following TCP/UDP/ICMP/IP/DNS/payload into a dictionary and save into a CVS file
"""
from scapy.all import *

packets = '/Users/hieu/PycharmProjects/pythonProject/test.pcapng'  # Replace with your actual pcap file location


def parse(x):
    file = PcapReader(packets)
    for packet in file:
        parse_data = {}
        parse_data['Timestamp'] = packet.time
        if 'IP' in packet:
            parse_data['ip_src'] = packet['IP'].src
            parse_data['ip_dst'] = packet['IP'].dst
        if 'Ether' in packet:
            parse_data['src_mac'] = packet['Ether'].src
            parse_data['dst_mac'] = packet['Ether'].dst
        if 'TCP' in packet:
            parse_data['protocol'] = 'TCP'
            parse_data['tcp_scr'] = packet['TCP'].sport
            parse_data['tcp_dst'] = packet['TCP'].dport
            if packet['TCP'].flags & 0x02:
                parse_data['suspicious_tcp_syn'] = packet.summary()
        if 'UDP' in packet:
            parse_data['protocol'] = 'UDP'
            parse_data['udp_src'] = packet['UDP'].sport
            parse_data['udp_dst'] = packet['UDP'].dport
        if 'ICMP' in packet:
            parse_data['protocol'] = 'ICMP'
            parse_data['icmp_type'] = packet['ICMP'].type
            parse_data['icmp_code'] = packet['ICMP'].code
        if 'Raw' in packet:
            parse_data['payload'] = packet['Raw'].load
        if 'DNS' in packet:
            parse_data['dns_query_type'] = packet['DNS'].qd
            parse_data['dns_response'] = packet['DNS'].ns

        with open('pcap.cvs', 'a+') as f:
            f.write(f"{parse_data}\n")
        print(parse_data)



parse(packets)
