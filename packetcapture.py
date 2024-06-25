import sys
from scapy.all import sniff, wrpcap
import psutil

def list_interfaces():
  interfaces = psutil.net_if_addrs()
  return list(interfaces.keys())

def capture_traffic(interface, duration, output_file):
  packets = []

  def packet_handler(packet):
    packets.append(packet)
    print(f"Captured packet: {packet.summary()}")

  print(f"Starting packet capture on interface {interface} for {duration} seconds...")
  sniff(iface=interface, prn=packet_handler, timeout=duration)
  wrpcap(output_file, packets)
  print(f"Packet capture complete. {len(packets)} packets captured and saved to {output_file}")

def main():
  if len(sys.argv) != 4:
    print("Usage: python packetcapture.py <interface> <duration> <output_file>")
    return

  interface = sys.argv[1]
  duration = int(sys.argv[2])
  output_file = sys.argv[3]

  interfaces = list_interfaces()
  if interface not in interfaces:
    print(f"Error: Interface {interface} does not exist.")
    return

  capture_traffic(interface, duration, output_file)

if __name__ == "__main__":
  main()
