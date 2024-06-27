import pyfiglet
import subprocess
import os
import psutil

def list_interfaces():
  # Function to list available network interfaces for user to choose from
  interfaces = psutil.net_if_addrs()
  print("Available network interfaces:")
  for idx, interface in enumerate(interfaces.keys()):
    print(f"{idx}: {interface}")
  return list(interfaces.keys())

def run_script(script_name, *args):
  command = ["python", script_name] + list(args)
  result = subprocess.run(command, capture_output=True, text=True)
  print(result.stdout)
  if result.stderr:
    print(f"Error running {script_name}: {result.stderr}")
  return result

def main():
  ascii_banner = pyfiglet.figlet_format("SNORT RULES")
  print(ascii_banner)

  choice = input("Do you have an existing pcap file? (y/n): ").strip().lower()
  if choice == 'y':
    pcap_file = input("Enter the path to the pcap file: ").strip()
    if not os.path.isfile(pcap_file):
      print("The specified file does not exist. Exiting.")
      return
  elif choice == 'n':
    # Ask user for network interface, duration, and output file name
    # List interfaces if not provided
    interfaces = list_interfaces()
    choice = int(input("Select the interface number: "))
    if choice < 0 or choice >= len(interfaces):
      print("Invalid choice. Exiting.")
      return
    interface = interfaces[choice]
    duration = input("Enter the capture duration in seconds: ").strip()
    output_file = input("Enter the output pcap file name: ").strip()

    # Run packet capture script with provided arguments
    print("Running packet capture...")
    
    result = run_script("packetcapture.py", interface, duration, output_file)
    if result.returncode != 0:
      print("Failed to run packetcapture.py")
      return

    pcap_file = output_file
  else:
    print("Invalid choice. Exiting.")
    return


  # Run rule-gen.py with the pcap file as an argument
  print(f"Processing pcap file: {pcap_file}")
  result = run_script("rule-gen.py", pcap_file)
  if result.returncode != 0:
    print("Failed to run rule-gen.py")
    return
  

if __name__ == "__main__":
  main()
