# Network Anomaly Detection and Snort Rule Generation

## Overview

This set of Python scripts allows for the analysis of network traffic captured in a pcap file using `scapy`, and subsequently generates Snort rules based on detected anomalies.

### Scripts:

1. **packetcapture.py**: Captures network traffic on a specified interface for a given duration and saves it to a pcap file using `scapy`.

2. **SnortRules.py**: Analyzes a pcap file and generates Snort rules for potential network anomalies such as suspicious IP activity, unusual port usage, potential DNS tunneling, and port scans.

3. **rule-gen.py**: Processes a pcap file to generate Snort rules for detecting specific network behaviors and patterns.

## Installation

Before using these scripts, ensure you have Python installed (version 3.6 or higher).

### Dependencies

Install the required Python libraries using `pip` and the provided `requirements.txt` file:

```bash
pip install -r requirements.txt

### Usage
Capture Network Traffic (optional)

If you don't have an existing pcap file and want to capture new network traffic:

```bash
Copy code
python packetcapture.py <interface> <duration> <output_file>
<interface>: Network interface name (e.g., eth0, wlan0).
<duration>: Duration in seconds to capture traffic.
<output_file>: Name of the output pcap file to save captured packets.
Detect Anomalies and Generate Snort Rules

### Analyze a pcap file and generate Snort rules using SnortRules.py:

```bash
Copy code
python SnortRules.py <pcap_file>
<pcap_file>: Path to the pcap file to analyze.
Customize and Extend

Adjust thresholds and specific detection criteria in SnortRules.py and rule-gen.py as needed.
Modify generated Snort rules (generate_snort_rules() function in SnortRules.py) to fit your network security requirements.
