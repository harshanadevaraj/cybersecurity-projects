
# Network Traffic Analysis and Rule-Based Anomaly Detection

## Overview

A Python-based network traffic analysis tool that processes PCAP files offline to extract network metadata, summarize traffic patterns, visualize packet statistics, and identify potential anomalies using configurable heuristic rules.

## Objectives

- Analyze IPv4 and IPv6 network traffic.
- Identify TCP, UDP, ICMP and ICMPv6 traffic.
- Summarize source and destination IP addresses.
- Analyze destination port distributions.
- Extract DNS queries.
- Visualize packet sizes and traffic distribution over time.
- Identify potential port scans, high packet rates and DNS query bursts.

## Technologies

- Python
- Scapy
- Wireshark
- Matplotlib
- CSV

## Project Structure

```text
network-traffic-analysis/
├── src/
│   └── analyze_pcap.py
├── data/
│   └── pcap/
├── reports/
│   ├── analysis_report.txt
│   ├── protocols.csv
│   ├── source_ips.csv
│   ├── destination_ips.csv
│   ├── destination_ports.csv
│   ├── dns_queries.csv
│   ├── protocol_distribution.png
│   ├── top_ports.png
│   ├── top_source_ips.png
│   ├── packet_size_distribution.png
│   └── traffic_timeline.png
├── requirements.txt
└── README.md
```

## Installation

Clone the repository:

```bash
git clone <YOUR_REPOSITORY_URL>
cd network-traffic-analysis
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the analyzer:

```bash
python src/analyze_pcap.py data/pcap/sample.pcap --out reports
```

The tool generates a text report, CSV summaries and visualizations.

## Anomaly Detection Rules

The analyzer implements three heuristic detection rules:

| Detection rule | Threshold |
|---|---|
| Possible TCP port scan | 10 unique destination ports from one source within a 10-second fixed window |
| High packet rate | 100 or more packets within one second |
| High DNS query volume | 20 or more DNS queries from one source within a 10-second fixed window |

These rules identify potential indicators and do not independently establish malicious activity.

## Sample Analysis

The development capture contained:

- 668 total packets
- 525 IPv4 packets
- 129 IPv6 packets
- 14 ARP packets
- 315 TCP packets
- 306 UDP packets
- 53 DNS queries

No anomaly thresholds were triggered in this capture.

## Limitations

- Detection uses fixed thresholds and may produce false positives or false negatives.
- The analyzer performs offline PCAP analysis, not live network monitoring.
- The current port-scan rule considers TCP SYN packets.
- Encrypted application payloads are not inspected.
- Results depend on the completeness and quality of the capture.


## Future Improvements

- Sliding-window anomaly detection.
- Configurable detection thresholds.
- Additional TCP behavior analysis.
- More comprehensive IPv6 and DNS analysis.
- Automated HTML report generation.
