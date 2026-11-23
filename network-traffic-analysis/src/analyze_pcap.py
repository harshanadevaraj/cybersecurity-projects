
from scapy.all import (
    rdpcap, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR
)
from collections import Counter, defaultdict
from pathlib import Path
import argparse
import csv
import matplotlib.pyplot as plt


# ---------------- COMMAND-LINE ARGUMENTS ----------------

parser = argparse.ArgumentParser(
    description="Network Traffic Analysis and Rule-Based Anomaly Detection"
)

parser.add_argument("pcap", help="Path to PCAP file")
parser.add_argument(
    "--out",
    default="reports",
    help="Output directory (default: reports)"
)

args = parser.parse_args()

pcap_file = Path(args.pcap)
out_dir = Path(args.out)
out_dir.mkdir(parents=True, exist_ok=True)

if not pcap_file.exists():
    raise FileNotFoundError(f"PCAP file not found: {pcap_file}")

packets = rdpcap(str(pcap_file))


# ---------------- INITIALIZE COUNTERS ----------------

protocols = Counter()
source_ips = Counter()
destination_ips = Counter()
destination_ports = Counter()
dns_queries = Counter()
dns_by_source = Counter()

source_unique_ports = defaultdict(set)

packet_sizes = []
timestamps = []
packets_per_second = Counter()

syn_events = []
dns_events = []

ipv4_count = 0
ipv6_count = 0
arp_count = 0


# ---------------- PACKET PROCESSING ----------------

for packet in packets:

    packet_sizes.append(len(packet))

    try:
        timestamp = float(packet.time)
        timestamps.append(timestamp)
        packets_per_second[int(timestamp)] += 1
    except (ValueError, TypeError, AttributeError):
        continue

    # Count ARP packets separately
    if ARP in packet:
        arp_count += 1

    # Identify IPv4 or IPv6
    if IP in packet:
        layer = packet[IP]
        src = layer.src
        dst = layer.dst
        ipv4_count += 1

    elif IPv6 in packet:
        layer = packet[IPv6]
        src = layer.src
        dst = layer.dst
        ipv6_count += 1

    else:
        continue

    source_ips[src] += 1
    destination_ips[dst] += 1

    # TCP traffic
    if TCP in packet:
        protocols["TCP"] += 1

        tcp = packet[TCP]
        port = tcp.dport
        destination_ports[port] += 1
        source_unique_ports[src].add(port)

        # Record TCP SYN packets without ACK
        if tcp.flags & 0x02 and not tcp.flags & 0x10:
            syn_events.append((timestamp, src, port))

    # UDP traffic
    elif UDP in packet:
        protocols["UDP"] += 1

        port = packet[UDP].dport
        destination_ports[port] += 1
        source_unique_ports[src].add(port)

    # ICMP traffic
    elif ICMP in packet:
        protocols["ICMP"] += 1

    # ICMPv6 traffic
    elif IPv6 in packet and packet[IPv6].nh == 58:
        protocols["ICMPv6"] += 1

    else:
        protocols["OTHER"] += 1

    # DNS query extraction (exclude DNS responses)
    if DNS in packet and DNSQR in packet:

        dns = packet[DNS]

        if dns.qr == 0:

            query = packet[DNSQR].qname.decode(
                "utf-8",
                errors="replace"
            ).rstrip(".")

            dns_queries[query] += 1
            dns_by_source[src] += 1

            dns_events.append((timestamp, src))


# ---------------- ANOMALY DETECTION ----------------

alerts = []

WINDOW = 10

# Rule 1: Possible TCP port scan
# Threshold: 10 or more unique destination ports
# contacted by one source within a 10-second window.

scan_windows = defaultdict(set)

for timestamp, src, port in syn_events:

    window = int(timestamp // WINDOW)
    scan_windows[(src, window)].add(port)

for (src, window), ports in scan_windows.items():

    if len(ports) >= 10:

        alerts.append({
            "Rule": "Possible Port Scan",
            "Source": src,
            "Details": (
                f"{len(ports)} unique destination ports "
                f"within a 10-second window"
            )
        })


# Rule 2: High packet rate
# Threshold: 100 or more packets within one second.

for second, count in packets_per_second.items():

    if count >= 100:

        alerts.append({
            "Rule": "High Packet Rate",
            "Source": "Multiple/Unknown",
            "Details": f"{count} packets within one second"
        })


# Rule 3: High DNS query volume
# Threshold: 20 or more DNS queries from one source
# within a 10-second window.

dns_windows = Counter()

for timestamp, src in dns_events:

    window = int(timestamp // WINDOW)
    dns_windows[(src, window)] += 1

for (src, window), count in dns_windows.items():

    if count >= 20:

        alerts.append({
            "Rule": "High DNS Query Volume",
            "Source": src,
            "Details": (
                f"{count} DNS queries within a 10-second window"
            )
        })


# ---------------- GENERATE TEXT REPORT ----------------

report_file = out_dir / "analysis_report.txt"

with open(report_file, "w", encoding="utf-8") as report:

    report.write("===== NETWORK TRAFFIC ANALYSIS REPORT =====\n\n")

    report.write(f"PCAP File: {pcap_file.name}\n")
    report.write(f"Total Packets: {len(packets)}\n")
    report.write(f"IPv4 Packets: {ipv4_count}\n")
    report.write(f"IPv6 Packets: {ipv6_count}\n")
    report.write(f"ARP Packets: {arp_count}\n\n")

    report.write("--- Protocol Distribution ---\n")

    for protocol, count in protocols.most_common():
        report.write(f"{protocol}: {count}\n")

    report.write("\n--- Top Source IPs ---\n")

    for ip, count in source_ips.most_common(10):
        report.write(f"{ip}: {count}\n")

    report.write("\n--- Top Destination IPs ---\n")

    for ip, count in destination_ips.most_common(10):
        report.write(f"{ip}: {count}\n")

    report.write("\n--- Top Destination Ports ---\n")

    for port, count in destination_ports.most_common(10):
        report.write(f"{port}: {count}\n")

    report.write("\n--- DNS Queries ---\n")

    for domain, count in dns_queries.most_common(20):
        report.write(f"{domain}: {count}\n")

    report.write("\n--- Anomaly Indicators ---\n")

    if alerts:

        for alert in alerts:
            report.write(
                f"{alert['Rule']} | {alert['Source']} | "
                f"{alert['Details']}\n"
            )

    else:
        report.write("No rule thresholds triggered.\n")

    report.write("\n--- Detection Rule Configuration ---\n")
    report.write("Possible Port Scan: 10 unique TCP SYN destination ports in 10 seconds\n")
    report.write("High Packet Rate: 100 packets in one second\n")
    report.write("High DNS Query Volume: 20 queries from one source in 10 seconds\n")

    report.write(
        "\nNote: These are heuristic indicators, not proof of malicious activity. "
        "Fixed thresholds may produce false positives or miss activity. "
        "The capture is analyzed offline.\n"
    )


# ---------------- CSV EXPORTS ----------------

def save_counter_csv(counter, filename, key_name, value_name):

    with open(
        out_dir / filename,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)
        writer.writerow([key_name, value_name])

        for key, value in counter.most_common():
            writer.writerow([key, value])


save_counter_csv(
    protocols,
    "protocols.csv",
    "Protocol",
    "Packets"
)

save_counter_csv(
    source_ips,
    "source_ips.csv",
    "Source IP",
    "Packets"
)

save_counter_csv(
    destination_ips,
    "destination_ips.csv",
    "Destination IP",
    "Packets"
)

save_counter_csv(
    destination_ports,
    "destination_ports.csv",
    "Port",
    "Packets"
)

save_counter_csv(
    dns_queries,
    "dns_queries.csv",
    "Domain",
    "Queries"
)


# ---------------- VISUALIZATIONS ----------------

# 1. Protocol distribution
if protocols:

    plt.figure(figsize=(8, 5))
    plt.bar(protocols.keys(), protocols.values())

    plt.title("Protocol Distribution")
    plt.xlabel("Protocol")
    plt.ylabel("Packet Count")

    plt.tight_layout()
    plt.savefig(out_dir / "protocol_distribution.png")
    plt.close()


# 2. Top destination ports
top_ports = destination_ports.most_common(10)

if top_ports:

    labels, values = zip(*top_ports)

    plt.figure(figsize=(9, 5))
    plt.bar([str(port) for port in labels], values)

    plt.title("Top Destination Ports")
    plt.xlabel("Destination Port")
    plt.ylabel("Packet Count")

    plt.tight_layout()
    plt.savefig(out_dir / "top_ports.png")
    plt.close()


# 3. Top source IP addresses
top_sources = source_ips.most_common(10)

if top_sources:

    labels, values = zip(*top_sources)

    plt.figure(figsize=(10, 5))
    plt.bar(labels, values)

    plt.title("Top Source IP Addresses")
    plt.xlabel("Source IP")
    plt.ylabel("Packet Count")

    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(out_dir / "top_source_ips.png")
    plt.close()


# 4. Packet size distribution
if packet_sizes:

    plt.figure(figsize=(8, 5))
    plt.hist(packet_sizes, bins=30)

    plt.title("Packet Size Distribution")
    plt.xlabel("Packet Size (Bytes)")
    plt.ylabel("Frequency")

    plt.tight_layout()
    plt.savefig(out_dir / "packet_size_distribution.png")
    plt.close()


# 5. Traffic timeline
if timestamps:

    first_time = min(timestamps)
    relative_times = [
        timestamp - first_time for timestamp in timestamps
    ]

    plt.figure(figsize=(10, 5))
    plt.hist(relative_times, bins=30)

    plt.title("Packet Traffic Over Capture Duration")
    plt.xlabel("Time Since Capture Start (Seconds)")
    plt.ylabel("Packet Count")

    plt.tight_layout()
    plt.savefig(out_dir / "traffic_timeline.png")
    plt.close()


# ---------------- FINAL SUMMARY ----------------

print("\n===== ANALYSIS COMPLETE =====")
print(f"Packets analyzed: {len(packets)}")
print(f"IPv4: {ipv4_count} | IPv6: {ipv6_count} | ARP: {arp_count}")
print(f"Output directory: {out_dir.resolve()}")
print(f"Report: {report_file.resolve()}")
print(f"TCP SYN events: {len(syn_events)}")
print(f"DNS queries: {len(dns_events)}")
print(f"Anomaly indicators: {len(alerts)}")
