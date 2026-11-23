# Cybersecurity Projects

Hands-on cybersecurity projects focused on network traffic analysis,
web application security testing, and vulnerability documentation.

These projects demonstrate practical exploration of security concepts
through controlled, locally hosted lab environments.

## Projects

### 1. Network Traffic Analysis and Anomaly Detection

**Technologies:** Python, Scapy, Wireshark, Matplotlib

A Python-based tool for analyzing packet captures and summarizing
network protocols, traffic patterns, and selected anomaly indicators.

Key work:
- Parsed PCAP files and extracted packet-level information.
- Analyzed protocol and network traffic distributions.
- Implemented heuristic indicators for possible port scanning,
  high packet rates, and DNS query bursts.
- Generated analysis summaries and visualizations.

[View project](network-traffic-analysis/)

### 2. Web Application Security Assessment

**Technologies:** Burp Suite Community Edition, OWASP Juice Shop, Docker

A manual security assessment of a deliberately vulnerable web
application deployed locally.

Key work:
- Inspected HTTP requests and authentication traffic.
- Tested object-level authorization using separate test accounts.
- Identified unauthorized access to another user's basket metadata.
- Tested user-controlled search input and observed JavaScript execution.
- Documented findings, impact, limitations, and remediation.

[View project](web-application-security/)

## Scope and Responsible Testing

All web application testing was conducted against a local,
intentionally vulnerable OWASP Juice Shop instance.
Network analysis was performed on locally captured traffic.

The anomaly indicators are heuristic and are not presented as
validated intrusion detection mechanisms.

## Author

Computer Science and Engineering graduate building practical
skills in network security, vulnerability analysis, and
application security.
