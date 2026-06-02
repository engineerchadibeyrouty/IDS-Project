# Network Intrusion Detection System (IDS)

A real-time Network Intrusion Detection System built with Python.

## What it does
- Monitors live network traffic
- Detects Port Scans, DoS Attacks, SYN Floods, UDP Floods
- Displays live alerts on a web dashboard

## Technologies Used
- Python
- Scapy (packet sniffing)
- Flask (web dashboard)
- Chart.js (data visualization)

## How to run
1. Install requirements: pip install scapy flask
2. Run IDS: python ids.py
3. Run Dashboard: python app.py
4. Open browser: http://127.0.0.1:5000

## Screenshots
Dashboard shows live alerts, attack types chart, and top attacker IPs.
