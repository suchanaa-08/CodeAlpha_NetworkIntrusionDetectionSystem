# Network Intrusion Detection System (NIDS)

## Project Overview

A Network Intrusion Detection System developed using Suricata and Python to monitor network traffic, detect suspicious activities, generate security alerts, and record response actions.

The project also includes an interactive dashboard developed using Streamlit for visualizing detected alerts and response history.

## Technologies Used

- Python
- Suricata IDS
- Npcap
- Streamlit
- Pandas
- Plotly
- Windows 11
- Visual Studio Code

## Project Structure

```text
NIDS/
│
├── dashboard/
│   └── app.py
│
├── logs/
│   └── .gitkeep
│
├── rules/
│   └── local.rules
│
├── src/
│   ├── alert_processor.py
│   ├── live_alert_monitor.py
│   └── response.py
│
├── .gitignore
├── requirements.txt
└── README.md
```

## Features

1. Network traffic monitoring using Suricata.
2. Custom ICMP detection rules.
3. Automatic generation of security alerts.
4. Python-based alert processing.
5. Continuous monitoring of Suricata EVE logs.
6. Intrusion response logging.
7. Interactive security dashboard.
8. Alert visualization using charts and tables.

## Installation

### 1. Install prerequisites

- Python 3
- Suricata
- Npcap
- Visual Studio Code

### 2. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd NIDS
```

### 3. Install Python dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Configure Suricata

Install Suricata and Npcap on Windows.

Configure the Suricata YAML configuration file and custom detection rules according to your network adapter.

### 5. Start Suricata

Run Suricata with the configured network interface, custom rules and project logs directory.

### 6. Start continuous monitoring

```bash
python src/live_alert_monitor.py
```

### 7. Launch the dashboard

```bash
python -m streamlit run dashboard/app.py
```

Open the local URL provided by Streamlit, usually:

```text
http://localhost:8501
```

## Dashboard

The dashboard provides:

- Total detected alerts
- Unique source IP addresses
- Response records
- Protocol distribution
- Severity distribution
- Detected intrusion alert history
- Response history

## Detection and Response

Suricata detects traffic matching configured rules and generates alerts in EVE JSON format.

Python processes these alerts and records the source IP, destination IP, protocol, signature, severity, and recommended response action.

The current implementation records and recommends security responses; it does not automatically block network traffic.

## Platform

Developed and tested on Windows 11.

## Author

Suchana Pan