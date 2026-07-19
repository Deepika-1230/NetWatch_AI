# NetWatch AI Final

NetWatch AI is a Python 3.11 desktop SOC-style network monitoring and digital forensics platform. This final version mixes the polished CustomTkinter dashboard from the reference project with the safe demo features, geolocation map, one-click alert actions, and firewall response controls from the earlier NetWatch AI build.

The app starts in simulated capture mode by default, so it can be demonstrated without administrator packet-capture privileges, API keys, or internet access.

## Project Title

**NetWatch AI: AI-Powered Network Threat Monitoring and Forensic Analysis Tool**

## Short Description

NetWatch AI monitors live or simulated network traffic, detects suspicious activity using anomaly scoring and protocol rules, stores incidents in SQLite, supports offline PCAP investigation, checks threat intelligence sources, maps threat origins, and exports forensic reports.

## Key Features

- Live packet capture dashboard with Scapy live mode and safe simulated mode.
- Password login gate before opening the NetWatch AI dashboard.
- ML anomaly detection using Isolation Forest with heuristic fallback.
- Port scan, high traffic, suspicious payload, ARP spoofing, and DNS poisoning detection.
- Packet payload inspector with hex and ASCII evidence.
- Traffic behavior profiling and top talker analytics.
- Network topology mapper using NetworkX and Matplotlib.
- IP geolocation threat map with offline demo coordinates.
- CVE vulnerability lookup using the NVD API or simulated offline results.
- VirusTotal IP reputation lookup or simulated offline results.
- One-click alert actions: reputation check, CVE lookup, and source IP block preview.
- AI threat explanation that describes each alert in simple, user-friendly language.
- Risk score system that rates every alert from 1 to 100 using severity, ML score, category, sensitive ports, public IPs, and trusted-device status.
- Device trust list for known safe IPs or MAC addresses to reduce false-positive risk scores.
- Incident timeline view showing observed traffic, detection reason, and suggested response in order.
- Network devices page showing observed LAN and external hosts ranked by traffic.
- Full CRUD device inventory using SQLite: create, read, update, and delete monitored devices.
- Remediation suggestions for each threat, including safe next steps for DNS, ARP, payload, scan, and anomaly alerts.
- Safe firewall blocking support for Windows Firewall and iptables.
- Desktop notifications for high and critical threats when `plyer` is installed.
- SQLite packet, alert, reputation, and CVE history.
- Offline PCAP/PCAPNG analysis through Scapy or PyShark support.
- Forensic PDF report export with metrics, alerts, and topology snapshot.
- Reports center for viewing saved PDFs and exporting a new investigation report.
- Built-in project guide page for demo flow and viva explanation.
- Login password change support from the Settings page.

## Tech Stack

- Python 3.11+
- CustomTkinter
- Scapy and PyShark
- scikit-learn
- NetworkX and Matplotlib
- pandas-ready CSV workflow
- fpdf2
- sqlite3
- requests for NVD and VirusTotal
- geoip2 optional support
- plyer notifications

## How To Run

```bash
cd NetWatchAI_Final
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python main.py
```

The app opens with a login screen. You can change the login password from `Settings` after unlocking the dashboard.

To reset the login password from code/terminal:

```bash
python reset_login_password.py newpassword123
```

On macOS or Linux:

```bash
source .venv/bin/activate
```

## Live Capture Notes

The app defaults to simulated mode. To capture real traffic:

1. Open `Settings`.
2. Set `Mode` to `live`.
3. Optionally enter a network interface.
4. Save settings.
5. Start capture from the dashboard.

Live capture usually requires administrator/root privileges. On Windows, install Npcap. For PyShark workflows, install Wireshark/TShark and make sure `tshark` is available on PATH.

## Firewall Blocking Safety

Firewall blocking is preview-only by default. In `Settings`, enable **Execute firewall commands** only when you are sure you want the app to add real Windows Firewall or iptables rules.

## Project Structure

```text
NetWatchAI_Final/
|-- main.py
|-- reset_login_password.py
|-- core/
|   |-- analyzer.py
|   |-- arp_detector.py
|   |-- auth.py
|   |-- blocker.py
|   |-- controller.py
|   |-- dns_detector.py
|   |-- geolocator.py
|   |-- intel.py
|   |-- ml_engine.py
|   |-- notifier.py
|   |-- payload_inspector.py
|   |-- sniffer.py
|   |-- threat_enrichment.py
|   |-- topology_mapper.py
|-- gui/
|   |-- analytics.py
|   |-- app.py
|   |-- dashboard.py
|   |-- devices.py
|   |-- forensics.py
|   |-- geo_map.py
|   |-- guide.py
|   |-- login.py
|   |-- reports.py
|   |-- settings.py
|   |-- theme.py
|   |-- threats.py
|   |-- timeline.py
|-- database/
|   |-- threat_store.py
|-- reports/
|   |-- report_generator.py
|-- assets/
|-- logs/
|-- models/
|-- requirements.txt
|-- README.md
```

## Defensive Use

Use this project only on your own computer, a lab network, or a network where you have permission. It is designed for defensive monitoring, incident response, classroom demonstration, and authorized testing.
