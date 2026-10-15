# 🛡️ Nessus Network Shield — Office Network SOC Dashboard

An enterprise-grade Security Operations Center (SOC) dashboard designed for analyzing and visualizing **Tenable Nessus** vulnerability scans, office subnet discovery, open port services, and network packet telemetry.

![SOC Aesthetic](https://img.shields.io/badge/Aesthetic-Cyber%20Dark%20SOC-06b6d4?style=for-the-badge)
![Nessus Ready](https://img.shields.io/badge/Tenable%20Nessus-v8%20%7C%20v10%2B-0284c7?style=for-the-badge)
![Zero Dependencies](https://img.shields.io/badge/Frontend-Vanilla%20JS%20%26%20CSS-10b981?style=for-the-badge)

---

## 🌟 Key Features

### 1. 📊 Executive Posture & Analytics Overview
- **Vulnerability Matrix Donut**: Visual breakdown across Critical, High, Medium, Low, and Info severities with neon glow indicators.
- **Office Threat Risk Index (0–100)**: Real-time calculated risk gauge based on VPR (Vulnerability Priority Rating), public exploits, and high-value target exposure.
- **Top Vulnerable Office Assets**: Prioritized remediation ranking of compromised workstations and servers.
- **Exposed Services Distribution**: Frequency analysis of exposed protocols (SMB 445, RDP 3389, HTTP 80/443, SSH 22, etc.).

### 2. 🌐 Subnet & Office Topology Map
- Grouped by corporate network segments:
  - `192.168.20.0/24`: Core Servers & Active Directory VLAN
  - `10.0.50.0/24`: Edge Perimeter & SSL-VPN DMZ
  - `192.168.10.0/24`: Corporate User Workstations (Finance, HR, Engineering)
  - `192.168.30.0/24`: Office IoT (Network Printers, VoIP Conference Phones)
- Interactive host cards with real-time port tags, OS identification, and severity alert levels.

### 3. 🔍 Deep-Dive Host Inspector Drawer
- Click any office machine to inspect:
  - FQDN, IP, MAC address, detected OS version.
  - Active open ports with service banner grabs.
  - Prioritized list of all vulnerabilities found on that specific host.

### 4. 🛡️ Vulnerability & CVE Matrix
- Filterable and searchable catalog with instant search across CVE, Plugin ID, host, and plugin family.
- Deep-dive vulnerability modal:
  - Synopsis & Description
  - CVSS v3.0 & Tenable VPR scores
  - Exploit availability flag (Metasploit, public PoC, active in the wild)
  - **Packet probe evidence**: Raw packet traces showing handshake and service trigger responses
  - Vendor-approved remediation and patch solutions

### 5. 🦈 Wireshark Packet Tracker & Web/User Intelligence
- **Websites & Domains Intelligence**: Extracts exact visited websites from DNS queries and TLS SNI handshakes (`github.com`, `youtube.com`, `google.com`, `microsoft.com`, `aws.amazon.com`, internal portals).
- **User & Device Attribution**: Directly tracks which user/IP accessed which website, request frequencies, and bandwidth consumed.
- **Wireshark 3-Pane Dissector**:
  - Color-coded packet grid (TCP, UDP, TLS, DNS, HTTP, ARP, ICMP).
  - Protocol Details Tree (Ethernet II ➔ IPv4 ➔ TCP/UDP ➔ Application Layer).
  - Raw Hexadecimal & printable ASCII dump inspector.
- **Native `.pcap` & `.pcapng` Ingestion**: Drag & drop any capture file saved from Wireshark for instant client-side dissection.
- **Live Packet Sniffing**: Real-time packet telemetry streaming with 1-click start/pause controls.

### 6. ⚡ Live Tenable Nessus REST API Connector
- Direct integration with Nessus Professional / Expert / Scanner REST APIs.
- Endpoints supported:
  - `GET /server/status`
  - `GET /scans`
  - `GET /scans/{id}`
  - `GET /scans/{id}/hosts/{id}`
  - `GET /scans/{id}/plugins/{id}`
- Synchronize remote scans directly into the dashboard with 1 click.

### 7. 📁 Client-Side `.nessus` (XML) & JSON Parser
- Drag & drop native `.nessus` (XML v2) files directly into the dashboard.
- 100% client-side: processed securely in the browser without uploading files to any external cloud.

---

## 🚀 Quick Start Guide

### Option A: Launching via Local Web Server (Recommended)

1. Open a terminal in this directory:
   ```powershell
   cd C:\Users\Dhiraj\.gemini\antigravity-ide\scratch\nessus-office-dashboard
   ```
2. Start the HTTP server:
   ```powershell
   python -m http.server 8090
   ```
3. Open your browser to:
   ```text
   http://localhost:8090/index.html
   ```

---

## ⚡ Connecting to Live Tenable Nessus Scanners

Tenable Nessus runs on `https://<ip>:8834` with self-signed SSL certificates. Because modern browsers enforce strict CORS and certificate validation on client-side JavaScript requests, we have included an ultra-lightweight, zero-dependency Node.js proxy.

### Step 1: Start the Local Proxy
Double click `proxy/start-proxy.bat` or run:
```powershell
node proxy/server.js
```
*Proxy starts on `http://localhost:3000` with automatic CORS bypass and self-signed SSL certificate handling.*

### Step 2: Configure Credentials in the Dashboard
1. Click **API Config** (`⚙️`) in the top navigation bar.
2. Enter your Nessus details:
   - **Nessus Server URL**: `https://localhost:8834` (or your remote scanner IP)
   - **Access Key**: (Generated from *Nessus -> Settings -> My Account -> API Keys*)
   - **Secret Key**: (Your secret API key)
   - Check **Use Local Proxy** (Default: `http://localhost:3000/api/nessus`)
3. Click **Test Connection** or **Save & Connect**.
4. Switch to the **Live Nessus API** tab to select and load any active office network scan!

---

## 📁 Project Architecture

```
nessus-office-dashboard/
├── index.html                  # Main SOC Dashboard UI
├── css/
│   └── styles.css              # Cyber Dark Glassmorphic Design System
├── js/
│   ├── app.js                  # Main Application Controller & UI logic
│   ├── nessus-api.js           # Tenable Nessus REST API Client
│   ├── nessus-parser.js        # Native .nessus (XML) and JSON parser
│   ├── charts.js               # Canvas/SVG Donut, Gauges, & Bar charts
│   └── mock-data.js            # Pre-loaded realistic office network scan
├── proxy/
│   ├── server.js               # Zero-dependency Node.js CORS/SSL Proxy
│   └── start-proxy.bat         # 1-Click Windows execution script
└── README.md                   # System documentation & usage guide
```

---

## 📊 Pre-Loaded Enterprise Demo Dataset
The dashboard comes with realistic corporate network assessment data:
- **APP-SRV01 (192.168.20.12)**: Apache Log4j RCE (CVE-2021-44228) with Metasploit payload evidence.
- **DC01 (192.168.20.5)**: Windows PrintNightmare (CVE-2021-34527) & SMB signing verification.
- **FIN-WS-09 (192.168.10.45)**: EternalBlue SMBv1 (CVE-2017-0144) on finance workstation.
- **FW-EDGE01 (10.0.50.1)**: Fortinet FortiOS SSL-VPN buffer overflow (CVE-2022-42475).
- **PRINTER-FL2-HP (192.168.30.15)**: Default SNMP community string `public` exposed on office IoT.
