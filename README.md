# 🛡️ Optox Shield — Frontend Console (Pure Node.js)

A lightweight, high-performance SOC Security Dashboard and Telemetry Visualizer for **Optox Shield PBX Defense**. Built in pure Node.js and Vanilla CSS/HTML with **zero external NPM packages required**.

---

## 🌟 Features
- **Pure Node.js Architecture**: 0 external npm dependencies, runs instantly on any machine with Node.js 16+.
- **Real-Time Attack Visualizer**: Live Chart.js attack vector matrix, sliding window telemetry, and call logs.
- **Dynamic Threat Thresholds**: Configure and enforce instant per-caller `INVITE_FLOOD` rules.
- **Multi-Server PBX Fleet Manager**: Switch between Staging, Production, and Local PBX instances seamlessly.
- **1-Click Firewall & Blacklist Management**: Unban malicious IPs and whitelist legitimate carrier trunks on the fly.

---

## 🚀 Quick Start

### 1. Prerequisites
- **Node.js**: Version `16.x` or higher (`node --version`)

### 2. Run the Dashboard
```bash
# Clone repository
git clone https://github.com/trutechlab/Opto-shield-frontend-.git
cd Opto-shield-frontend-

# Start Node.js Web Server
node server.js
# (or: npm start)
```

### 3. Open in Browser
Visit **`http://localhost:9000`** in Google Chrome, Edge, Safari, or Firefox.

- **Default Username**: `admin`
- **Default Password**: `admin123`

---

## ⚙️ Environment Variables (Optional)

Create a `.env` file in the root directory:
```ini
HOST=0.0.0.0
PORT=9000
FRONTEND_ADMIN_USER=admin
FRONTEND_ADMIN_PASS=admin123
DEFAULT_BACKEND_HOST=10.0.9.249
DEFAULT_BACKEND_PORT=5000
DEFAULT_BACKEND_PROTOCOL=http
DEFAULT_API_KEY=5e2930ea32cdf5c8cc6f6a6476077b82103ef6456e92050fa2acbd7d09d4ce78
```

---

## 📂 Project Structure
```text
opto-shield-frontend/
├── index.html              # Standalone Dark-Glass SOC Dashboard UI
├── server.js               # Pure Node.js Web Server & Backend Reverse Proxy
├── package.json            # NPM Package Manifest (node server.js)
├── run_local_frontend.bat  # Windows 1-Click Launch Script
├── .env.example            # Environment Configuration Template
├── .gitignore              # Node.js Git Exclusions
└── README.md               # Documentation
```
