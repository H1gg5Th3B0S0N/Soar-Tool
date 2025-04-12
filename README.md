# 🚨 SOAR Tool - Malicious IP Blocking Dashboard

A lightweight SOAR (Security Orchestration, Automation, and Response) GUI tool built in Python for monitoring system logs in real-time and automatically detecting & blocking malicious IP addresses using `iptables`.

---

## 📌 Features

- 🔍 **Real-time SSH brute-force detection** using log analysis  
- 🔒 **Automatic blocking** of IPs via `iptables`  
- 🧠 **Basic threshold logic** for detecting repeated failed login attempts  
- 📊 **User-friendly dashboard** with tkinter GUI  
- 🔁 **Manual unblock/block** functionality via GUI  
- 🪵 Live log tracking with `journalctl`  

---

## ⚙️ How It Works

1. Reads logs in real-time using `journalctl`
2. Detects repeated failed login attempts (default: ≥ 5 within 60 seconds)
3. Flags the source IP as malicious
4. Automatically applies an `iptables` rule to block the IP
5. Logs the incident in a visual dashboard with time, status, and actions

---

## 🚀 Getting Started

1. Clone the repository:

```bash
git clone https://github.com/H1gg5Th3B0S0N/Soar-Tool.git
cd Soar-Tool
```

2. Run the tool with Python:

```bash
sudo python3 Threat_Blocker_v1.py
```

✅ **Important:** `sudo` is required to apply `iptables` rules.

---

## 🔒 Example Detection

The tool currently detects:
- 🚨 SSH brute-force attacks (via `journalctl` pattern: `Failed password for ... from IP`)

More patterns and detection types (FTP, HTTP attacks, port scanning, etc.) can be added easily using regex in the `monitor_logs()` method.

---

## 🛡️ Use Cases

- Personal/home server protection  
- Educational cybersecurity project  
- Lightweight SOAR prototype for detection-response automation  
- Real-time dashboard for basic incident tracking  

---

## 🧠 Future Improvements

- Add support for other services (FTP, Apache, Nginx, etc.)  
- JSON-based rule configuration  
- Email alerting or logging to external services  
- Containerization (Docker)  
- Log saving and exporting feature  
