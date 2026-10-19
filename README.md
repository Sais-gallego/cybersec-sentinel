# 🛡️ CyberSec Sentinel

[![CI Tests](https://github.com/Sais-gallego/cybersec-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/Sais-gallego/cybersec-sentinel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Cisco Cybersecurity](https://img.shields.io/badge/Designed%20by-Cisco%20Certified%20Analyst-1BA0D7.svg)](https://github.com/Sais-gallego)

**CyberSec Sentinel** is an open-source, production-grade cybersecurity and network defense toolkit designed for security engineers, penetration testers, and system administrators.

Developed by **Sergio Andrés Ipuz Saavedra** ([@Sais-gallego](https://github.com/Sais-gallego)), Junior Cybersecurity Analyst (Cisco Networking Academy & UNAD) and Full Stack Software Engineer.

---

## ⚡ Core Modules & Capabilities

1. 🔍 **Concurrent Network & Port Scanner:**
   - Multi-threaded asynchronous port scanner.
   - Automatic service banner identification (`HTTP`, `SSH`, `FTP`, `MySQL`, `Redis`, `MongoDB`).
2. 🌐 **HTTP Security Headers Auditor:**
   - Evaluates compliance against OWASP defensive standards (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Permissions-Policy`).
   - Identifies sensitive technology leakage (`Server`, `X-Powered-By`).
   - Assigns instant letter grades (`A+`, `A`, `B`, `C`, `F`).
3. 🔐 **Cryptographic & Password Strength Engine:**
   - Calculates **Shannon Entropy** in bits.
   - Evaluates password complexity against modern brute-force thresholds.
   - Automated cryptographic hash identification (`MD5`, `SHA-1`, `SHA-256`, `SHA-512`, `Bcrypt`).

---

## 🚀 Quickstart & Installation

```bash
# Clone the repository
git clone https://github.com/Sais-gallego/cybersec-sentinel.git
cd cybersec-sentinel

# Install package in development mode
pip install -e .
```

---

## 💻 CLI Usage Examples

### 1. Port & Service Scanning
```bash
# Quick scan common infrastructure ports
python -m sentinel.cli scan scanme.nmap.org

# Scan specific custom ports
python -m sentinel.cli scan 192.168.1.1 -p 22,80,443,8080
```

### 2. Web Security Headers Audit
```bash
python -m sentinel.cli audit github.com
```

### 3. Password Strength & Hash Detection
```bash
# Evaluate password entropy
python -m sentinel.cli crypto -p "CorrectHorseBatteryStaple!2026"

# Identify hash algorithm
python -m sentinel.cli crypto --hash "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
```

---

## 🧪 Testing

```bash
pytest tests/ -v
```

---

## 📄 License
Released under the [MIT License](LICENSE).
