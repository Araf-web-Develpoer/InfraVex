<div align="center">

# `veex0x01-intel`

**Infrastructure Intelligence & Attack Surface Mapping Framework**

*Built strictly for Authorized Security Assessments, Blue/Purple Team Operations, Internal Visibility, and Bug Bounty within scope.*

[![Go Version](https://img.shields.io/badge/go-1.22+-blue.svg)](https://golang.org/dl/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

</div>

---

## 🧠 Overview

`veex0x01-intel` is a modular, high-performance, concurrent infrastructure mapping engine designed by `veex0x01`. It performs intelligent gathering and attack surface resolution without relying on unsafe or blind internet-wide scanning.

The engine leverages:

* Goroutines & Worker Pools for massive concurrency.
* Strict in-memory scope enforcement to ensure **Legal-by-Design** execution.
* CDN & Cloud edge node auto-detection to prevent useless scanning.
* Context-aware API rate limiting and intelligent reporting.

## ⚡ Features

* **Passive Reconnaissance Mode** 🕵️‍♂️: Domain resolution, WHOIS, and ASN extraction without touching target infrastructure directly.
* **Active Scanning Mode** 🚀: Extremely fast parallel TCP sweeps with concurrent safety (Semaphore limits built-in to prevent Linux `OOM Killed`).
* **CDN Auto-Bypass** ☁️: Identifies Cloudflare, Akamai, Fastly, Amazon IPs and refuses to execute edge-node active port scans, ensuring findings are relevant to the actual origin structure.
* **Multi-Target Ingestion**: Supports single domains via CLI, or bulk processing via text files (`--scope`).
* **SQLite Storage**: Built-in persistent local asset tracking.
* **Advanced Reporting** 📊: Generates interactive Markdown (`report.md`) and JSON (`report.json`) exports for easy parsing into SIEMs or Bug Bounty submissions.

---

## 🛠️ Output & Architecture

### Intelligence Workflow:

1. **Input & Validation**: Checks domains, IPs, and CIDRs for valid structures.
2. **Scope Enforcement Engine**: Hard boundary checks ensuring all targets belong to your authorized scope map.
3. **Resolution**: Fast, concurrent dual-stack A/AAAA/CNAME lookups.
4. **Network Intelligence Pivot**: Extracts real-time ASN and Organization context. Detects CDNs automatically.
5. **Active Scanner**: Configurable multi-threaded TCP fingerprinting (Optional via confirmation prompt).
6. **Reporting & Scoring Engine**: Collates intelligence and risk heuristics into centralized DB and local files.

## 📦 Installation

Ensure you have **Go 1.22+** installed.

```bash
git clone https://github.com/veex0x01/CIDR.git
cd CIDR
go mod tidy
go build -o veex0x01-intel main.go
```

## 🚀 Usage

### Global Flags

```text
  -D, --domain string   Target domain (e.g., example.com)
  -S, --scope string    Path to scope configuration file (multi-domain lists)
  -M, --mode string     Scan mode: passive or active (default "passive")
  -d, --debug           Enable debug level logging
```

### Examples

**1. Basic Passive Scan (Safe)**

```bash
./veex0x01-intel scan --domain example.com --mode passive
```

**2. Multi-Target Subdomain List (File Ingestion)**
Create a file named `targets.txt` with one domain/IP per line:

```bash
./veex0x01-intel scan --scope targets.txt --mode passive
```

**3. Active Penetration Scan**
*Requires manual `YES` terminal confirmation. Will automatically bypass CDN (Cloudflare/AWS) IP blocks.*

```bash
./veex0x01-intel scan --scope targets.txt --mode active
```

---

## ⚙️ Configuration (`config.yaml`)

You can control the scanning and concurrency footprint by adjusting the local configuration file:

```yaml
performance:
  max_workers: 50         # Goroutine TCP Dial Limit
  timeout_seconds: 5      # Connection Timeout
  rate_limit_rps: 100

scope:
  strict_enforcement: true
  max_cidr_expansion: 22

scanning:
  top_ports:
    - 80
    - 443
    - 8080
    - 8443
```

---

## ⚖️ Mandatory Legal Safeguards

**This tool is strictly developed for authorized penetration testing.**
The author (`veex0x01`) is not responsible for any misuse, unauthorized profiling, or damages caused by executing active scans against infrastructure you do not own or possess explicit written consent to test.

By running `--mode active`, you take full operational and legal responsibility for the network packets dispatched.
