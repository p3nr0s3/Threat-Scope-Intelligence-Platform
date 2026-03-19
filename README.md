# 🛡️ ThreatScope — Unified Threat Intelligence Platform

A professional-grade Streamlit application for SOC analysts, threat hunters, and CISO teams.

## Features

| Module | Capability |
|--------|-----------|
| **IOC Check** | Single IOC analysis across 10+ intel sources |
| **Bulk IOC Check** | File upload or paste — batch process with rate limiting |
| **Mail Analysis** | Email, domain, header analysis with SPF/DKIM/DMARC |
| **IOC Hunting** | Shodan/ThreatFox/OTX hunting with ATT&CK mapping |
| **OSINT** | Multi-module pivot investigation |
| **Results & Export** | Filter, view, export to CSV |

## Integrated Sources

### Free (No Key Required)
- **URLhaus** (abuse.ch) — Malicious URL database
- **ThreatFox** (abuse.ch) — Malware IOC database
- **IPInfo** — IP geolocation
- **Google DNS** — DNS resolution
- **RDAP/WHOIS** — Domain registration

### Requires API Key
| Source | Use Case | Get Key |
|--------|----------|---------|
| VirusTotal | Hash/IP/URL/Domain | virustotal.com |
| AbuseIPDB | IP reputation | abuseipdb.com |
| Shodan | Network scanning & hunting | shodan.io |
| AlienVault OTX | Threat pulses & IOCs | otx.alienvault.com |
| GreyNoise | Noise vs signal IP | greynoise.io |
| Censys | Host/cert scanning | censys.io |
| Pulsedive | Risk scoring | pulsedive.com |
| IntelligenceX | OSINT data leaks | intelx.io |
| HaveIBeenPwned | Email breach check | haveibeenpwned.com |
| MXToolbox | Mail infra (optional) | mxtoolbox.com |

## Installation

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Usage

1. **Configure APIs** in the left sidebar (keys stored in session only, never persisted)
2. Use **IOC Check** tab for quick single-IOC analysis
3. Use **Bulk IOC Check** for CSV/txt file upload with batch processing
4. Use **Mail Analysis** to investigate phishing emails (paste header for full analysis)
5. Use **IOC Hunting** to pivot and hunt for related infrastructure
6. Use **OSINT** for full intelligence profile on a target
7. All results aggregate in **Results & Export** — filter and download as CSV

## MITRE ATT&CK Mappings

The platform maps hunting activities to:
- T1046 — Network Service Discovery
- T1595 — Active Scanning  
- T1590 — Gather Victim Network Info
- T1071 — C2 over HTTP/HTTPS
- T1566 — Phishing

## Security Note

> API keys are stored only in Streamlit session state. They are **never** written to disk, logged, or transmitted to any party other than the respective API endpoints.
