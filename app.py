import streamlit as st
import requests
import pandas as pd
import json
import time
import hashlib
import re
import base64
from datetime import datetime
from io import StringIO, BytesIO

# ─────────────────────────────────────────────────────────────
#  PAGE CONFIG
# ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="ThreatScope — Unified Threat Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────
#  CUSTOM CSS — Dark tactical aesthetic
# ─────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Rajdhani:wght@400;500;600;700&display=swap');

:root {
  --bg-primary:    #0a0d12;
  --bg-secondary:  #0f1318;
  --bg-card:       #141920;
  --bg-hover:      #1a2230;
  --accent-cyan:   #00d4ff;
  --accent-green:  #00ff88;
  --accent-red:    #ff3860;
  --accent-orange: #ff8c00;
  --accent-yellow: #ffd700;
  --text-primary:  #e2e8f0;
  --text-muted:    #64748b;
  --border:        #1e2d40;
}

html, body, [data-testid="stAppViewContainer"] {
  background-color: var(--bg-primary) !important;
  color: var(--text-primary) !important;
  font-family: 'Rajdhani', sans-serif !important;
}

[data-testid="stSidebar"] {
  background: var(--bg-secondary) !important;
  border-right: 1px solid var(--border) !important;
}

[data-testid="stSidebar"] * { color: var(--text-primary) !important; }

h1, h2, h3, h4 {
  font-family: 'Rajdhani', sans-serif !important;
  letter-spacing: 0.05em;
}

.stTextInput > div > div > input,
.stTextArea > div > div > textarea,
.stSelectbox > div > div > div {
  background: var(--bg-card) !important;
  border: 1px solid var(--border) !important;
  color: var(--text-primary) !important;
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 13px !important;
  border-radius: 6px !important;
}

.stTextInput > div > div > input:focus,
.stTextArea > div > div > textarea:focus {
  border-color: var(--accent-cyan) !important;
  box-shadow: 0 0 0 1px var(--accent-cyan) !important;
}

.stButton > button {
  background: linear-gradient(135deg, #0a2a4a 0%, #0f3460 100%) !important;
  color: var(--accent-cyan) !important;
  border: 1px solid var(--accent-cyan) !important;
  font-family: 'Rajdhani', sans-serif !important;
  font-weight: 600 !important;
  font-size: 14px !important;
  letter-spacing: 0.08em !important;
  border-radius: 6px !important;
  transition: all 0.2s ease !important;
}

.stButton > button:hover {
  background: var(--accent-cyan) !important;
  color: var(--bg-primary) !important;
  box-shadow: 0 0 12px rgba(0,212,255,0.4) !important;
}

.stTabs [data-baseweb="tab-list"] {
  background: var(--bg-secondary) !important;
  border-bottom: 1px solid var(--border) !important;
  gap: 4px !important;
}

.stTabs [data-baseweb="tab"] {
  background: transparent !important;
  color: var(--text-muted) !important;
  font-family: 'Rajdhani', sans-serif !important;
  font-weight: 600 !important;
  font-size: 14px !important;
  letter-spacing: 0.06em !important;
  border: none !important;
  padding: 10px 20px !important;
}

.stTabs [aria-selected="true"] {
  color: var(--accent-cyan) !important;
  border-bottom: 2px solid var(--accent-cyan) !important;
}

[data-testid="stExpander"] {
  background: var(--bg-card) !important;
  border: 1px solid var(--border) !important;
  border-radius: 8px !important;
}

.threat-badge-clean   { color: #00ff88; font-weight: 700; }
.threat-badge-malicious { color: #ff3860; font-weight: 700; }
.threat-badge-suspicious { color: #ff8c00; font-weight: 700; }
.threat-badge-unknown   { color: #94a3b8; font-weight: 700; }

.metric-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 16px 20px;
  text-align: center;
}

.metric-value {
  font-family: 'JetBrains Mono', monospace;
  font-size: 28px;
  font-weight: 700;
  color: var(--accent-cyan);
}

.metric-label {
  font-size: 12px;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-top: 4px;
}

.result-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px 18px;
  margin: 8px 0;
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
}

.result-card.malicious { border-left: 3px solid var(--accent-red); }
.result-card.clean     { border-left: 3px solid var(--accent-green); }
.result-card.suspicious { border-left: 3px solid var(--accent-orange); }
.result-card.unknown   { border-left: 3px solid var(--text-muted); }

.header-banner {
  background: linear-gradient(135deg, var(--bg-secondary) 0%, #0f1a2e 100%);
  border: 1px solid var(--border);
  border-bottom: 2px solid var(--accent-cyan);
  border-radius: 10px;
  padding: 20px 28px;
  margin-bottom: 24px;
  display: flex;
  align-items: center;
  gap: 16px;
}

.api-status-dot {
  display: inline-block;
  width: 8px; height: 8px;
  border-radius: 50%;
  margin-right: 6px;
}
.api-status-dot.active   { background: var(--accent-green); box-shadow: 0 0 6px var(--accent-green); }
.api-status-dot.inactive { background: var(--text-muted); }

div[data-testid="stDataFrame"] { border: 1px solid var(--border) !important; border-radius: 8px !important; }
[data-testid="stDataFrame"] th { background: var(--bg-secondary) !important; color: var(--accent-cyan) !important; font-family: 'Rajdhani', sans-serif !important; }
[data-testid="stDataFrame"] td { background: var(--bg-card) !important; color: var(--text-primary) !important; font-family: 'JetBrains Mono', monospace !important; font-size: 12px !important; }

.stAlert { background: var(--bg-card) !important; border: 1px solid var(--border) !important; }

div[data-testid="stSelectbox"] > div { background: var(--bg-card) !important; }

label { color: var(--text-primary) !important; font-family: 'Rajdhani', sans-serif !important; font-size: 14px !important; font-weight: 500 !important; }

.stProgress > div > div { background: var(--accent-cyan) !important; }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
#  SESSION STATE
# ─────────────────────────────────────────────────────────────
for key in ["results", "bulk_results", "mail_results", "osint_results", "hunt_results"]:
    if key not in st.session_state:
        st.session_state[key] = []

# ─────────────────────────────────────────────────────────────
#  HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────
def is_ip(value):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value.strip()))

def is_domain(value):
    return bool(re.match(r"^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$", value.strip()))

def is_hash(value):
    v = value.strip()
    if re.match(r"^[a-fA-F0-9]{32}$", v): return "md5"
    if re.match(r"^[a-fA-F0-9]{40}$", v): return "sha1"
    if re.match(r"^[a-fA-F0-9]{64}$", v): return "sha256"
    return None

def is_url(value):
    return value.strip().startswith("http://") or value.strip().startswith("https://")

def is_email(value):
    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", value.strip()))

def classify_ioc(value):
    if is_ip(value):      return "IP"
    if is_email(value):   return "Email"
    if is_url(value):     return "URL"
    if is_hash(value):    return "Hash"
    if is_domain(value):  return "Domain"
    return "Unknown"

def severity_color(verdict):
    v = str(verdict).lower()
    if "malicious" in v or "phishing" in v or "spam" in v: return "malicious"
    if "suspicious" in v or "warn" in v: return "suspicious"
    if "clean" in v or "harmless" in v or "safe" in v: return "clean"
    return "unknown"

def ts():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

# ─────────────────────────────────────────────────────────────
#  API INTEGRATIONS
# ─────────────────────────────────────────────────────────────

def vt_check(ioc, api_key):
    ioc = ioc.strip()
    headers = {"x-apikey": api_key}
    ioc_type = classify_ioc(ioc)
    try:
        if ioc_type == "IP":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
        elif ioc_type == "Domain":
            url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
        elif ioc_type in ("MD5","SHA1","SHA256","Hash"):
            url = f"https://www.virustotal.com/api/v3/files/{ioc}"
        elif ioc_type == "URL":
            ioc_b64 = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{ioc_b64}"
        else:
            url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            d = r.json().get("data", {}).get("attributes", {})
            stats = d.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0
            verdict = "Malicious" if malicious > 0 else ("Suspicious" if suspicious > 0 else "Clean")
            return {
                "source": "VirusTotal",
                "ioc": ioc,
                "type": ioc_type,
                "verdict": verdict,
                "malicious_engines": malicious,
                "suspicious_engines": suspicious,
                "total_engines": total,
                "country": d.get("country", "N/A"),
                "asn": d.get("asn", "N/A"),
                "tags": ", ".join(d.get("tags", [])),
                "timestamp": ts(),
                "raw": json.dumps(stats)
            }
        else:
            return {"source": "VirusTotal", "ioc": ioc, "type": ioc_type,
                    "verdict": f"Error {r.status_code}", "timestamp": ts(), "raw": r.text[:200]}
    except Exception as e:
        return {"source": "VirusTotal", "ioc": ioc, "type": ioc_type,
                "verdict": f"Exception: {str(e)}", "timestamp": ts(), "raw": ""}


def abuseipdb_check(ip, api_key):
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=15
        )
        if r.status_code == 200:
            d = r.json().get("data", {})
            score = d.get("abuseConfidenceScore", 0)
            verdict = "Malicious" if score >= 75 else ("Suspicious" if score >= 25 else "Clean")
            return {
                "source": "AbuseIPDB",
                "ioc": ip,
                "type": "IP",
                "verdict": verdict,
                "abuse_score": score,
                "total_reports": d.get("totalReports", 0),
                "country": d.get("countryCode", "N/A"),
                "isp": d.get("isp", "N/A"),
                "usage_type": d.get("usageType", "N/A"),
                "domain": d.get("domain", "N/A"),
                "is_tor": d.get("isTor", False),
                "timestamp": ts(),
                "raw": ""
            }
        return {"source": "AbuseIPDB", "ioc": ip, "verdict": f"Error {r.status_code}", "timestamp": ts()}
    except Exception as e:
        return {"source": "AbuseIPDB", "ioc": ip, "verdict": f"Exception: {str(e)}", "timestamp": ts()}


def shodan_check(query, api_key):
    try:
        if is_ip(query):
            r = requests.get(f"https://api.shodan.io/shodan/host/{query}?key={api_key}", timeout=15)
        else:
            r = requests.get("https://api.shodan.io/shodan/host/search",
                             params={"key": api_key, "query": query, "minify": True}, timeout=15)
        if r.status_code == 200:
            d = r.json()
            if is_ip(query):
                ports = d.get("ports", [])
                vulns = list(d.get("vulns", {}).keys())
                return {
                    "source": "Shodan",
                    "ioc": query,
                    "type": "IP",
                    "verdict": "Vulnerable" if vulns else "Active Host",
                    "open_ports": ", ".join(str(p) for p in ports[:10]),
                    "vulns": ", ".join(vulns[:5]),
                    "org": d.get("org", "N/A"),
                    "os": d.get("os", "N/A"),
                    "country": d.get("country_name", "N/A"),
                    "hostnames": ", ".join(d.get("hostnames", [])[:3]),
                    "timestamp": ts(),
                    "raw": json.dumps(ports)
                }
            else:
                total = d.get("total", 0)
                return {"source": "Shodan", "ioc": query, "type": "Query",
                        "verdict": f"{total} results", "timestamp": ts()}
        return {"source": "Shodan", "ioc": query, "verdict": f"Error {r.status_code}", "timestamp": ts()}
    except Exception as e:
        return {"source": "Shodan", "ioc": query, "verdict": f"Exception: {str(e)}", "timestamp": ts()}


def otx_check(ioc, api_key):
    ioc_type = classify_ioc(ioc)
    try:
        section_map = {"IP": "general", "Domain": "general", "URL": "general",
                       "Hash": "general", "Email": "general"}
        type_path = {"IP": "IPv4", "Domain": "domain", "URL": "url",
                     "Hash": "file", "Email": "hostname"}.get(ioc_type, "hostname")
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/{type_path}/{ioc}/general",
            headers={"X-OTX-API-KEY": api_key}, timeout=15
        )
        if r.status_code == 200:
            d = r.json()
            pulse_count = d.get("pulse_info", {}).get("count", 0)
            verdict = "Malicious" if pulse_count >= 3 else ("Suspicious" if pulse_count >= 1 else "Clean")
            return {
                "source": "AlienVault OTX",
                "ioc": ioc,
                "type": ioc_type,
                "verdict": verdict,
                "pulse_count": pulse_count,
                "reputation": d.get("reputation", 0),
                "country": d.get("country_name", "N/A"),
                "asn": d.get("asn", "N/A"),
                "timestamp": ts(),
                "raw": ""
            }
        return {"source": "AlienVault OTX", "ioc": ioc, "verdict": f"Error {r.status_code}", "timestamp": ts()}
    except Exception as e:
        return {"source": "AlienVault OTX", "ioc": ioc, "verdict": f"Exception: {str(e)}", "timestamp": ts()}


def urlhaus_check(url_or_domain):
    try:
        payload = {}
        if is_url(url_or_domain):
            payload = {"url": url_or_domain}
            endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
        else:
            payload = {"host": url_or_domain}
            endpoint = "https://urlhaus-api.abuse.ch/v1/host/"
        r = requests.post(endpoint, data=payload, timeout=15)
        if r.status_code == 200:
            d = r.json()
            status = d.get("query_status", "")
            urls = d.get("urls", [])
            verdict = "Malicious" if status in ("is_host", "is_listed") or len(urls) > 0 else "Clean"
            return {
                "source": "URLhaus",
                "ioc": url_or_domain,
                "type": classify_ioc(url_or_domain),
                "verdict": verdict,
                "status": status,
                "url_count": len(urls),
                "timestamp": ts(),
                "raw": ""
            }
        return {"source": "URLhaus", "ioc": url_or_domain, "verdict": f"Error {r.status_code}", "timestamp": ts()}
    except Exception as e:
        return {"source": "URLhaus", "ioc": url_or_domain, "verdict": f"Exception: {str(e)}", "timestamp": ts()}


def greynoise_check(ip, api_key):
    try:
        r = requests.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={"key": api_key}, timeout=15
        )
        if r.status_code == 200:
            d = r.json()
            noise = d.get("noise", False)
            riot = d.get("riot", False)
            classification = d.get("classification", "unknown")
            verdict = "Malicious" if classification == "malicious" else \
                      ("Benign" if riot or classification == "benign" else
                       ("Noisy" if noise else "Unknown"))
            return {
                "source": "GreyNoise",
                "ioc": ip,
                "type": "IP",
                "verdict": verdict,
                "classification": classification,
                "noise": noise,
                "riot": riot,
                "name": d.get("name", "N/A"),
                "timestamp": ts(),
                "raw": ""
            }
        return {"source": "GreyNoise", "ioc": ip, "verdict": f"Error {r.status_code}", "timestamp": ts()}
    except Exception as e:
        return {"source": "GreyNoise", "ioc": ip, "verdict": f"Exception: {str(e)}", "timestamp": ts()}


def threatfox_check(ioc):
    try:
        payload = json.dumps({"query": "search_ioc", "search_term": ioc})
        r = requests.post("https://threatfox-api.abuse.ch/api/v1/",
                          data=payload, timeout=15)
        if r.status_code == 200:
            d = r.json()
            query_status = d.get("query_status", "")
            iocs = d.get("data", [])
            verdict = "Malicious" if iocs else "Not Found"
            malware = iocs[0].get("malware", "N/A") if iocs else "N/A"
            return {
                "source": "ThreatFox",
                "ioc": ioc,
                "type": classify_ioc(ioc),
                "verdict": verdict,
                "malware_family": malware,
                "hits": len(iocs),
                "timestamp": ts(),
                "raw": ""
            }
        return {"source": "ThreatFox", "ioc": ioc, "verdict": f"Error {r.status_code}", "timestamp": ts()}
    except Exception as e:
        return {"source": "ThreatFox", "ioc": ioc, "verdict": f"Exception: {str(e)}", "timestamp": ts()}


def ipinfo_check(ip):
    """Free tier — no key needed"""
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        if r.status_code == 200:
            d = r.json()
            return {
                "source": "IPInfo",
                "ioc": ip,
                "type": "IP",
                "verdict": "Info",
                "org": d.get("org", "N/A"),
                "city": d.get("city", "N/A"),
                "region": d.get("region", "N/A"),
                "country": d.get("country", "N/A"),
                "timezone": d.get("timezone", "N/A"),
                "hostname": d.get("hostname", "N/A"),
                "timestamp": ts(),
                "raw": ""
            }
        return {"source": "IPInfo", "ioc": ip, "verdict": f"Error {r.status_code}", "timestamp": ts()}
    except Exception as e:
        return {"source": "IPInfo", "ioc": ip, "verdict": f"Exception: {str(e)}", "timestamp": ts()}


def mxtoolbox_check(domain, api_key=None):
    """Checks MX, SPF, DMARC via MXToolbox API"""
    try:
        headers = {}
        if api_key:
            headers["Authorization"] = api_key
        results = {}
        for check_type in ["mx", "spf", "dmarc", "blacklist"]:
            endpoint = f"https://api.mxtoolbox.com/api/v1/lookup/{check_type}/{domain}"
            r = requests.get(endpoint, headers=headers, timeout=15)
            if r.status_code == 200:
                d = r.json()
                failed = d.get("Failed", [])
                results[check_type] = "FAIL" if failed else "PASS"
            else:
                results[check_type] = f"Error {r.status_code}"
        verdict = "Issues Found" if any(v == "FAIL" for v in results.values()) else "Passed"
        return {
            "source": "MXToolbox",
            "ioc": domain,
            "type": "Domain",
            "verdict": verdict,
            "mx": results.get("mx", "N/A"),
            "spf": results.get("spf", "N/A"),
            "dmarc": results.get("dmarc", "N/A"),
            "blacklist": results.get("blacklist", "N/A"),
            "timestamp": ts(),
            "raw": ""
        }
    except Exception as e:
        return {"source": "MXToolbox", "ioc": domain, "verdict": f"Exception: {str(e)}", "timestamp": ts()}


def hibp_check(email, api_key):
    """Have I Been Pwned check for email"""
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers={"hibp-api-key": api_key, "User-Agent": "ThreatScope-Platform"},
            params={"truncateResponse": False},
            timeout=15
        )
        if r.status_code == 200:
            breaches = r.json()
            breach_names = [b.get("Name", "") for b in breaches]
            return {
                "source": "HaveIBeenPwned",
                "ioc": email,
                "type": "Email",
                "verdict": f"Breached ({len(breaches)} breaches)" if breaches else "Not Found",
                "breach_count": len(breaches),
                "breaches": ", ".join(breach_names[:5]),
                "timestamp": ts(),
                "raw": ""
            }
        elif r.status_code == 404:
            return {"source": "HaveIBeenPwned", "ioc": email, "type": "Email",
                    "verdict": "Not Found", "breach_count": 0, "breaches": "", "timestamp": ts()}
        return {"source": "HaveIBeenPwned", "ioc": email, "verdict": f"Error {r.status_code}", "timestamp": ts()}
    except Exception as e:
        return {"source": "HaveIBeenPwned", "ioc": email, "verdict": f"Exception: {str(e)}", "timestamp": ts()}


def censys_check(ip, api_id, api_secret):
    try:
        r = requests.get(
            f"https://search.censys.io/api/v2/hosts/{ip}",
            auth=(api_id, api_secret), timeout=15
        )
        if r.status_code == 200:
            d = r.json().get("result", {})
            svcs = d.get("services", [])
            ports = [str(s.get("port", "")) for s in svcs]
            return {
                "source": "Censys",
                "ioc": ip,
                "type": "IP",
                "verdict": "Active Host",
                "open_ports": ", ".join(ports[:10]),
                "autonomous_system": d.get("autonomous_system", {}).get("name", "N/A"),
                "country": d.get("location", {}).get("country", "N/A"),
                "labels": ", ".join(d.get("labels", [])),
                "timestamp": ts(),
                "raw": ""
            }
        return {"source": "Censys", "ioc": ip, "verdict": f"Error {r.status_code}", "timestamp": ts()}
    except Exception as e:
        return {"source": "Censys", "ioc": ip, "verdict": f"Exception: {str(e)}", "timestamp": ts()}


def pulsedive_check(ioc, api_key):
    try:
        r = requests.get(
            "https://pulsedive.com/api/info.php",
            params={"indicator": ioc, "pretty": 1, "key": api_key},
            timeout=15
        )
        if r.status_code == 200:
            d = r.json()
            risk = d.get("risk", "unknown")
            verdict = "Malicious" if risk in ("high", "critical") else \
                      ("Suspicious" if risk == "medium" else \
                       ("Clean" if risk in ("low", "none") else "Unknown"))
            return {
                "source": "Pulsedive",
                "ioc": ioc,
                "type": classify_ioc(ioc),
                "verdict": verdict,
                "risk": risk,
                "threats": ", ".join([t.get("name","") for t in d.get("threats",[])[:3]]),
                "feeds": ", ".join([f.get("name","") for f in d.get("feeds",[])[:3]]),
                "timestamp": ts(),
                "raw": ""
            }
        return {"source": "Pulsedive", "ioc": ioc, "verdict": f"Error {r.status_code}", "timestamp": ts()}
    except Exception as e:
        return {"source": "Pulsedive", "ioc": ioc, "verdict": f"Exception: {str(e)}", "timestamp": ts()}


def intelx_check(query, api_key):
    """IntelligenceX search"""
    try:
        # Search request
        r = requests.post(
            "https://2.intelx.io/intelligent/search",
            headers={"x-key": api_key, "Content-Type": "application/json"},
            json={"term": query, "maxresults": 20, "media": 0, "sort": 4, "terminate": []},
            timeout=15
        )
        if r.status_code == 200:
            search_id = r.json().get("id", "")
            # Fetch results
            time.sleep(2)
            r2 = requests.get(
                f"https://2.intelx.io/intelligent/search/result?id={search_id}&limit=10&offset=0",
                headers={"x-key": api_key}, timeout=15
            )
            if r2.status_code == 200:
                records = r2.json().get("records", [])
                return {
                    "source": "IntelligenceX",
                    "ioc": query,
                    "type": classify_ioc(query),
                    "verdict": f"{len(records)} Records Found" if records else "Not Found",
                    "record_count": len(records),
                    "timestamp": ts(),
                    "raw": ""
                }
        return {"source": "IntelligenceX", "ioc": query, "verdict": f"Error {r.status_code}", "timestamp": ts()}
    except Exception as e:
        return {"source": "IntelligenceX", "ioc": query, "verdict": f"Exception: {str(e)}", "timestamp": ts()}


def whois_lookup(domain):
    """Free WHOIS via rdap"""
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=15)
        if r.status_code == 200:
            d = r.json()
            events = {e.get("eventAction",""): e.get("eventDate","") for e in d.get("events",[])}
            nameservers = [ns.get("ldhName","") for ns in d.get("nameservers",[])]
            return {
                "source": "RDAP/WHOIS",
                "ioc": domain,
                "type": "Domain",
                "verdict": "Registered",
                "registered": events.get("registration", "N/A"),
                "expiry": events.get("expiration", "N/A"),
                "last_changed": events.get("last changed", "N/A"),
                "nameservers": ", ".join(nameservers[:4]),
                "status": ", ".join(d.get("status",[])),
                "timestamp": ts(),
                "raw": ""
            }
        return {"source": "RDAP/WHOIS", "ioc": domain, "verdict": f"Error {r.status_code}", "timestamp": ts()}
    except Exception as e:
        return {"source": "RDAP/WHOIS", "ioc": domain, "verdict": f"Exception: {str(e)}", "timestamp": ts()}


def dns_lookup(domain):
    """Free DNS lookup"""
    try:
        r = requests.get(f"https://dns.google/resolve?name={domain}&type=A", timeout=10)
        r2 = requests.get(f"https://dns.google/resolve?name={domain}&type=MX", timeout=10)
        r3 = requests.get(f"https://dns.google/resolve?name={domain}&type=TXT", timeout=10)
        a_records = [a.get("data","") for a in r.json().get("Answer",[])] if r.status_code==200 else []
        mx_records = [m.get("data","") for m in r2.json().get("Answer",[])] if r2.status_code==200 else []
        txt_records = [t.get("data","") for t in r3.json().get("Answer",[])] if r3.status_code==200 else []
        spf = next((t for t in txt_records if "v=spf1" in t.lower()), "Not Found")
        dmarc_r = requests.get(f"https://dns.google/resolve?name=_dmarc.{domain}&type=TXT", timeout=10)
        dmarc_records = [t.get("data","") for t in dmarc_r.json().get("Answer",[])] if dmarc_r.status_code==200 else []
        dmarc = dmarc_records[0] if dmarc_records else "Not Found"
        return {
            "source": "DNS Lookup",
            "ioc": domain,
            "type": "Domain",
            "verdict": "Resolved" if a_records else "No A Record",
            "a_records": ", ".join(a_records[:5]),
            "mx_records": ", ".join(mx_records[:3]),
            "spf": spf[:80] if len(spf) > 80 else spf,
            "dmarc": dmarc[:80] if len(dmarc) > 80 else dmarc,
            "timestamp": ts(),
            "raw": ""
        }
    except Exception as e:
        return {"source": "DNS Lookup", "ioc": domain, "verdict": f"Exception: {str(e)}", "timestamp": ts()}


# ─────────────────────────────────────────────────────────────
#  SIDEBAR — API KEY CONFIGURATION
# ─────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style='text-align:center; padding: 10px 0 20px 0;'>
      <div style='font-family: Rajdhani, sans-serif; font-size: 22px; font-weight: 700; color: #00d4ff; letter-spacing: 0.1em;'>
        🛡️ THREATSCOPE
      </div>
      <div style='font-size: 11px; color: #64748b; letter-spacing: 0.15em; margin-top: 4px;'>
        UNIFIED THREAT INTELLIGENCE
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### ⚙️ API Configuration")

    with st.expander("🔬 VirusTotal", expanded=False):
        vt_key = st.text_input("API Key", key="vt_key", type="password", placeholder="VT API key...")

    with st.expander("🚨 AbuseIPDB", expanded=False):
        abuse_key = st.text_input("API Key", key="abuse_key", type="password", placeholder="AbuseIPDB key...")

    with st.expander("🔍 Shodan", expanded=False):
        shodan_key = st.text_input("API Key", key="shodan_key", type="password", placeholder="Shodan API key...")

    with st.expander("👽 AlienVault OTX", expanded=False):
        otx_key = st.text_input("API Key", key="otx_key", type="password", placeholder="OTX key...")

    with st.expander("🌫️ GreyNoise", expanded=False):
        gn_key = st.text_input("API Key", key="gn_key", type="password", placeholder="GreyNoise key...")

    with st.expander("📡 Censys", expanded=False):
        censys_id = st.text_input("API ID", key="censys_id", type="password")
        censys_secret = st.text_input("API Secret", key="censys_secret", type="password")

    with st.expander("💉 Pulsedive", expanded=False):
        pd_key = st.text_input("API Key", key="pd_key", type="password", placeholder="Pulsedive key...")

    with st.expander("🧠 IntelligenceX", expanded=False):
        intelx_key = st.text_input("API Key", key="intelx_key", type="password", placeholder="IntelX key...")

    with st.expander("📧 HaveIBeenPwned", expanded=False):
        hibp_key = st.text_input("API Key", key="hibp_key", type="password", placeholder="HIBP key...")

    with st.expander("📨 MXToolbox", expanded=False):
        mxtb_key = st.text_input("API Key (optional)", key="mxtb_key", type="password", placeholder="Optional...")

    st.markdown("---")
    st.markdown("""
    <div style='font-size:11px; color:#475569; padding:8px 0;'>
      <span style='color:#00d4ff;'>FREE</span> — URLhaus, ThreatFox, IPInfo, DNS, RDAP<br>
      <span style='color:#ffd700;'>API KEY</span> — All other integrations<br><br>
      Keys stored in session only. Not persisted.
    </div>
    """, unsafe_allow_html=True)

    # Active APIs summary
    active = []
    if st.session_state.get("vt_key"):    active.append("VT")
    if st.session_state.get("abuse_key"): active.append("AIPDB")
    if st.session_state.get("shodan_key"):active.append("Shodan")
    if st.session_state.get("otx_key"):   active.append("OTX")
    if st.session_state.get("gn_key"):    active.append("GN")
    if st.session_state.get("pd_key"):    active.append("PD")

    if active:
        st.markdown(f"""
        <div style='background:#0f1318; border:1px solid #1e2d40; border-radius:6px; padding:10px; margin-top:8px;'>
          <div style='font-size:11px; color:#00ff88; font-weight:600; margin-bottom:6px;'>● ACTIVE INTEGRATIONS</div>
          <div style='font-size:11px; color:#94a3b8;'>{' · '.join(active)}</div>
        </div>
        """, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
#  HEADER
# ─────────────────────────────────────────────────────────────
st.markdown("""
<div class='header-banner'>
  <div>
    <div style='font-size:28px; font-weight:700; color:#e2e8f0; letter-spacing:0.05em;'>
      🛡️ ThreatScope Intelligence Platform
    </div>
    <div style='font-size:14px; color:#64748b; margin-top:4px; font-family: JetBrains Mono, monospace;'>
      IOC Checking · IOC Hunting · Mail Analysis · Threat Intelligence · OSINT
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
#  MAIN TABS
# ─────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "🔍 IOC Check",
    "🎯 Bulk IOC Check",
    "📧 Mail Analysis",
    "🕵️ IOC Hunting",
    "🌐 OSINT",
    "📊 Results & Export"
])

# ════════════════════════════════════════════════════════════════
#  TAB 1 — SINGLE IOC CHECK
# ════════════════════════════════════════════════════════════════
with tab1:
    st.markdown("### Single IOC Analysis")
    st.markdown("<div style='font-size:13px;color:#64748b;margin-bottom:16px;'>Analyze a single IOC across multiple threat intelligence sources simultaneously.</div>", unsafe_allow_html=True)

    col1, col2 = st.columns([3,1])
    with col1:
        ioc_input = st.text_input(
            "Enter IOC (IP, Domain, URL, Hash, Email)",
            placeholder="e.g. 1.2.3.4  |  evil.com  |  https://...  |  abc123...  |  user@domain.com"
        )
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        auto_detect = st.checkbox("Auto-detect type", value=True)

    if ioc_input:
        ioc_type_detected = classify_ioc(ioc_input.strip())
        st.markdown(f"""
        <div style='background:#0f1318;border:1px solid #1e2d40;border-radius:6px;padding:10px 16px;margin-bottom:12px;font-family:JetBrains Mono,monospace;font-size:13px;'>
          <span style='color:#64748b;'>Detected Type:</span>
          <span style='color:#00d4ff;font-weight:600;'> {ioc_type_detected}</span>
          <span style='color:#64748b;margin-left:20px;'>IOC:</span>
          <span style='color:#e2e8f0;'> {ioc_input.strip()}</span>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("**Select Intelligence Sources:**")
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        use_vt      = st.checkbox("VirusTotal",    value=True,  key="ioc_vt")
        use_otx     = st.checkbox("AlienVault OTX", value=True, key="ioc_otx")
    with c2:
        use_abuse   = st.checkbox("AbuseIPDB",     value=True,  key="ioc_abuse")
        use_urlhaus = st.checkbox("URLhaus",        value=True,  key="ioc_urlhaus")
    with c3:
        use_shodan  = st.checkbox("Shodan",         value=False, key="ioc_shodan")
        use_threatfox = st.checkbox("ThreatFox",   value=True,  key="ioc_threatfox")
    with c4:
        use_gn      = st.checkbox("GreyNoise",      value=False, key="ioc_gn")
        use_ipinfo  = st.checkbox("IPInfo (free)",  value=True,  key="ioc_ipinfo")
    with c5:
        use_pd      = st.checkbox("Pulsedive",      value=False, key="ioc_pd")
        use_censys  = st.checkbox("Censys",         value=False, key="ioc_censys")

    col_btn1, col_btn2 = st.columns([1,4])
    with col_btn1:
        analyze_btn = st.button("⚡ ANALYZE IOC", use_container_width=True, key="btn_analyze_ioc")

    if analyze_btn and ioc_input:
        ioc = ioc_input.strip()
        ioc_type = classify_ioc(ioc)
        results = []

        progress = st.progress(0)
        status_txt = st.empty()
        checks = []

        if use_vt and st.session_state.get("vt_key"):       checks.append(("VirusTotal", lambda: vt_check(ioc, st.session_state.vt_key)))
        if use_abuse and st.session_state.get("abuse_key") and ioc_type=="IP": checks.append(("AbuseIPDB", lambda: abuseipdb_check(ioc, st.session_state.abuse_key)))
        if use_shodan and st.session_state.get("shodan_key"): checks.append(("Shodan", lambda: shodan_check(ioc, st.session_state.shodan_key)))
        if use_otx and st.session_state.get("otx_key"):     checks.append(("OTX", lambda: otx_check(ioc, st.session_state.otx_key)))
        if use_urlhaus:                                       checks.append(("URLhaus", lambda: urlhaus_check(ioc)))
        if use_gn and st.session_state.get("gn_key") and ioc_type=="IP": checks.append(("GreyNoise", lambda: greynoise_check(ioc, st.session_state.gn_key)))
        if use_threatfox:                                     checks.append(("ThreatFox", lambda: threatfox_check(ioc)))
        if use_ipinfo and ioc_type=="IP":                     checks.append(("IPInfo", lambda: ipinfo_check(ioc)))
        if use_pd and st.session_state.get("pd_key"):        checks.append(("Pulsedive", lambda: pulsedive_check(ioc, st.session_state.pd_key)))
        if use_censys and st.session_state.get("censys_id"): checks.append(("Censys", lambda: censys_check(ioc, st.session_state.censys_id, st.session_state.censys_secret)))

        if not checks:
            st.warning("⚠️ No sources selected or API keys not configured. URLhaus, ThreatFox, and IPInfo are free and require no keys.")
        else:
            for i, (name, fn) in enumerate(checks):
                status_txt.markdown(f"<span style='font-family:JetBrains Mono,monospace;font-size:13px;color:#00d4ff;'>Querying {name}...</span>", unsafe_allow_html=True)
                result = fn()
                results.append(result)
                progress.progress((i+1) / len(checks))
                time.sleep(0.3)

            status_txt.empty()
            progress.empty()

            # Store results
            for r in results:
                r["session_ioc"] = ioc
            st.session_state.results.extend(results)

            # Summary row
            malicious_count = sum(1 for r in results if "malicious" in str(r.get("verdict","")).lower())
            suspicious_count = sum(1 for r in results if "suspicious" in str(r.get("verdict","")).lower())
            clean_count = sum(1 for r in results if any(x in str(r.get("verdict","")).lower() for x in ["clean","safe","harmless","not found","benign"]))

            st.markdown("<br>", unsafe_allow_html=True)
            m1, m2, m3, m4 = st.columns(4)
            with m1:
                st.markdown(f"""<div class='metric-card'><div class='metric-value' style='color:#ff3860;'>{malicious_count}</div><div class='metric-label'>Malicious Flags</div></div>""", unsafe_allow_html=True)
            with m2:
                st.markdown(f"""<div class='metric-card'><div class='metric-value' style='color:#ff8c00;'>{suspicious_count}</div><div class='metric-label'>Suspicious Flags</div></div>""", unsafe_allow_html=True)
            with m3:
                st.markdown(f"""<div class='metric-card'><div class='metric-value' style='color:#00ff88;'>{clean_count}</div><div class='metric-label'>Clean/Safe</div></div>""", unsafe_allow_html=True)
            with m4:
                st.markdown(f"""<div class='metric-card'><div class='metric-value'>{len(results)}</div><div class='metric-label'>Sources Queried</div></div>""", unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)
            for r in results:
                verdict = r.get("verdict", "Unknown")
                sev = severity_color(verdict)
                color_map = {"malicious": "#ff3860", "suspicious": "#ff8c00", "clean": "#00ff88", "unknown": "#64748b"}
                color = color_map.get(sev, "#64748b")
                details = " | ".join(f"{k}: <span style='color:#e2e8f0;'>{v}</span>"
                                     for k, v in r.items()
                                     if k not in ("source","ioc","type","verdict","timestamp","raw","session_ioc") and v and v != "N/A")
                st.markdown(f"""
                <div class='result-card {sev}'>
                  <div style='display:flex;justify-content:space-between;align-items:center;'>
                    <span style='color:#00d4ff;font-weight:600;font-size:14px;'>{r.get("source","")}</span>
                    <span style='color:{color};font-weight:700;font-size:14px;'>{verdict}</span>
                  </div>
                  <div style='color:#64748b;margin-top:6px;font-size:11px;line-height:1.8;'>{details}</div>
                </div>
                """, unsafe_allow_html=True)

    elif analyze_btn and not ioc_input:
        st.error("Please enter an IOC value to analyze.")


# ════════════════════════════════════════════════════════════════
#  TAB 2 — BULK IOC CHECK
# ════════════════════════════════════════════════════════════════
with tab2:
    st.markdown("### Bulk IOC Analysis")
    st.markdown("<div style='font-size:13px;color:#64748b;margin-bottom:16px;'>Upload a file or paste multiple IOCs for batch processing across selected intelligence sources.</div>", unsafe_allow_html=True)

    col_in1, col_in2 = st.columns([2,1])
    with col_in1:
        bulk_text = st.text_area(
            "Paste IOCs (one per line)",
            height=200,
            placeholder="1.2.3.4\nevil-domain.com\nhttps://malware-url.com/payload\nabc123def456...\nuser@phishing.com"
        )
    with col_in2:
        uploaded_file = st.file_uploader("Or upload .txt / .csv", type=["txt","csv"])
        st.markdown("<br>", unsafe_allow_html=True)
        delay_seconds = st.slider("Delay between requests (s)", 0.0, 3.0, 0.5, 0.1,
                                   help="Avoid API rate limiting")
        bulk_vt    = st.checkbox("VirusTotal",     value=True,  key="bulk_vt")
        bulk_abuse = st.checkbox("AbuseIPDB",      value=True,  key="bulk_abuse")
        bulk_otx   = st.checkbox("OTX",            value=True,  key="bulk_otx")
        bulk_tf    = st.checkbox("ThreatFox",      value=True,  key="bulk_tf")
        bulk_uh    = st.checkbox("URLhaus",        value=True,  key="bulk_uh")
        bulk_gn    = st.checkbox("GreyNoise",      value=False, key="bulk_gn")
        bulk_pd    = st.checkbox("Pulsedive",      value=False, key="bulk_pd")

    ioc_list = []
    if uploaded_file:
        content = uploaded_file.read().decode("utf-8", errors="ignore")
        ioc_list = [line.strip() for line in content.splitlines() if line.strip()]
    elif bulk_text:
        ioc_list = [line.strip() for line in bulk_text.splitlines() if line.strip()]

    if ioc_list:
        st.markdown(f"""
        <div style='background:#0f1318;border:1px solid #1e2d40;border-radius:6px;padding:10px 16px;margin-bottom:12px;font-family:JetBrains Mono,monospace;font-size:13px;'>
          <span style='color:#64748b;'>Loaded:</span>
          <span style='color:#00d4ff;font-weight:600;'> {len(ioc_list)} IOCs</span>
          <span style='color:#64748b;margin-left:20px;'>Types:</span>
          <span style='color:#e2e8f0;'> {", ".join(set(classify_ioc(i) for i in ioc_list))}</span>
        </div>
        """, unsafe_allow_html=True)

    col_b1, col_b2 = st.columns([1,4])
    with col_b1:
        bulk_btn = st.button("⚡ RUN BULK CHECK", use_container_width=True, key="btn_bulk_check")

    if bulk_btn and ioc_list:
        all_results = []
        prog = st.progress(0)
        status_placeholder = st.empty()
        table_placeholder = st.empty()

        for idx, ioc in enumerate(ioc_list):
            ioc = ioc.strip()
            if not ioc:
                continue
            ioc_type = classify_ioc(ioc)
            status_placeholder.markdown(
                f"<span style='font-family:JetBrains Mono,monospace;font-size:13px;color:#00d4ff;'>[{idx+1}/{len(ioc_list)}] Checking: {ioc}</span>",
                unsafe_allow_html=True
            )

            row_results = []
            if bulk_vt and st.session_state.get("vt_key"):
                row_results.append(vt_check(ioc, st.session_state.vt_key))
                time.sleep(delay_seconds)
            if bulk_abuse and st.session_state.get("abuse_key") and ioc_type=="IP":
                row_results.append(abuseipdb_check(ioc, st.session_state.abuse_key))
                time.sleep(delay_seconds)
            if bulk_otx and st.session_state.get("otx_key"):
                row_results.append(otx_check(ioc, st.session_state.otx_key))
                time.sleep(delay_seconds)
            if bulk_tf:
                row_results.append(threatfox_check(ioc))
                time.sleep(delay_seconds)
            if bulk_uh:
                row_results.append(urlhaus_check(ioc))
                time.sleep(delay_seconds)
            if bulk_gn and st.session_state.get("gn_key") and ioc_type=="IP":
                row_results.append(greynoise_check(ioc, st.session_state.gn_key))
                time.sleep(delay_seconds)
            if bulk_pd and st.session_state.get("pd_key"):
                row_results.append(pulsedive_check(ioc, st.session_state.pd_key))
                time.sleep(delay_seconds)

            if not row_results:
                row_results.append(urlhaus_check(ioc))
                row_results.append(threatfox_check(ioc))

            for r in row_results:
                r["session_ioc"] = ioc
                all_results.append(r)

            prog.progress((idx+1)/len(ioc_list))

            # Update live table
            if all_results:
                df_preview = pd.DataFrame(all_results)[["ioc","type","source","verdict","timestamp"]].tail(20)
                table_placeholder.dataframe(df_preview, use_container_width=True, hide_index=True)

        status_placeholder.empty()
        prog.empty()

        st.session_state.bulk_results = all_results
        st.success(f"✅ Bulk check complete — {len(all_results)} results from {len(ioc_list)} IOCs.")

        df_final = pd.DataFrame(all_results)
        col_map = {c:c for c in df_final.columns if c != "raw"}
        df_display = df_final[[c for c in col_map if c in df_final.columns]].drop(columns=["raw","session_ioc"], errors="ignore")
        st.dataframe(df_display, use_container_width=True, hide_index=True)

        csv = df_display.to_csv(index=False)
        st.download_button(
            "⬇️ Export Bulk Results as CSV",
            csv,
            f"threatscope_bulk_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv",
            "text/csv",
            use_container_width=False
        )

    elif bulk_btn and not ioc_list:
        st.error("Please input IOCs via text or file upload.")


# ════════════════════════════════════════════════════════════════
#  TAB 3 — MAIL ANALYSIS
# ════════════════════════════════════════════════════════════════
with tab3:
    st.markdown("### Email & Mail Infrastructure Analysis")
    st.markdown("<div style='font-size:13px;color:#64748b;margin-bottom:16px;'>Analyze email addresses, domains, and mail headers for phishing indicators, spoofing, and compromise.</div>", unsafe_allow_html=True)

    mail_mode = st.radio("Analysis Mode:", ["Email Address", "Mail Domain", "Email Header Analysis"], horizontal=True)

    if mail_mode == "Email Address":
        col_m1, col_m2 = st.columns([3,1])
        with col_m1:
            email_input = st.text_input("Email Address", placeholder="user@domain.com")
        with col_m2:
            st.markdown("<br>", unsafe_allow_html=True)
            check_hibp   = st.checkbox("HaveIBeenPwned", value=True,  key="mail_hibp")
            check_vt_mail = st.checkbox("VirusTotal",    value=True,  key="mail_vt")
            check_otx_mail = st.checkbox("OTX",         value=True,  key="mail_otx")
            check_tf_mail = st.checkbox("ThreatFox",    value=True,  key="mail_tf")

        if st.button("🔍 ANALYZE EMAIL", use_container_width=False, key="btn_analyze_email"):
            if email_input:
                results = []
                with st.spinner("Analyzing email..."):
                    if check_hibp and st.session_state.get("hibp_key"):
                        results.append(hibp_check(email_input, st.session_state.hibp_key))
                    if check_vt_mail and st.session_state.get("vt_key"):
                        # Check domain part
                        domain_part = email_input.split("@")[-1]
                        r = vt_check(domain_part, st.session_state.vt_key)
                        r["ioc"] = f"{email_input} (domain)"
                        results.append(r)
                    if check_otx_mail and st.session_state.get("otx_key"):
                        domain_part = email_input.split("@")[-1]
                        results.append(otx_check(domain_part, st.session_state.otx_key))
                    if check_tf_mail:
                        results.append(threatfox_check(email_input))
                    # Always do DNS
                    domain_part = email_input.split("@")[-1]
                    results.append(dns_lookup(domain_part))
                    results.append(whois_lookup(domain_part))

                st.session_state.mail_results.extend(results)
                for r in results:
                    verdict = r.get("verdict","Unknown")
                    sev = severity_color(verdict)
                    color_map = {"malicious":"#ff3860","suspicious":"#ff8c00","clean":"#00ff88","unknown":"#64748b"}
                    color = color_map.get(sev,"#64748b")
                    details = " | ".join(f"{k}: <span style='color:#e2e8f0;'>{v}</span>"
                                        for k,v in r.items()
                                        if k not in ("source","ioc","type","verdict","timestamp","raw","session_ioc") and v and v != "N/A")
                    st.markdown(f"""
                    <div class='result-card {sev}'>
                      <div style='display:flex;justify-content:space-between;align-items:center;'>
                        <span style='color:#00d4ff;font-weight:600;font-size:14px;'>{r.get("source","")}</span>
                        <span style='color:{color};font-weight:700;font-size:14px;'>{verdict}</span>
                      </div>
                      <div style='color:#64748b;margin-top:6px;font-size:11px;line-height:1.8;'>{details}</div>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.error("Please enter an email address.")

    elif mail_mode == "Mail Domain":
        col_md1, col_md2 = st.columns([3,1])
        with col_md1:
            mail_domain = st.text_input("Mail Domain", placeholder="example.com")
        with col_md2:
            st.markdown("<br>", unsafe_allow_html=True)
            check_dns   = st.checkbox("DNS Records", value=True, key="md_dns")
            check_whois = st.checkbox("WHOIS/RDAP",  value=True, key="md_whois")
            check_mxtb  = st.checkbox("MXToolbox",   value=False, key="md_mxtb")
            check_vt_dom = st.checkbox("VirusTotal", value=True, key="md_vt")
            check_bl    = st.checkbox("URLhaus",     value=True, key="md_bl")

        if st.button("🔍 ANALYZE DOMAIN", use_container_width=False, key="btn_analyze_domain"):
            if mail_domain:
                results = []
                with st.spinner("Analyzing domain..."):
                    if check_dns:   results.append(dns_lookup(mail_domain))
                    if check_whois: results.append(whois_lookup(mail_domain))
                    if check_mxtb:  results.append(mxtoolbox_check(mail_domain, st.session_state.get("mxtb_key","")))
                    if check_vt_dom and st.session_state.get("vt_key"): results.append(vt_check(mail_domain, st.session_state.vt_key))
                    if check_bl: results.append(urlhaus_check(mail_domain))

                st.session_state.mail_results.extend(results)
                for r in results:
                    verdict = r.get("verdict","Unknown")
                    sev = severity_color(verdict)
                    color_map = {"malicious":"#ff3860","suspicious":"#ff8c00","clean":"#00ff88","unknown":"#64748b"}
                    color = color_map.get(sev,"#64748b")
                    details = " | ".join(f"{k}: <span style='color:#e2e8f0;'>{v}</span>"
                                        for k,v in r.items()
                                        if k not in ("source","ioc","type","verdict","timestamp","raw","session_ioc") and v and v!="N/A")
                    st.markdown(f"""
                    <div class='result-card {sev}'>
                      <div style='display:flex;justify-content:space-between;'>
                        <span style='color:#00d4ff;font-weight:600;font-size:14px;'>{r.get("source","")}</span>
                        <span style='color:{color};font-weight:700;font-size:14px;'>{verdict}</span>
                      </div>
                      <div style='color:#64748b;margin-top:6px;font-size:11px;line-height:1.8;'>{details}</div>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.error("Please enter a domain.")

    else:  # Email Header Analysis
        header_input = st.text_area("Paste Full Email Header", height=300,
                                     placeholder="Received: from mail.evil.com (1.2.3.4) by...\nX-Originating-IP: ...\nX-Mailer: ...")

        if st.button("🔍 ANALYZE HEADER", use_container_width=False, key="btn_analyze_header"):
            if header_input:
                # Extract IPs from header
                ips_found = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', header_input)
                domains_found = re.findall(r'from\s+([\w\.\-]+)', header_input)
                spf_result = re.search(r'spf=(pass|fail|neutral|softfail|none)', header_input, re.IGNORECASE)
                dkim_result = re.search(r'dkim=(pass|fail|neutral)', header_input, re.IGNORECASE)
                dmarc_result = re.search(r'dmarc=(pass|fail|bestguesspass)', header_input, re.IGNORECASE)

                st.markdown("#### 📋 Header Extraction Results")
                col_h1, col_h2, col_h3 = st.columns(3)
                with col_h1:
                    spf_val = spf_result.group(1).upper() if spf_result else "NOT FOUND"
                    spf_col = "#00ff88" if spf_val == "PASS" else "#ff3860"
                    st.markdown(f"""<div class='metric-card'><div class='metric-value' style='color:{spf_col};'>{spf_val}</div><div class='metric-label'>SPF Result</div></div>""", unsafe_allow_html=True)
                with col_h2:
                    dkim_val = dkim_result.group(1).upper() if dkim_result else "NOT FOUND"
                    dkim_col = "#00ff88" if dkim_val == "PASS" else "#ff3860"
                    st.markdown(f"""<div class='metric-card'><div class='metric-value' style='color:{dkim_col};'>{dkim_val}</div><div class='metric-label'>DKIM Result</div></div>""", unsafe_allow_html=True)
                with col_h3:
                    dmarc_val = dmarc_result.group(1).upper() if dmarc_result else "NOT FOUND"
                    dmarc_col = "#00ff88" if dmarc_val == "PASS" else "#ff3860"
                    st.markdown(f"""<div class='metric-card'><div class='metric-value' style='color:{dmarc_col};'>{dmarc_val}</div><div class='metric-label'>DMARC Result</div></div>""", unsafe_allow_html=True)

                unique_ips = list(set(ips_found))
                st.markdown(f"<br>**IPs Found in Header ({len(unique_ips)}):** `{'` · `'.join(unique_ips[:10])}`", unsafe_allow_html=True)
                unique_domains = list(set(d for d in domains_found if "." in d))[:5]
                if unique_domains:
                    st.markdown(f"**Domains Found:** `{'` · `'.join(unique_domains)}`", unsafe_allow_html=True)

                if unique_ips and st.session_state.get("vt_key"):
                    st.markdown("<br>**Running IOC checks on extracted IPs...**")
                    header_results = []
                    for ip in unique_ips[:5]:
                        if is_ip(ip) and not ip.startswith(("192.168","10.","172.","127.")):
                            r = vt_check(ip, st.session_state.vt_key)
                            r["context"] = "email-header"
                            header_results.append(r)
                            time.sleep(0.5)
                    st.session_state.mail_results.extend(header_results)
                    if header_results:
                        df_h = pd.DataFrame(header_results)[["ioc","verdict","country","timestamp"]]
                        st.dataframe(df_h, use_container_width=True, hide_index=True)
            else:
                st.error("Please paste email header content.")


# ════════════════════════════════════════════════════════════════
#  TAB 4 — IOC HUNTING
# ════════════════════════════════════════════════════════════════
with tab4:
    st.markdown("### IOC Hunting & Threat Hunting")
    st.markdown("<div style='font-size:13px;color:#64748b;margin-bottom:16px;'>Hunt for related IOCs, pivot across threat intelligence platforms, and map to MITRE ATT&CK.</div>", unsafe_allow_html=True)

    hunt_mode = st.selectbox("Hunt Mode", [
        "Network Scan Hunt (Shodan/Censys)",
        "Malware Family Hunt (ThreatFox)",
        "OSINT Pivot (OTX Pulses)",
        "Passive DNS Hunt",
        "ASN / CIDR Hunt (Shodan)"
    ])

    if hunt_mode == "Network Scan Hunt (Shodan/Censys)":
        st.markdown("**Hunt for exposed services, default credentials, and infrastructure.**")
        col_h1, col_h2 = st.columns(2)
        with col_h1:
            hunt_query = st.text_input("Shodan Search Query", placeholder='port:22 country:ID org:"Telkom"')
            shodan_facets = st.multiselect("Facets", ["country","org","port","os","asn"], default=["country","org"])
        with col_h2:
            hunt_limit = st.slider("Max Results", 10, 100, 20)
            st.markdown("**MITRE ATT&CK Mapping:**")
            st.markdown("""
            <div style='font-size:12px;font-family:JetBrains Mono,monospace;color:#64748b;line-height:1.8;'>
              T1046 — Network Service Discovery<br>
              T1595 — Active Scanning<br>
              T1590 — Gather Victim Network Info
            </div>
            """, unsafe_allow_html=True)

        if st.button("🎯 HUNT NOW", key="hunt_shodan"):
            if hunt_query and st.session_state.get("shodan_key"):
                with st.spinner("Hunting on Shodan..."):
                    r = shodan_check(hunt_query, st.session_state.shodan_key)
                    st.session_state.hunt_results.append(r)
                    st.markdown(f"""
                    <div class='result-card unknown'>
                      <span style='color:#00d4ff;'>Shodan Query:</span>
                      <span style='color:#e2e8f0;'> {hunt_query}</span><br>
                      <span style='color:#64748b;font-size:12px;'>Result: {r.get("verdict","")}</span>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.warning("Shodan API key required. Configure in sidebar.")

    elif hunt_mode == "Malware Family Hunt (ThreatFox)":
        st.markdown("**Hunt IOCs associated with specific malware families.**")
        malware_families = [
            "Cobalt Strike", "Emotet", "Qakbot", "Raccoon Stealer", "RedLine",
            "AsyncRAT", "Agent Tesla", "NjRAT", "Formbook", "IcedID",
            "Metasploit", "Sliver", "Havoc C2", "BumbleBee", "GootLoader"
        ]
        mf_col1, mf_col2 = st.columns(2)
        with mf_col1:
            selected_family = st.selectbox("Malware Family", malware_families)
            custom_family = st.text_input("Or enter custom family name", placeholder="e.g. BlackCat")
        with mf_col2:
            st.markdown(f"""
            <div style='background:#0f1318;border:1px solid #1e2d40;border-radius:8px;padding:14px;font-size:12px;font-family:JetBrains Mono,monospace;'>
              <div style='color:#ff8c00;font-weight:600;margin-bottom:8px;'>📍 MITRE ATT&CK TTPs</div>
              <div style='color:#64748b;line-height:1.8;'>
                T1071 — C2 over HTTP/HTTPS<br>
                T1055 — Process Injection<br>
                T1105 — Ingress Tool Transfer<br>
                T1566 — Phishing Initial Access<br>
                T1059 — Command Interpreter
              </div>
            </div>
            """, unsafe_allow_html=True)

        if st.button("🎯 HUNT MALWARE FAMILY", key="hunt_malware"):
            family = custom_family if custom_family else selected_family
            with st.spinner(f"Hunting IOCs for {family}..."):
                try:
                    payload = json.dumps({"query": "taginfo", "tag": family})
                    r = requests.post("https://threatfox-api.abuse.ch/api/v1/", data=payload, timeout=15)
                    if r.status_code == 200:
                        d = r.json()
                        iocs_data = d.get("data", [])
                        if iocs_data:
                            df_hunt = pd.DataFrame(iocs_data[:50])
                            cols = [c for c in ["ioc", "ioc_type", "malware", "confidence_level", "first_seen", "tags"] if c in df_hunt.columns]
                            st.dataframe(df_hunt[cols], use_container_width=True, hide_index=True)
                            st.session_state.hunt_results.extend(
                                [{"source":"ThreatFox-Hunt","ioc":i.get("ioc",""),"verdict":i.get("malware",""),
                                  "type":i.get("ioc_type",""),"timestamp":ts()} for i in iocs_data[:50]]
                            )
                            csv = df_hunt[cols].to_csv(index=False)
                            st.download_button("⬇️ Export Hunt Results", csv,
                                               f"hunt_{family}_{datetime.utcnow().strftime('%Y%m%d')}.csv","text/csv")
                        else:
                            st.info(f"No IOCs found for family: {family}")
                except Exception as e:
                    st.error(f"Error: {e}")

    elif hunt_mode == "OSINT Pivot (OTX Pulses)":
        col_otx1, col_otx2 = st.columns([2,1])
        with col_otx1:
            otx_search = st.text_input("Search OTX Pulses", placeholder="APT29 / SolarWinds / ransomware / CVE-2024-...")
        with col_otx2:
            otx_limit = st.slider("Max Pulses", 5, 50, 10, key="otx_hunt_limit")

        if st.button("🎯 SEARCH PULSES", key="hunt_otx"):
            if otx_search and st.session_state.get("otx_key"):
                with st.spinner("Searching OTX Pulses..."):
                    try:
                        r = requests.get(
                            f"https://otx.alienvault.com/api/v1/search/pulses?q={otx_search}&limit={otx_limit}",
                            headers={"X-OTX-API-KEY": st.session_state.otx_key}, timeout=15
                        )
                        if r.status_code == 200:
                            pulses = r.json().get("results", [])
                            if pulses:
                                for p in pulses[:10]:
                                    st.markdown(f"""
                                    <div class='result-card suspicious'>
                                      <div style='color:#00d4ff;font-weight:600;font-size:14px;'>{p.get("name","")}</div>
                                      <div style='color:#64748b;font-size:11px;margin-top:4px;'>
                                        Author: {p.get("author_name","")} | 
                                        IOCs: {p.get("indicator_count",0)} | 
                                        Tags: {", ".join(p.get("tags",[])[:5])} |
                                        Modified: {p.get("modified","")[:10]}
                                      </div>
                                      <div style='color:#94a3b8;font-size:11px;margin-top:4px;'>{str(p.get("description",""))[:200]}</div>
                                    </div>
                                    """, unsafe_allow_html=True)
                            else:
                                st.info("No pulses found.")
                    except Exception as e:
                        st.error(f"Error: {e}")
            else:
                st.warning("OTX API key required.")

    elif hunt_mode == "Passive DNS Hunt":
        col_pd1, _ = st.columns([2,1])
        with col_pd1:
            pdns_query = st.text_input("IP or Domain for Passive DNS", placeholder="1.2.3.4 or evil.com")

        if st.button("🎯 HUNT PASSIVE DNS", key="hunt_pdns"):
            if pdns_query:
                with st.spinner("Running Passive DNS lookups..."):
                    results = []
                    results.append(dns_lookup(pdns_query))
                    if is_domain(pdns_query):
                        results.append(whois_lookup(pdns_query))
                    if st.session_state.get("vt_key"):
                        if is_domain(pdns_query):
                            try:
                                r = requests.get(
                                    f"https://www.virustotal.com/api/v3/domains/{pdns_query}/resolutions?limit=20",
                                    headers={"x-apikey": st.session_state.vt_key}, timeout=15
                                )
                                if r.status_code == 200:
                                    resolutions = r.json().get("data",[])
                                    ips = [res.get("attributes",{}).get("ip_address","") for res in resolutions]
                                    st.markdown(f"**Passive DNS Resolutions ({len(ips)}):** `{'` · `'.join(set(ips[:15]))}`")
                            except: pass

                    st.session_state.hunt_results.extend(results)
                    for res in results:
                        details = " | ".join(f"{k}: <span style='color:#e2e8f0;'>{v}</span>"
                                            for k,v in res.items()
                                            if k not in ("source","ioc","type","verdict","timestamp","raw") and v and v!="N/A")
                        st.markdown(f"""
                        <div class='result-card unknown'>
                          <span style='color:#00d4ff;font-weight:600;'>{res.get("source","")}</span>
                          <span style='color:#94a3b8;margin-left:12px;font-size:12px;'>{res.get("verdict","")}</span>
                          <div style='color:#64748b;margin-top:6px;font-size:11px;line-height:1.8;'>{details}</div>
                        </div>
                        """, unsafe_allow_html=True)

    elif hunt_mode == "ASN / CIDR Hunt (Shodan)":
        col_asn1, _ = st.columns([2,1])
        with col_asn1:
            asn_query = st.text_input("ASN or CIDR", placeholder="AS13335  |  192.168.0.0/24")
            asn_filters = st.text_input("Additional Shodan Filters", placeholder='port:3389 os:"Windows"')

        if st.button("🎯 HUNT ASN/CIDR", key="hunt_asn"):
            if asn_query and st.session_state.get("shodan_key"):
                q = f"asn:{asn_query} {asn_filters}" if asn_query.startswith("AS") else f"net:{asn_query} {asn_filters}"
                with st.spinner("Hunting infrastructure..."):
                    r = shodan_check(q.strip(), st.session_state.shodan_key)
                    st.session_state.hunt_results.append(r)
                    st.markdown(f"""
                    <div class='result-card unknown'>
                      <span style='color:#00d4ff;'>Query:</span> <span style='color:#e2e8f0;font-family:JetBrains Mono,monospace;'>{q}</span><br>
                      <span style='color:#64748b;font-size:12px;margin-top:4px;display:block;'>Result: {r.get("verdict","")}</span>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.warning("Shodan API key required.")


# ════════════════════════════════════════════════════════════════
#  TAB 5 — OSINT
# ════════════════════════════════════════════════════════════════
with tab5:
    st.markdown("### OSINT Investigation")
    st.markdown("<div style='font-size:13px;color:#64748b;margin-bottom:16px;'>Open-source intelligence gathering for domains, IPs, and infrastructure.</div>", unsafe_allow_html=True)

    osint_col1, osint_col2 = st.columns([2,1])
    with osint_col1:
        osint_target = st.text_input("OSINT Target", placeholder="IP address, domain, or organization name")
    with osint_col2:
        osint_modules = st.multiselect("Modules", [
            "WHOIS/RDAP", "DNS Records", "IP Geolocation",
            "Shodan Scan", "Censys Scan", "VirusTotal Context",
            "OTX Intelligence", "IntelligenceX", "Pulsedive"
        ], default=["WHOIS/RDAP","DNS Records","IP Geolocation"])

    if st.button("🌐 RUN OSINT", use_container_width=False, key="btn_run_osint"):
        if osint_target:
            osint_results = []
            target = osint_target.strip()
            progress = st.progress(0)
            total = len(osint_modules)

            for i, mod in enumerate(osint_modules):
                with st.spinner(f"Running {mod}..."):
                    r = None
                    if mod == "WHOIS/RDAP":
                        if is_domain(target):
                            r = whois_lookup(target)
                    elif mod == "DNS Records":
                        if is_domain(target):
                            r = dns_lookup(target)
                    elif mod == "IP Geolocation":
                        if is_ip(target):
                            r = ipinfo_check(target)
                    elif mod == "Shodan Scan" and st.session_state.get("shodan_key"):
                        r = shodan_check(target, st.session_state.shodan_key)
                    elif mod == "Censys Scan" and st.session_state.get("censys_id"):
                        r = censys_check(target, st.session_state.censys_id, st.session_state.censys_secret)
                    elif mod == "VirusTotal Context" and st.session_state.get("vt_key"):
                        r = vt_check(target, st.session_state.vt_key)
                    elif mod == "OTX Intelligence" and st.session_state.get("otx_key"):
                        r = otx_check(target, st.session_state.otx_key)
                    elif mod == "IntelligenceX" and st.session_state.get("intelx_key"):
                        r = intelx_check(target, st.session_state.intelx_key)
                    elif mod == "Pulsedive" and st.session_state.get("pd_key"):
                        r = pulsedive_check(target, st.session_state.pd_key)

                    if r:
                        osint_results.append(r)
                        r2_clean = {k:v for k,v in r.items() if k not in ("raw","session_ioc")}
                        with st.expander(f"📌 {mod} — {r.get('verdict','')}", expanded=True):
                            for k, v in r2_clean.items():
                                if v and v != "N/A" and k not in ("source","ioc","type","verdict"):
                                    st.markdown(f"""
                                    <span style='font-family:JetBrains Mono,monospace;font-size:12px;'>
                                      <span style='color:#64748b;'>{k}:</span>
                                      <span style='color:#e2e8f0;margin-left:8px;'>{v}</span>
                                    </span><br>
                                    """, unsafe_allow_html=True)
                    progress.progress((i+1)/total)
                    time.sleep(0.2)

            progress.empty()
            st.session_state.osint_results.extend(osint_results)

            if osint_results:
                st.success(f"✅ OSINT complete — {len(osint_results)} module(s) returned data.")
        else:
            st.error("Please enter an OSINT target.")


# ════════════════════════════════════════════════════════════════
#  TAB 6 — RESULTS & EXPORT
# ════════════════════════════════════════════════════════════════
with tab6:
    st.markdown("### Results Dashboard & Export")

    # Aggregate all results
    all_data = (
        st.session_state.results +
        st.session_state.bulk_results +
        st.session_state.mail_results +
        st.session_state.osint_results +
        st.session_state.hunt_results
    )

    if all_data:
        df_all = pd.DataFrame(all_data)
        df_all = df_all.drop(columns=["raw","session_ioc"], errors="ignore")

        # Summary metrics
        total = len(df_all)
        malicious = df_all["verdict"].str.lower().str.contains("malicious|phishing|spam", na=False).sum() if "verdict" in df_all.columns else 0
        suspicious = df_all["verdict"].str.lower().str.contains("suspicious|warn", na=False).sum() if "verdict" in df_all.columns else 0
        clean = df_all["verdict"].str.lower().str.contains("clean|harmless|safe|not found|benign", na=False).sum() if "verdict" in df_all.columns else 0

        m1, m2, m3, m4 = st.columns(4)
        with m1: st.markdown(f"""<div class='metric-card'><div class='metric-value'>{total}</div><div class='metric-label'>Total Results</div></div>""", unsafe_allow_html=True)
        with m2: st.markdown(f"""<div class='metric-card'><div class='metric-value' style='color:#ff3860;'>{malicious}</div><div class='metric-label'>Malicious</div></div>""", unsafe_allow_html=True)
        with m3: st.markdown(f"""<div class='metric-card'><div class='metric-value' style='color:#ff8c00;'>{suspicious}</div><div class='metric-label'>Suspicious</div></div>""", unsafe_allow_html=True)
        with m4: st.markdown(f"""<div class='metric-card'><div class='metric-value' style='color:#00ff88;'>{clean}</div><div class='metric-label'>Clean</div></div>""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Filter controls
        col_f1, col_f2, col_f3 = st.columns(3)
        with col_f1:
            filter_verdict = st.multiselect("Filter by Verdict", df_all["verdict"].dropna().unique().tolist() if "verdict" in df_all.columns else [])
        with col_f2:
            filter_source = st.multiselect("Filter by Source", df_all["source"].dropna().unique().tolist() if "source" in df_all.columns else [])
        with col_f3:
            filter_type = st.multiselect("Filter by IOC Type", df_all["type"].dropna().unique().tolist() if "type" in df_all.columns else [])

        df_filtered = df_all.copy()
        if filter_verdict: df_filtered = df_filtered[df_filtered["verdict"].isin(filter_verdict)]
        if filter_source:  df_filtered = df_filtered[df_filtered["source"].isin(filter_source)]
        if filter_type:    df_filtered = df_filtered[df_filtered["type"].isin(filter_type)]

        st.markdown(f"**Showing {len(df_filtered)} of {total} results**")
        st.dataframe(df_filtered, use_container_width=True, hide_index=True)

        # Export options
        st.markdown("---")
        st.markdown("### 📥 Export Options")
        exp_col1, exp_col2, exp_col3 = st.columns(3)

        with exp_col1:
            csv_all = df_all.to_csv(index=False)
            st.download_button(
                "⬇️ Export ALL Results (CSV)",
                csv_all,
                f"threatscope_all_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv",
                "text/csv",
                use_container_width=True
            )

        with exp_col2:
            if len(df_filtered) > 0:
                csv_filtered = df_filtered.to_csv(index=False)
                st.download_button(
                    "⬇️ Export Filtered (CSV)",
                    csv_filtered,
                    f"threatscope_filtered_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv",
                    "text/csv",
                    use_container_width=True
                )

        with exp_col3:
            # Export only malicious
            if "verdict" in df_all.columns:
                df_mal = df_all[df_all["verdict"].str.lower().str.contains("malicious|phishing", na=False)]
                if len(df_mal) > 0:
                    csv_mal = df_mal.to_csv(index=False)
                    st.download_button(
                        "⬇️ Export Malicious Only (CSV)",
                        csv_mal,
                        f"threatscope_malicious_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv",
                        "text/csv",
                        use_container_width=True
                    )

        # Clear results
        st.markdown("---")
        if st.button("🗑️ Clear All Session Results", type="secondary", key="btn_clear_results"):
            for key in ["results","bulk_results","mail_results","osint_results","hunt_results"]:
                st.session_state[key] = []
            st.rerun()

    else:
        st.markdown("""
        <div style='text-align:center;padding:60px 20px;color:#475569;'>
          <div style='font-size:48px;'>📭</div>
          <div style='font-size:18px;font-weight:600;margin-top:16px;font-family:Rajdhani,sans-serif;'>No results yet</div>
          <div style='font-size:14px;margin-top:8px;'>Run IOC checks, bulk analysis, or OSINT investigations to see results here.</div>
        </div>
        """, unsafe_allow_html=True)
