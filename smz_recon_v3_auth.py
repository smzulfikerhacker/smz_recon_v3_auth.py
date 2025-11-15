#!/usr/bin/env python3
"""
SM Zulfiker Hacker v3 - Final (Auth-enabled, permission-first, Kali & Termux friendly)
Usage:
    python3 smz_recon_v3_auth.py example.com

Default auth:
    Username: SM Zulfiker
    Password: Hacker

Dependencies (python):
    pip3 install requests beautifulsoup4 tldextract python-dateutil dnspython
(External optional tools: subfinder, amass, nmap, nuclei, nikto - only used if installed and you confirm)
"""

from __future__ import annotations
import os, sys, time, re, json, socket, subprocess, hashlib
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import tldextract
from dateutil import tz

# ---- Settings ----
DEFAULT_USER = os.getenv("SMZ_USER", "SM Zulfiker")
DEFAULT_PASS_HASH = os.getenv("SMZ_PASS_HASH",
                              hashlib.sha256("Hacker".encode()).hexdigest())
UA = {"User-Agent": "SMZ-Recon/v3-final (+for authorized testing only)"}
RATE_SLEEP = 0.4
REFLECTION_TOKEN = "SMZ_FINAL_REFLECT_2025"
COMMON_PATHS = ["/admin", "/administrator", "/login", "/wp-admin", "/.git/HEAD",
                "/robots.txt", "/.env", "/config.js", "/.well-known/security.txt"]
JS_PATTERNS = [
    r"api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9\-\._=+/]{8,}['\"]",
    r"access[_-]?key",
    r"secret[_-]?key",
    r"token\s*[:=]\s*['\"][A-Za-z0-9\-\._]{8,}['\"]",
    r"client[_-]?id\s*[:=]\s*['\"][A-Za-z0-9\-\._]{6,}['\"]"
]
BUCKET_PROBES = ["{name}.s3.amazonaws.com", "storage.googleapis.com/{name}", "{name}.blob.core.windows.net"]
COMMON_BUCKET_WORDLIST = ["backup","uploads","static","assets","media","dev","staging","prod","backup-uploads"]

# suppress insecure warnings for verify=False (explicitly used)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ---- Helpers ----
def auth_prompt() -> bool:
    print("=== SM Zulfiker Hacker v3 — LOGIN ===")
    user = input("Username: ").strip()
    pwd = input("Password: ").strip()
    phash = hashlib.sha256(pwd.encode()).hexdigest()
    if user == DEFAULT_USER and phash == DEFAULT_PASS_HASH:
        print("[✓] Authenticated\n")
        return True
    else:
        print("[✗] Authentication failed\n")
        return False

def confirm(prompt: str) -> bool:
    ans = input(f"{prompt} (yes/no): ").strip().lower()
    return ans == "yes"

def is_tool_installed(name: str) -> bool:
    try:
        subprocess.check_output(["which", name], stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False

def run_cmd(cmd_list, timeout=300):
    try:
        return subprocess.check_output(cmd_list, stderr=subprocess.DEVNULL, timeout=timeout).decode(errors="ignore")
    except Exception:
        return None

def simple_domain_validator(domain: str) -> bool:
    # basic check: contains at least one dot and no scheme
    if not domain or " " in domain:
        return False
    d = domain.strip().lower()
    if d.startswith("http://") or d.startswith("https://"):
        d = d.split("://",1)[1]
    return "." in d and len(d.split(".")[-1]) >= 2

# ---- Passive enum ----
def crt_sh(domain: str):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, headers=UA, timeout=15)
        time.sleep(RATE_SLEEP)
        if r.status_code != 200:
            return []
        data = r.json()
        subs = set()
        for e in data:
            nv = e.get("name_value","") or ""
            for s in nv.splitlines():
                s = s.strip()
                if s and "*" not in s:
                    subs.add(s)
        return sorted(subs)
    except Exception:
        return []

def threatcrowd(domain: str):
    try:
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        r = requests.get(url, headers=UA, timeout=12)
        time.sleep(RATE_SLEEP)
        j = r.json()
        return j.get("subdomains", []) or []
    except Exception:
        return []

# ---- Active brute (simple wordlist) ----
def brute_wordlist(domain: str, words=None):
    if words is None:
        words = ["www","api","dev","stage","staging","test","mail","admin","portal","beta","app"]
    found = []
    for w in words:
        host = f"{w}.{domain}"
        try:
            socket.gethostbyname(host)
            found.append(host)
        except:
            pass
    return sorted(found)

# ---- Resolve ----
def resolve_host(host: str):
    try:
        return socket.gethostbyname(host)
    except:
        return None

# ---- HTTP probe (httpx-like) ----
def probe_host(host: str):
    results = []
    for scheme in ("https://","http://"):
        url = scheme + host
        try:
            r = requests.get(url, headers=UA, timeout=10, allow_redirects=True, verify=False)
            soup = BeautifulSoup(r.text, "html.parser")
            title = soup.title.string.strip() if soup.title and soup.title.string else ""
            results.append({
                "url": url,
                "status": r.status_code,
                "title": title,
                "server": r.headers.get("Server",""),
                "length": len(r.text),
                "headers": dict(r.headers),
                "body": r.text[:20000]
            })
            break
        except Exception:
            continue
    return results

# ---- Extract URLs & JS ----
def extract_urls_and_js(html: str, base: str):
    soup = BeautifulSoup(html, "html.parser")
    urls = set()
    js = set()
    for tag in soup.find_all(["a","link","script","img","iframe","form"]):
        for attr in ("href","src","action"):
            v = tag.get(attr)
            if v:
                full = urljoin(base, v)
                urls.add(full)
                if full.endswith(".js") or ".js?" in full:
                    js.add(full)
    return sorted(urls), sorted(js)

# ---- Param heuristics + reflection ----
def find_param_candidates(urls):
    items = []
    for u in urls:
        try:
            p = urlparse(u)
            qs = parse_qs(p.query)
            if not qs:
                continue
            params = list(qs.keys())
            sqli = [n for n in params if any(x in n.lower() for x in ("id","uid","user","prod","item","order","cat","page"))]
            xss = [n for n in params if any(x in n.lower() for x in ("q","search","s","query","term","msg","name","title","comment","body","text"))]
            reflected = []
            for param in xss:
                try:
                    base = p.scheme + "://" + p.netloc + p.path
                    params_dict = {k: (REFLECTION_TOKEN if k==param else (v[0] if isinstance(v,list) else v)) for k,v in qs.items()}
                    r = requests.get(base, params=params_dict, headers=UA, timeout=8, verify=False)
                    time.sleep(RATE_SLEEP)
                    if REFLECTION_TOKEN in r.text:
                        reflected.append(param)
                except:
                    pass
            items.append({"url":u,"params":params,"sqli":sqli,"xss":xss,"reflected":reflected})
        except:
            continue
    return items

# ---- JS secret scan ----
def scan_js_for_secrets(js_urls, limit=20):
    findings = {}
    for j in js_urls[:limit]:
        try:
            r = requests.get(j, headers=UA, timeout=10, verify=False)
            time.sleep(RATE_SLEEP)
            body = r.text[:20000]
            matches = []
            for pat in JS_PATTERNS:
                if re.search(pat, body, re.IGNORECASE):
                    matches.append(pat)
            if matches:
                findings[j] = matches
        except:
            continue
    return findings

# ---- Common paths ----
def check_common_paths(host: str):
    found = []
    base = ("https://" + host) if not host.startswith("http") else host
    for p in COMMON_PATHS:
        try:
            url = urljoin(base if base.endswith("/") else base + "/", p.lstrip("/"))
            r = requests.get(url, headers=UA, timeout=6, allow_redirects=True, verify=False)
            time.sleep(RATE_SLEEP)
            if r.status_code in (200,401,403):
                found.append({"path":p,"url":url,"status":r.status_code})
        except:
            continue
    return found

# ---- Cloud bucket probes (safe) ----
def check_public_bucket_names(domain: str):
    findings = []
    candidates = [domain.split(".")[0]] + COMMON_BUCKET_WORDLIST
    for name in candidates:
        for template in BUCKET_PROBES:
            probe = template.format(name=name)
            try:
                r = requests.head(f"https://{probe}", headers=UA, timeout=6, verify=False)
                if r.status_code in (200,403,401):
                    findings.append({"probe":probe,"status":r.status_code})
            except:
                continue
    return findings

# ---- External tools wrappers (optional) ----
def run_subfinder(domain: str):
    if not is_tool_installed("subfinder"):
        return None
    if not confirm("subfinder detected. Run subfinder now?"):
        return None
    print("[*] Running subfinder (may take time)...")
    out = run_cmd(["subfinder","-d",domain,"-silent"], timeout=900)
    if out:
        return sorted(set(out.splitlines()))
    return None

def run_amass(domain: str):
    if not is_tool_installed("amass"):
        return None
    if not confirm("amass detected. Run amass enum now?"):
        return None
    run_cmd(["amass","enum","-d",domain,"-oA",f"/tmp/smz_amass_{domain}"], timeout=1200)
    p = f"/tmp/smz_amass_{domain}.txt"
    if os.path.exists(p):
        with open(p,"r") as fh:
            return sorted(set(l.strip() for l in fh if l.strip()))
    return None

def run_nmap(target: str):
    if not is_tool_installed("nmap"):
        return None
    if not confirm("nmap detected. Run light nmap (-sV -Pn)?"):
        return None
    print("[*] Running nmap (light)...")
    return run_cmd(["nmap","-sV","-Pn",target], timeout=600)

def run_nuclei(target: str):
    if not is_tool_installed("nuclei"):
        return None
    if not confirm("nuclei detected. Run nuclei templates?"):
        return None
    print("[*] Running nuclei (may take time)...")
    return run_cmd(["nuclei","-u",target,"-silent"], timeout=900)

def run_nikto(target: str):
    if not is_tool_installed("nikto"):
        return None
    if not confirm("nikto detected. Run nikto web scan?"):
        return None
    print("[*] Running nikto (active web scan)...")
    return run_cmd(["nikto","-h",target], timeout=900)

# ---- Report generation ----
def generate_reports(domain: str, findings: dict):
    now = datetime.now(tz=tz.tzlocal()).strftime("%Y%m%dT%H%M%S%z")
    md_name = f"smz_report_{domain.replace('.','_')}_{now}.md"
    json_name = f"smz_report_{domain.replace('.','_')}_{now}.json"
    with open(json_name,"w",encoding="utf-8") as jf:
        json.dump(findings, jf, indent=2)
    lines = []
    lines.append(f"# SM Zulfiker Hacker v3 — Recon Report")
    lines.append(f"_Target: {domain}_")
    lines.append(f"_Generated: {datetime.now(tz=tz.tzlocal()).isoformat()}_")
    lines.append("\n---\n")
    lines.append("## Summary")
    lines.append(f"- Passive subdomains: {len(findings.get('passive_subs',[]))}")
    lines.append(f"- Active subs: {len(findings.get('active_subs',[]))}")
    lines.append(f"- Live hosts: {len(findings.get('live_hosts',[]))}")
    lines.append("\n---\n")
    lines.append("## Passive Subdomains")
    for s in findings.get("passive_subs",[]):
        lines.append(f"- {s}")
    lines.append("\n---\n")
    lines.append("## Active Subdomains")
    for s in findings.get("active_subs",[]):
        lines.append(f"- {s}")
    lines.append("\n---\n")
    lines.append("## Live Hosts")
    for h,ip in findings.get("live_hosts",[]):
        lines.append(f"- {h} → {ip}")
    lines.append("\n---\n")
    lines.append("## HTTP Probes")
    for host, probes in findings.get("probes",{}).items():
        lines.append(f"### {host}")
        for p in probes:
            lines.append(f"- {p['url']} (status: {p['status']})")
            if p.get("title"):
                lines.append(f"  - Title: {p['title']}")
            if p.get("server"):
                lines.append(f"  - Server: {p['server']}")
    lines.append("\n---\n")
    lines.append("## Parameter Candidates")
    for it in findings.get("param_candidates",[]):
        lines.append(f"- {it['url']}")
        if it.get("params"):
            lines.append(f"  - Params: {', '.join(it['params'])}")
        if it.get("sqli"):
            lines.append(f"  - SQLi heuristics: {', '.join(it['sqli'])}")
        if it.get("xss"):
            lines.append(f"  - XSS heuristics: {', '.join(it['xss'])}")
        if it.get("reflected"):
            lines.append(f"  - Reflected: {', '.join(it['reflected'])}")
    lines.append("\n---\n")
    lines.append("## JS Secret Heuristics")
    for j,matches in findings.get("js_secrets",{}).items():
        lines.append(f"- {j} — patterns: {', '.join(matches)}")
    lines.append("\n---\n")
    lines.append("## Common paths")
    for p in findings.get("common_paths",[]):
        lines.append(f"- {p['url']} (status: {p['status']})")
    lines.append("\n---\n")
    lines.append("## Cloud bucket probes")
    for b in findings.get("bucket_checks",[]):
        lines.append(f"- {b['probe']} (status: {b['status']})")
    if findings.get("nmap"):
        lines.append("\n---\n## nmap\n```")
        lines.append(findings["nmap"][:20000])
        lines.append("```")
    if findings.get("nuclei"):
        lines.append("\n---\n## nuclei\n```")
        lines.append(findings["nuclei"][:20000])
        lines.append("```")
    if findings.get("nikto"):
        lines.append("\n---\n## nikto\n```")
        lines.append(findings["nikto"][:20000])
        lines.append("```")
    with open(md_name,"w",encoding="utf-8") as mf:
        mf.write("\n".join(lines))
    return md_name, json_name

# ---- Main workflow ----
def main():
    if len(sys.argv) != 2:
        print("Usage: python3 smz_recon_v3_auth.py example.com")
        sys.exit(0)
    target = sys.argv[1].strip()
    if not simple_domain_validator(target):
        print("Please provide a valid domain (example.com)")
        sys.exit(1)

    if not auth_prompt():
        sys.exit(1)

    print("[*] Starting passive enumeration (crt.sh, ThreatCrowd)...")
    findings = {
        "passive_subs": [],
        "active_subs": [],
        "live_hosts": [],
        "probes": {},
        "param_candidates": [],
        "js_secrets": {},
        "common_paths": [],
        "bucket_checks": [],
        "nmap": None,
        "nuclei": None,
        "nikto": None
    }

    passive = set(crt_sh(target) + threatcrowd(target))
    findings["passive_subs"] = sorted(passive)

    print(f"[*] Passive found: {len(findings['passive_subs'])} subdomains")

    print("[*] Active enumeration: local wordlist + optional external tools...")
    active = set(brute_wordlist(target))
    sf = run_subfinder(target)
    if sf:
        active.update(sf)
    am = run_amass(target)
    if am:
        active.update(am)
    findings["active_subs"] = sorted(active - set(findings["passive_subs"]))

    all_subs = sorted(set(findings["passive_subs"]) | set(findings["active_subs"]) | {target})
    print(f"[*] Total targets to probe: {len(all_subs)}")

    for s in all_subs:
        ip = resolve_host(s)
        if ip:
            findings["live_hosts"].append([s, ip])
    print(f"[*] Live hosts: {len(findings['live_hosts'])}")

    for s, ip in findings["live_hosts"]:
        print(f"[*] Probing {s} ...")
        probes = probe_host(s)
        findings["probes"][s] = probes
        for p in probes:
            urls, js = extract_urls_and_js(p.get("body","") or "", p.get("url",""))
            pc = find_param_candidates(urls)
            findings["param_candidates"].extend(pc)
            jssec = scan_js_for_secrets(js, limit=30)
            findings["js_secrets"].update(jssec)
            cp = check_common_paths(s)
            findings["common_paths"].extend(cp)
        time.sleep(RATE_SLEEP)

    if confirm("Run safe cloud-bucket probes (HTTP HEAD checks)?"):
        findings["bucket_checks"] = check_public_bucket_names(target)

    if is_tool_installed("nmap") and confirm("Run nmap (light) now?"):
        findings["nmap"] = run_nmap(target)
    if is_tool_installed("nuclei") and confirm("Run nuclei now?"):
        findings["nuclei"] = run_nuclei(target)
    if is_tool_installed("nikto") and confirm("Run nikto now?"):
        findings["nikto"] = run_nikto(target)

    md, js = generate_reports(target, findings)
    print(f"\n[+] Reports generated:\n - {md}\n - {js}")
    print("[!] Reminder: This tool only helps reconnaissance & points to manual test areas. Do NOT run exploits without explicit written permission.")

if __name__ == "__main__":
    main()
