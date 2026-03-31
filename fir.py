#!/usr/bin/env python3
"""
forensic.py — Network Forensic Analyser
Powered by tshark (Wireshark CLI engine)

Usage:
  python3 forensic.py file.pcap
  python3 forensic.py file1.pcap file2.pcap file3.pcap   (batch mode)

Course: 21CSE381T — Forensics and Incident Response
"""

import subprocess, sys, os, re, datetime, webbrowser, ipaddress, json
from pathlib import Path
from collections import Counter, defaultdict

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────
TSHARK     = "tshark"
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

SUSPICIOUS_PORTS = {
    4444:  "Metasploit default",
    1337:  "Leet / backdoor",
    8080:  "Alt HTTP / C2",
    8443:  "Alt HTTPS / C2",
    9001:  "Tor OR port",
    9030:  "Tor directory",
    6667:  "IRC / botnet",
    6666:  "IRC / botnet",
    31337: "Elite backdoor",
}

SUSPICIOUS_UA_PATTERNS = [
    "python-requests", "curl", "wget", "go-http",
    "libwww", "masscan", "nmap", "zgrab", "nuclei", "sqlmap",
]

TYPOSQUAT_KEYWORDS = [
    "microsoft", "google", "amazon", "apple", "facebook",
    "paypal", "dropbox", "adobe", "windows", "office365",
]

# Map last segment of frame.protocols chain -> display label
PROTO_MAP = {
    "tls":      "TLS",
    "http":     "HTTP",
    "http2":    "HTTP/2",
    "dns":      "DNS",
    "kerberos": "Kerberos",
    "smb":      "SMB",
    "smb2":     "SMB2",
    "dhcp":     "DHCP",
    "bootp":    "DHCP",
    "ssh":      "SSH",
    "ftp":      "FTP",
    "smtp":     "SMTP",
    "imap":     "IMAP",
    "nbns":     "NBNS",
    "mdns":     "mDNS",
    "ntp":      "NTP",
    "ssdp":     "SSDP",
    "icmp":     "ICMP",
    "arp":      "ARP",
    "tcp":      "TCP",
    "udp":      "UDP",
}

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def is_private(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_RANGES)
    except ValueError:
        return False

def run_tshark(pcap, fields, display_filter=""):
    cmd = [TSHARK, "-r", pcap, "-T", "fields",
           "-E", "header=n", "-E", "separator=|",
           "-E", "quote=n",  "-E", "occurrence=f"]
    for f in fields:
        cmd += ["-e", f]
    if display_filter:
        cmd += ["-Y", display_filter]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except subprocess.CalledProcessError:
        return []
    results = []
    for line in out.strip().splitlines():
        parts = line.split("|")
        while len(parts) < len(fields):
            parts.append("")
        results.append(dict(zip(fields, parts)))
    return results

def severity_label(score):
    if score >= 8: return ("CRITICAL", "#FF3B30")
    if score >= 5: return ("HIGH",     "#FF9500")
    if score >= 3: return ("MEDIUM",   "#FFCC00")
    return              ("LOW",      "#30D158")

# ─────────────────────────────────────────────────────────────────────────────
# ANALYSIS MODULES
# ─────────────────────────────────────────────────────────────────────────────
def get_pcap_summary(pcap):
    print("  [1/8] Gathering capture summary...")
    summary = {"file": os.path.basename(pcap),
               "packets": "N/A", "duration": "N/A",
               "start": "N/A", "end": "N/A", "size": "N/A"}
    try:
        out = subprocess.check_output(
            ["capinfos", pcap], stderr=subprocess.DEVNULL, text=True)
        for key, pat in [
            ("packets",  r"Number of packets:\s+(.+)"),
            ("duration", r"Capture duration:\s+(.+)"),
            ("start",    r"First packet time:\s+(.+)"),
            ("end",      r"Last packet time:\s+(.+)"),
            ("size",     r"File size:\s+(.+)"),
        ]:
            m = re.search(pat, out)
            if m:
                summary[key] = m.group(1).strip()
    except Exception:
        pass
    return summary

def get_protocol_stats(pcap):
    """
    Reads frame.protocols for every packet and counts the most specific
    application-layer protocol in each chain. This is far more reliable
    than parsing -z io,phs text output.
    """
    print("  [2/8] Analysing protocol distribution...")
    rows = run_tshark(pcap, ["frame.protocols"])
    counter = Counter()

    for row in rows:
        chain = row.get("frame.protocols", "").lower().strip()
        if not chain:
            continue
        parts = [p.strip() for p in chain.split(":") if p.strip()]
        # Walk from most-specific (rightmost) to find a label we know
        best = None
        for p in reversed(parts):
            if p in PROTO_MAP:
                best = PROTO_MAP[p]
                break
        if best is None:
            best = parts[-1].upper() if parts else "OTHER"
        counter[best] += 1

    # Return top 10
    return dict(counter.most_common(10))

def get_victim_profile(pcap):
    print("  [3/8] Identifying victim host...")
    profile = {"hostname": None, "ip": None, "mac": None,
               "username": None, "domain": None, "os_hint": None}

    kerb = run_tshark(pcap, ["kerberos.CNameString", "ip.src"],
                      "kerberos.CNameString")
    for row in kerb:
        name = row.get("kerberos.CNameString", "")
        if name and "$" not in name:
            profile["username"] = name
            profile["ip"] = row.get("ip.src", "")
            break

    dhcp = run_tshark(pcap,
        ["dhcp.option.hostname", "eth.src", "ip.src"],
        "dhcp.option.hostname")
    for row in dhcp:
        hn = row.get("dhcp.option.hostname", "")
        if hn:
            profile["hostname"] = hn
            profile["mac"]      = row.get("eth.src", "")
            if not profile["ip"]:
                profile["ip"]   = row.get("ip.src", "")
            break

    dns_rows = run_tshark(pcap, ["dns.qry.name"], "dns.qry.name")
    for r in dns_rows:
        d = r.get("dns.qry.name", "")
        if profile["hostname"] and profile["hostname"].lower() in d.lower():
            profile["domain"] = d
            break

    ua_rows = run_tshark(pcap, ["http.user_agent"], "http.user_agent")
    for row in ua_rows:
        ua = row.get("http.user_agent", "")
        if "Windows" in ua:   profile["os_hint"] = "Windows"; break
        elif "Linux" in ua:   profile["os_hint"] = "Linux";   break
        elif "Mac" in ua:     profile["os_hint"] = "macOS";   break

    return profile

def get_dns_analysis(pcap):
    print("  [4/8] Analysing DNS traffic...")
    rows = run_tshark(pcap,
        ["dns.qry.name", "dns.a", "ip.src"], "dns.qry.type == 1")

    query_counter = Counter()
    suspicious    = []
    all_domains   = []

    for row in rows:
        qname = row.get("dns.qry.name", "").strip().lower()
        if not qname:
            continue
        query_counter[qname] += 1
        all_domains.append(qname)
        reasons = []

        for keyword in TYPOSQUAT_KEYWORDS:
            if keyword in qname:
                legit = [f"{keyword}.com", f"www.{keyword}.com",
                         f"{keyword}.net", f"{keyword}.org"]
                if not any(qname == l or qname.endswith(f".{keyword}.com")
                           for l in legit):
                    reasons.append(f"Typosquats '{keyword}'")

        tld = qname.split(".")[-1] if "." in qname else ""
        if tld in ["xyz","top","live","club","online","site",
                   "info","biz","pw","cc","ru","cn","tk"]:
            reasons.append(f"Suspicious TLD .{tld}")

        parts = qname.split(".")
        if parts:
            sub = parts[0]
            if len(sub) > 15 and re.match(r"^[a-z0-9]+$", sub):
                if sum(c.isdigit() for c in sub) / len(sub) > 0.3:
                    reasons.append("Possible DGA domain")

        if reasons:
            suspicious.append({
                "domain": qname,
                "ip":     row.get("dns.a", ""),
                "src":    row.get("ip.src", ""),
                "reasons": reasons,
                "score":   len(reasons) * 3
            })

    seen = set()
    deduped = []
    for item in suspicious:
        if item["domain"] not in seen:
            seen.add(item["domain"])
            deduped.append(item)

    return {
        "total_queries":  len(rows),
        "unique_domains": len(set(all_domains)),
        "top_queried":    query_counter.most_common(10),
        "suspicious":     sorted(deduped, key=lambda x: x["score"], reverse=True)
    }

def get_http_analysis(pcap):
    print("  [5/8] Analysing HTTP traffic...")
    rows = run_tshark(pcap,
        ["ip.src", "ip.dst", "http.host", "http.request.uri",
         "http.request.method", "http.user_agent"],
        "http.request")

    ua_counter   = Counter()
    host_counter = Counter()
    suspicious   = []

    for row in rows:
        host   = row.get("http.host", "")
        uri    = row.get("http.request.uri", "")
        method = row.get("http.request.method", "")
        ua     = row.get("http.user_agent", "")
        src    = row.get("ip.src", "")
        dst    = row.get("ip.dst", "")

        if host: host_counter[host] += 1
        if ua:   ua_counter[ua] += 1

        reasons  = []
        uri_path = uri.split("?")[0].strip("/")
        if uri_path and len(uri_path) > 8:
            if re.match(r"^[A-Za-z0-9]{8,}$", uri_path):
                reasons.append("Random-looking URI (C2 beacon pattern)")

        for sus_ua in SUSPICIOUS_UA_PATTERNS:
            if sus_ua in ua.lower():
                reasons.append(f"Suspicious UA: {sus_ua}")

        if method == "POST" and dst and not is_private(dst):
            reasons.append("POST to external IP")

        if reasons:
            suspicious.append({
                "method": method, "host": host, "uri": uri,
                "ua": ua, "src": src, "dst": dst,
                "reasons": reasons, "score": len(reasons) * 3
            })

    return {
        "total_requests":  len(rows),
        "top_hosts":       host_counter.most_common(8),
        "top_user_agents": ua_counter.most_common(5),
        "suspicious":      sorted(suspicious, key=lambda x: x["score"], reverse=True)[:15],
    }

def get_tls_analysis(pcap):
    print("  [6/8] Analysing TLS/encrypted traffic...")
    rows = run_tshark(pcap,
        ["ip.src", "ip.dst", "tcp.dstport",
         "tls.handshake.extensions_server_name", "tls.handshake.ja3"],
        "tls.handshake.type == 1")

    ja3_counter = Counter()
    sni_list    = []
    suspicious  = []

    for row in rows:
        src  = row.get("ip.src", "")
        dst  = row.get("ip.dst", "")
        port = row.get("tcp.dstport", "")
        sni  = row.get("tls.handshake.extensions_server_name", "")
        ja3  = row.get("tls.handshake.ja3", "")

        if ja3: ja3_counter[ja3] += 1
        if sni: sni_list.append(sni)

        reasons = []
        if port and port not in ["443", "8443"]:
            reasons.append(f"TLS on non-standard port {port}")

        if dst and not is_private(dst):
            for keyword in TYPOSQUAT_KEYWORDS:
                if sni and keyword in sni.lower():
                    if not sni.endswith(f"{keyword}.com"):
                        reasons.append(f"Typosquatted SNI: {sni}")

        if port:
            try:
                p = int(port)
                if p in SUSPICIOUS_PORTS:
                    reasons.append(f"Port {p}: {SUSPICIOUS_PORTS[p]}")
            except ValueError:
                pass

        if reasons:
            suspicious.append({
                "src": src, "dst": dst, "port": port,
                "sni": sni, "ja3": ja3,
                "reasons": reasons, "score": len(reasons) * 3
            })

    repeated_ja3 = [(j, c) for j, c in ja3_counter.most_common() if c > 1]

    return {
        "total_client_hellos": len(rows),
        "unique_ja3":          len(ja3_counter),
        "repeated_ja3":        repeated_ja3,
        "suspicious":          sorted(suspicious, key=lambda x: x["score"], reverse=True)[:15],
        "sni_list":            list(set(sni_list))[:20]
    }

def get_connection_analysis(pcap):
    print("  [7/8] Analysing network connections...")
    rows = run_tshark(pcap,
        ["ip.src", "ip.dst", "tcp.dstport"],
        "tcp.flags.syn == 1 and tcp.flags.ack == 0")

    external_conns = defaultdict(set)
    suspicious     = []
    ip_counter     = Counter()

    for row in rows:
        src  = row.get("ip.src", "")
        dst  = row.get("ip.dst", "")
        port = row.get("tcp.dstport", "")

        if dst and not is_private(dst):
            external_conns[dst].add(port)
            ip_counter[dst] += 1

        if port:
            try:
                p = int(port)
                if p in SUSPICIOUS_PORTS:
                    suspicious.append({
                        "src": src, "dst": dst, "port": p,
                        "reason": SUSPICIOUS_PORTS[p], "score": 7
                    })
            except ValueError:
                pass

    return {
        "external_ip_count": len(external_conns),
        "top_external_ips":  ip_counter.most_common(10),
        "suspicious_ports":  suspicious[:10],
    }

def get_ioc_summary(dns, http, tls, conns):
    print("  [8/8] Consolidating IOCs...")
    iocs = []

    for item in dns.get("suspicious", []):
        iocs.append({"type": "Domain", "value": item["domain"],
                     "context": " · ".join(item["reasons"]),
                     "score": item["score"]})
    for item in http.get("suspicious", []):
        iocs.append({"type": "HTTP Request",
                     "value": f"{item['method']} {item['host']}{item['uri']}",
                     "context": " · ".join(item["reasons"]),
                     "score": item["score"]})
    for item in tls.get("suspicious", []):
        val = item["sni"] if item["sni"] else item["dst"]
        iocs.append({"type": "TLS Session",
                     "value": f"{val}:{item['port']}",
                     "context": " · ".join(item["reasons"]),
                     "score": item["score"]})
    for ja3, count in tls.get("repeated_ja3", []):
        iocs.append({"type": "JA3 Fingerprint", "value": ja3,
                     "context": f"Seen {count}× — same malware TLS library",
                     "score": min(count * 2, 10)})
    for item in conns.get("suspicious_ports", []):
        iocs.append({"type": "Suspicious Port",
                     "value": f"{item['dst']}:{item['port']}",
                     "context": item["reason"], "score": item["score"]})

    return sorted(iocs, key=lambda x: x["score"], reverse=True)

# ─────────────────────────────────────────────────────────────────────────────
# HTML REPORT
# Apple-esque / Dieter Rams minimal — Apple green (#30D158) accents
# ─────────────────────────────────────────────────────────────────────────────
def build_html(pcap_path, summary, protocols, victim, dns, http, tls, conns, iocs):
    total_score       = sum(i["score"] for i in iocs[:10])
    sev_label, sev_c  = severity_label(min(total_score // 3, 10))
    ts                = datetime.datetime.now().strftime("%B %d, %Y  %H:%M")

    proto_labels = json.dumps(list(protocols.keys()))
    proto_values = json.dumps(list(protocols.values()))
    # Apple green shades for doughnut slices
    proto_colors = json.dumps([
        "#30D158","#34C759","#25A244","#1A7A30",
        "#86EFAC","#A3E4B7","#059669","#6EE7B7",
        "#064E3B","#D1FAE5",
    ])

    def sev_badge(score):
        lbl, c = severity_label(score)
        return (f'<span class="badge" '
                f'style="background:{c}18;color:{c};border:1px solid {c}38">'
                f'{lbl}</span>')

    def rc(i):
        return "rs" if i % 2 != 0 else ""

    # ── sub-table fragments ──────────────────────────────────
    ioc_rows = "".join(f"""
      <tr class="{rc(i)}"><td>{sev_badge(x['score'])}</td>
      <td><span class="pill">{x['type']}</span></td>
      <td class="mono">{x['value']}</td>
      <td class="dim">{x['context']}</td></tr>"""
      for i, x in enumerate(iocs[:20]))

    dns_rows = "".join(f"""
      <tr class="{rc(i)}"><td class="mono">{d['domain']}</td>
      <td class="mono dim">{d.get('ip','—')}</td>
      <td class="dim">{' · '.join(d['reasons'])}</td>
      <td>{sev_badge(d['score'])}</td></tr>"""
      for i, d in enumerate(dns.get("suspicious",[])[:10]))

    METHOD_C  = {"GET":"#30D158","POST":"#FF9500"}
    METHOD_BD = {"GET":"#30D15840","POST":"#FF950040"}
    METHOD_BG = {"GET":"#30D15810","POST":"#FF950010"}
    http_parts = []
    for i, h in enumerate(http.get("suspicious",[])[:10]):
        mc  = METHOD_C.get(h["method"],"#8E8E93")
        mbd = METHOD_BD.get(h["method"],"#8E8E9340")
        mbg = METHOD_BG.get(h["method"],"#8E8E9310")
        http_parts.append(
            f'<tr class="{rc(i)}">'
            f'<td><span class="mpill" style="color:{mc};border-color:{mbd};background:{mbg}">{h["method"]}</span></td>'
            f'<td class="mono">{h["host"]}</td>'
            f'<td class="mono dim">{h["uri"]}</td>'
            f'<td class="dim">{" · ".join(h["reasons"])}</td></tr>'
        )
    http_rows = "".join(http_parts)
    tls_rows = "".join(f"""
      <tr class="{rc(i)}"><td class="mono">{t['src']}</td>
      <td class="mono">{t['dst']}:{t['port']}</td>
      <td class="mono dim">{t['sni'] or '—'}</td>
      <td class="dim">{' · '.join(t['reasons'])}</td></tr>"""
      for i, t in enumerate(tls.get("suspicious",[])[:10]))

    ja3_rows = "".join(f"""
      <tr class="{rc(i)}">
      <td class="mono" style="font-size:11px">{j}</td>
      <td style="color:#FF3B30;font-weight:600">{c}×</td>
      <td class="dim">Same TLS library across {c} sessions — one malware binary</td></tr>"""
      for i,(j,c) in enumerate(tls.get("repeated_ja3",[])[:5]))

    ext_rows = "".join(f"""
      <tr class="{rc(i)}"><td class="mono">{ip}</td>
      <td style="font-weight:500">{cnt}</td>
      <td><span class="pill" style="background:#FF3B3010;color:#FF3B30;border-color:#FF3B3030">External</span></td></tr>"""
      for i,(ip,cnt) in enumerate(conns.get("top_external_ips",[])[:8]))

    victim_rows = "".join(f"""
      <div class="kv"><div class="kv-lbl">{lbl}</div>
      <div class="kv-val mono {'dim' if val=='—' else ''}">{val}</div></div>"""
      for lbl, val in [
        ("Hostname",   victim.get("hostname") or "—"),
        ("IP Address", victim.get("ip")       or "—"),
        ("MAC",        victim.get("mac")       or "—"),
        ("Username",   victim.get("username")  or "—"),
        ("Domain",     victim.get("domain")    or "—"),
        ("OS",         victim.get("os_hint")   or "—"),
      ])

    top_dns = ""
    total_q = max(dns["total_queries"], 1)
    for domain, count in dns.get("top_queried", [])[:8]:
        pct = min(int((count / total_q) * 1000), 100)
        top_dns += f"""
        <div class="dbar">
          <div class="dbar-lbl mono">{domain}</div>
          <div class="dbar-track"><div class="dbar-fill" style="width:{pct}%"></div></div>
          <div class="dbar-n">{count}</div>
        </div>"""

    NO = '<div class="empty">No data found for this capture</div>'

    tbl = lambda hdr, body: (
        f'<table><thead><tr>'
        + "".join(f"<th>{h}</th>" for h in hdr)
        + f'</tr></thead><tbody>{body}</tbody></table>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Forensic Report — {summary['file']}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
html{{-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}}

:root{{
  --g:      #30D158;
  --g-dk:   #25A244;
  --g-bg:   rgba(48,209,88,.08);
  --g-bd:   rgba(48,209,88,.22);
  --red:    #FF3B30;
  --org:    #FF9500;
  --ylw:    #FFCC00;
  --blu:    #007AFF;
  --bg:     #F5F5F7;
  --srf:    #FFFFFF;
  --srf2:   #F9F9F9;
  --bdr:    #E5E5EA;
  --lbl:    #1D1D1F;
  --sec:    #3A3A3C;
  --trt:    #6E6E73;
  --qat:    #AEAEB2;
  --r:      12px;
  --r-lg:   16px;
  --sh:     0 1px 3px rgba(0,0,0,.05),0 4px 16px rgba(0,0,0,.07);
  --sh-sm:  0 1px 3px rgba(0,0,0,.06);
}}

body{{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","Helvetica Neue",sans-serif;
     background:var(--bg);color:var(--lbl);font-size:14px;line-height:1.5}}

/* NAV */
.nav{{position:sticky;top:0;z-index:100;
     background:rgba(255,255,255,.82);
     -webkit-backdrop-filter:blur(20px);backdrop-filter:blur(20px);
     border-bottom:1px solid var(--bdr);
     height:52px;padding:0 28px;
     display:flex;align-items:center;justify-content:space-between}}
.nav-l{{display:flex;align-items:center;gap:10px}}
.nav-dot{{width:9px;height:9px;border-radius:50%;background:var(--g);
         box-shadow:0 0 0 3px var(--g-bg)}}
.nav-title{{font-size:15px;font-weight:600;letter-spacing:-.2px}}
.nav-meta{{font-size:12px;color:var(--trt);margin-left:6px}}
.nav-chip{{font-size:11px;font-weight:600;letter-spacing:.5px;padding:3px 10px;
          border-radius:20px;background:{sev_c}18;color:{sev_c};border:1px solid {sev_c}40}}

/* WRAP */
.w{{max-width:1120px;margin:0 auto;padding:28px 24px 56px}}

/* HERO */
.hero{{background:var(--srf);border:1px solid var(--bdr);border-radius:var(--r-lg);
      padding:28px 32px;margin-bottom:18px;box-shadow:var(--sh);
      display:flex;align-items:center;justify-content:space-between;gap:24px}}
.hero-ey{{font-size:11px;font-weight:600;letter-spacing:1.4px;
         text-transform:uppercase;color:var(--g);margin-bottom:6px}}
.hero-title{{font-size:21px;font-weight:700;letter-spacing:-.4px;margin-bottom:5px}}
.hero-meta{{font-size:12px;color:var(--trt)}}
.hero-meta span{{margin-right:14px}}
.hero-status{{margin-top:12px;font-size:13px;font-weight:500;
             display:flex;align-items:center;gap:7px;
             color:{'#FF3B30' if len(iocs)>5 else '#30D158'}}}
.hero-status::before{{content:'';display:inline-block;width:7px;height:7px;
                     border-radius:50%;background:{'#FF3B30' if len(iocs)>5 else '#30D158'}}}
.hero-sev{{text-align:center;flex-shrink:0;
          background:{sev_c}0d;border:1.5px solid {sev_c}38;
          border-radius:var(--r);padding:16px 22px}}
.hero-sev-v{{font-size:13px;font-weight:700;letter-spacing:.8px;color:{sev_c}}}
.hero-sev-s{{font-size:11px;color:var(--trt);margin-top:2px}}

/* STATS */
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:18px}}
.stat{{background:var(--srf);border:1px solid var(--bdr);border-radius:var(--r);
      padding:18px 20px;box-shadow:var(--sh-sm)}}
.stat-n{{font-size:26px;font-weight:700;letter-spacing:-.5px;line-height:1.1}}
.stat-l{{font-size:11px;color:var(--trt);text-transform:uppercase;
        letter-spacing:.7px;margin-top:4px;font-weight:500}}

/* SEC LABEL */
.sl{{font-size:11px;font-weight:600;letter-spacing:1.1px;text-transform:uppercase;
    color:var(--trt);margin-bottom:9px;padding-left:1px}}

/* CARDS */
.card{{background:var(--srf);border:1px solid var(--bdr);border-radius:var(--r);
      box-shadow:var(--sh-sm);overflow:hidden}}
.ch{{padding:14px 18px 11px;border-bottom:1px solid var(--bdr)}}
.ct{{font-size:13px;font-weight:600}}
.cb{{padding:16px 18px}}

/* GRID */
.g2{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
.mb{{margin-bottom:18px}}

/* TABLE */
.tw{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
thead th{{padding:9px 14px;text-align:left;font-size:11px;font-weight:600;
         letter-spacing:.4px;text-transform:uppercase;color:var(--trt);
         background:var(--srf2);border-bottom:1px solid var(--bdr)}}
tbody td{{padding:10px 14px;border-bottom:1px solid #F2F2F7;vertical-align:middle}}
.rs td{{background:#FAFAFA}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:#F0F8FF}}

/* UTIL */
.mono{{font-family:"SF Mono","Fira Code",Menlo,Consolas,monospace;
      font-size:12px;word-break:break-all}}
.dim{{color:var(--trt)}}
.badge{{display:inline-flex;align-items:center;padding:2px 8px;
       border-radius:6px;font-size:11px;font-weight:600;white-space:nowrap}}
.pill{{display:inline-block;padding:2px 8px;border-radius:20px;
      font-size:11px;font-weight:500;
      background:var(--g-bg);color:var(--g-dk);border:1px solid var(--g-bd)}}
.mpill{{display:inline-block;padding:2px 8px;border-radius:6px;
       font-size:11px;font-weight:600;border:1px solid transparent}}

/* KV */
.kv{{display:flex;align-items:flex-start;gap:12px;
    padding:10px 0;border-bottom:1px solid var(--bdr)}}
.kv:last-child{{border-bottom:none}}
.kv-lbl{{font-size:11px;font-weight:600;color:var(--trt);
        text-transform:uppercase;letter-spacing:.5px;
        min-width:104px;padding-top:1px}}
.kv-val{{color:var(--lbl);flex:1;font-size:13px}}

/* DNS BAR */
.dbar{{display:flex;align-items:center;gap:10px;
      padding:7px 0;border-bottom:1px solid #F2F2F7}}
.dbar:last-child{{border-bottom:none}}
.dbar-lbl{{font-size:12px;min-width:190px;color:var(--sec)}}
.dbar-track{{flex:1;height:5px;background:#F2F2F7;border-radius:3px;overflow:hidden}}
.dbar-fill{{height:100%;background:var(--g);border-radius:3px}}
.dbar-n{{font-size:12px;color:var(--trt);min-width:26px;text-align:right}}

/* EMPTY */
.empty{{padding:32px;text-align:center;color:var(--qat);
       font-size:13px;font-style:italic}}

/* FOOTER */
.footer{{margin-top:40px;padding-top:20px;border-top:1px solid var(--bdr);
        text-align:center;font-size:12px;color:var(--qat)}}

@media(max-width:768px){{
  .stats,.g2{{grid-template-columns:1fr}}
  .hero{{flex-direction:column}}
}}
</style>
</head>
<body>

<nav class="nav">
  <div class="nav-l">
    <div class="nav-dot"></div>
    <span class="nav-title">Network Forensic Analyser</span>
    <span class="nav-meta">tshark · Wireshark 4.6.4 · {ts}</span>
  </div>
  <div class="nav-chip">{sev_label}</div>
</nav>

<div class="w">

  <div class="hero mb">
    <div>
      <div class="hero-ey">Incident Analysis Report</div>
      <div class="hero-title">{summary['file']}</div>
      <div class="hero-meta">
        <span>{summary['packets']} packets</span>
        <span>{summary['duration']} capture</span>
        <span>{summary['size']}</span>
      </div>
      <div class="hero-meta" style="margin-top:3px">
        <span>Start: {summary['start']}</span>
        <span>End: {summary['end']}</span>
      </div>
      <div class="hero-status">
        {str(len(iocs)) + ' Indicators of Compromise detected' if iocs else 'No significant IOCs detected'}
      </div>
    </div>
    <div class="hero-sev">
      <div class="hero-sev-v">{sev_label}</div>
      <div class="hero-sev-s">SEVERITY</div>
    </div>
  </div>

  <div class="stats mb">
    <div class="stat">
      <div class="stat-n" style="color:var(--g)">{summary['packets']}</div>
      <div class="stat-l">Total Packets</div>
    </div>
    <div class="stat">
      <div class="stat-n" style="color:var(--blu)">{dns['total_queries']}</div>
      <div class="stat-l">DNS Queries</div>
    </div>
    <div class="stat">
      <div class="stat-n" style="color:var(--org)">{http['total_requests']}</div>
      <div class="stat-l">HTTP Requests</div>
    </div>
    <div class="stat">
      <div class="stat-n" style="color:{'var(--red)' if len(iocs)>5 else 'var(--g)'}">{len(iocs)}</div>
      <div class="stat-l">IOCs Found</div>
    </div>
  </div>

  <div class="sl">Host Identification</div>
  <div class="g2 mb">
    <div class="card">
      <div class="ch"><div class="ct">Victim Profile</div></div>
      <div class="cb">
        {'<div class="empty">No victim details found — Kerberos / DHCP not present</div>' if not (victim.get('hostname') or victim.get('username')) else victim_rows}
      </div>
    </div>
    <div class="card">
      <div class="ch"><div class="ct">Protocol Distribution</div></div>
      <div class="cb" style="display:flex;align-items:center;justify-content:center;min-height:220px">
        {'<div class="empty">No protocol data available</div>' if not protocols else '<canvas id="pc" style="max-height:220px"></canvas>'}
      </div>
    </div>
  </div>

  <div class="sl">Indicators of Compromise</div>
  <div class="card mb">
    <div class="ch"><div class="ct">All IOCs — sorted by severity</div></div>
    <div class="tw">
      {tbl(["Severity","Type","Value","Context"], ioc_rows) if iocs else NO}
    </div>
  </div>

  <div class="sl">DNS Analysis</div>
  <div class="g2 mb">
    <div class="card">
      <div class="ch"><div class="ct">Suspicious Queries</div></div>
      <div class="tw">
        {tbl(["Domain","Resolved IP","Reason","Sev."], dns_rows) if dns.get('suspicious') else NO}
      </div>
    </div>
    <div class="card">
      <div class="ch"><div class="ct">Top Queried Domains</div></div>
      <div class="cb">{top_dns if top_dns else NO}</div>
    </div>
  </div>

  <div class="sl">HTTP Analysis</div>
  <div class="card mb">
    <div class="ch"><div class="ct">Suspicious HTTP Requests</div></div>
    <div class="tw">
      {tbl(["Method","Host","URI","Reason"], http_rows) if http.get('suspicious') else NO}
    </div>
  </div>

  <div class="sl">TLS / Encrypted Traffic</div>
  <div class="g2 mb">
    <div class="card">
      <div class="ch"><div class="ct">Suspicious TLS Sessions</div></div>
      <div class="tw">
        {tbl(["Source","Destination","SNI","Reason"], tls_rows) if tls.get('suspicious') else NO}
      </div>
    </div>
    <div class="card">
      <div class="ch"><div class="ct">Repeated JA3 Fingerprints</div></div>
      <div class="tw">
        {tbl(["JA3 Hash","Count","Significance"], ja3_rows) if tls.get('repeated_ja3') else NO}
      </div>
    </div>
  </div>

  <div class="sl">External Connections</div>
  <div class="card mb">
    <div class="ch"><div class="ct">Top External IP Addresses</div></div>
    <div class="tw">
      {tbl(["IP Address","Connections","Type"], ext_rows) if conns.get('top_external_ips') else NO}
    </div>
  </div>

  <div class="footer">
    forensic.py &nbsp;·&nbsp; tshark / Wireshark 4.6.4
    &nbsp;·&nbsp; 21CSE381T Forensics &amp; Incident Response &nbsp;·&nbsp; SRM IST
  </div>
</div>

<script>
(function(){{
  const labels={proto_labels}, values={proto_values}, colors={proto_colors};
  if(!labels.length) return;
  const el=document.getElementById('pc');
  if(!el) return;
  new Chart(el,{{
    type:'doughnut',
    data:{{labels,datasets:[{{data:values,backgroundColor:colors,
      borderWidth:2,borderColor:'#fff',
      hoverBorderWidth:3,hoverBorderColor:'#fff'}}]}},
    options:{{
      responsive:true,maintainAspectRatio:true,cutout:'60%',
      plugins:{{
        legend:{{
          position:'right',
          labels:{{
            font:{{family:'-apple-system,BlinkMacSystemFont,"SF Pro Text",sans-serif',size:12}},
            color:'#3A3A3C',padding:14,
            usePointStyle:true,pointStyleWidth:8,
            generateLabels:function(chart){{
              return chart.data.labels.map(function(label,i){{
                const val=chart.data.datasets[0].data[i];
                const total=chart.data.datasets[0].data.reduce((a,b)=>a+b,0);
                const pct=((val/total)*100).toFixed(1);
                return{{
                  text:label+' '+pct+'%',
                  fillStyle:chart.data.datasets[0].backgroundColor[i],
                  strokeStyle:'#fff',
                  pointStyle:'circle',index:i
                }};
              }});
            }}
          }}
        }},
        tooltip:{{
          callbacks:{{
            label:function(c){{
              const total=c.dataset.data.reduce((a,b)=>a+b,0);
              const pct=((c.parsed/total)*100).toFixed(1);
              return' '+c.label+': '+c.parsed.toLocaleString()+' pkts ('+pct+'%)';
            }}
          }},
          backgroundColor:'rgba(255,255,255,.97)',
          titleColor:'#1D1D1F',bodyColor:'#3A3A3C',
          borderColor:'#E5E5EA',borderWidth:1,padding:10
        }}
      }}
    }}
  }});
}})();
</script>
</body>
</html>"""

# ─────────────────────────────────────────────────────────────────────────────
# TERMINAL
# ─────────────────────────────────────────────────────────────────────────────
G="\033[92m"; R="\033[91m"; Y="\033[93m"
C="\033[96m"; B="\033[1m";  D="\033[2m"; X="\033[0m"

def print_summary(summary, victim, iocs):
    print(f"\n{B}{C}  {'─'*52}{X}")
    print(f"  {B}ANALYSIS COMPLETE{X}")
    print(f"{C}  {'─'*52}{X}")
    for lbl, val in [("File",    summary['file']),
                     ("Packets", summary['packets']),
                     ("Duration",summary['duration']),
                     ("Start",   summary['start'])]:
        print(f"  {D}{lbl:10}{X} {val}")
    print(f"{C}  {'─'*52}{X}")
    if victim.get("hostname") or victim.get("username"):
        print(f"\n  {B}VICTIM{X}")
        for lbl, val in [("Hostname",victim.get("hostname")),
                         ("IP",      victim.get("ip")),
                         ("MAC",     victim.get("mac")),
                         ("Username",victim.get("username")),
                         ("OS",      victim.get("os_hint"))]:
            if val:
                print(f"  {D}{lbl:10}{X} {G}{val}{X}")
    if iocs:
        total = sum(i["score"] for i in iocs[:10])
        lbl, _ = severity_label(min(total // 3, 10))
        col = R if lbl in ("CRITICAL","HIGH") else Y
        print(f"\n  {B}IOCs{X}  [{col}{lbl}{X}]")
        for ioc in iocs[:8]:
            dot = f"{R}●{X}" if ioc["score"] >= 7 else f"{Y}●{X}"
            print(f"  {dot} {ioc['type']:22} {ioc['value'][:50]}")
    else:
        print(f"\n  {G}✓ No significant IOCs detected{X}")
    print(f"\n{C}  {'─'*52}{X}\n")

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def analyse(pcap_path):
    pcap = str(pcap_path)
    if not os.path.exists(pcap):
        print(f"{R}  ✗ Not found: {pcap}{X}"); return None
    print(f"\n{B}{C}  Analysing: {os.path.basename(pcap)}{X}")
    summary   = get_pcap_summary(pcap)
    protocols = get_protocol_stats(pcap)
    victim    = get_victim_profile(pcap)
    dns       = get_dns_analysis(pcap)
    http      = get_http_analysis(pcap)
    tls_data  = get_tls_analysis(pcap)
    conns     = get_connection_analysis(pcap)
    iocs      = get_ioc_summary(dns, http, tls_data, conns)
    print_summary(summary, victim, iocs)
    html = build_html(pcap, summary, protocols, victim,
                      dns, http, tls_data, conns, iocs)
    name = os.path.basename(pcap).replace(".pcap","")
    ts   = datetime.datetime.now().strftime("%H%M%S")
    out  = REPORT_DIR / f"report_{name}_{ts}.html"
    out.write_text(html, encoding="utf-8")
    print(f"  {G}✓ Report:{X} {out}")
    return str(out)

def main():
    print(f"""\n{B}{C}
  ╔══════════════════════════════════════════════════╗
  ║         Network Forensic Analyser  v2.0          ║
  ║            tshark / Wireshark 4.6.4              ║
  ║                 ©️sarthaksuwan                    ║
  ╚══════════════════════════════════════════════════╝
{X}""")
    if len(sys.argv) < 2:
        print(f"  Usage : python3 forensic.py file.pcap")
        print(f"  Batch : python3 forensic.py f1.pcap f2.pcap\n")
        sys.exit(1)
    reports = [r for r in (analyse(p) for p in sys.argv[1:]) if r]
    for r in reports:
        webbrowser.open(f"file://{os.path.abspath(r)}")
        print(f"  {C}↗ Opened:{X} {r}")
    print(f"\n  {G}Done — {len(reports)} report(s) generated.{X}\n")

if __name__ == "__main__":
    main()