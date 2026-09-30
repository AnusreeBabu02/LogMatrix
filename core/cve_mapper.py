"""
CVE Mapper
-----------
Maps log events to known CVEs using (1) exploit-attempt signatures and
(2) software version banners checked against vulnerable ranges.
Fully offline. Extend CVE_INFO / SIGNATURES / VERSION_RULES to add coverage.
"""

import re
from urllib.parse import unquote

NVD_URL = "https://nvd.nist.gov/vuln/detail/{}"
RE_CVE_LITERAL = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# cve_id -> (name, CVSS v3 base score)
CVE_INFO = {
    "CVE-2021-44228": ("Log4Shell: Log4j JNDI RCE", 10.0),
    "CVE-2014-6271":  ("Shellshock: Bash env-var RCE", 9.8),
    "CVE-2021-41773": ("Apache 2.4.49 path traversal / RCE", 7.5),
    "CVE-2021-42013": ("Apache 2.4.49-2.4.50 path traversal / RCE", 9.8),
    "CVE-2022-22965": ("Spring4Shell: Spring Framework RCE", 9.8),
    "CVE-2022-22963": ("Spring Cloud Function SpEL injection", 9.8),
    "CVE-2017-5638":  ("Apache Struts2 Jakarta multipart RCE", 10.0),
    "CVE-2022-26134": ("Atlassian Confluence OGNL injection", 9.8),
    "CVE-2022-42889": ("Text4Shell: Apache Commons Text RCE", 9.8),
    "CVE-2024-4577":  ("PHP-CGI argument injection (Windows)", 9.8),
    "CVE-2023-34362": ("MOVEit Transfer SQLi / web shell", 9.8),
    "CVE-2020-1472":  ("Zerologon: Netlogon privilege escalation", 10.0),
    "CVE-2021-34527": ("PrintNightmare: Print Spooler RCE", 8.8),
    "CVE-2017-0144":  ("EternalBlue: SMBv1 RCE (MS17-010)", 8.1),
    "CVE-2019-0708":  ("BlueKeep: RDP RCE", 9.8),
    "CVE-2021-4034":  ("PwnKit: polkit pkexec local privesc", 7.8),
    "CVE-2021-3156":  ("Baron Samedit: sudoedit heap overflow", 7.8),
    "CVE-2024-6387":  ("regreSSHion: OpenSSH sshd race condition", 8.1),
    "CVE-2014-0160":  ("Heartbleed: OpenSSL information disclosure", 7.5),
    "CVE-2021-34473": ("ProxyShell: Exchange pre-auth RCE", 9.8),
}

# (cve_id, regex) -> exploit-attempt evidence (matched against raw + URL-decoded text)
SIGNATURES = [
    ("CVE-2021-44228", r"\$\{\s*jndi\s*:|\$\{\$\{[^}]{1,30}\}[^}]{0,30}ndi"),
    ("CVE-2014-6271",  r"\(\)\s*\{\s*:?\s*;\s*\}\s*;"),
    ("CVE-2021-41773", r"/(?:cgi-bin|icons)/(?:\.%2e|%2e%2e|%2e\.)/"),
    ("CVE-2021-42013", r"%%32%65"),
    ("CVE-2022-22965", r"class\.module\.classLoader"),
    ("CVE-2022-22963", r"spring\.cloud\.function\.routing-expression"),
    ("CVE-2017-5638",  r"#_memberAccess|%\{\(#_='multipart/form-data'\)"),
    ("CVE-2022-26134", r"/\$\{.{0,80}(?:getRuntime|ProcessBuilder)"),
    ("CVE-2022-42889", r"\$\{(?:script|dns|url):"),
    ("CVE-2024-4577",  r"php-cgi(?:\.exe)?\?.*%ad"),
    ("CVE-2023-34362", r"human2\.aspx"),
    ("CVE-2020-1472",  r"zerologon|netlogon.*(?:5829|vulnerable netlogon secure channel)"),
    ("CVE-2021-34527", r"printnightmare|spoolsv\.exe.*(?:\.dll|rundll32)|AddPrinterDriverEx"),
    ("CVE-2017-0144",  r"ms17-010|eternalblue|doublepulsar"),
    ("CVE-2019-0708",  r"bluekeep|ms_t120"),
    ("CVE-2021-4034",  r"pkexec.*(?:SHELL variable was not found|contains suspicious content)"),
    ("CVE-2021-3156",  r"sudoedit\s+-s\b.*\\"),
    ("CVE-2014-0160",  r"heartbleed"),
    ("CVE-2021-34473", r"/autodiscover/autodiscover\.json.*(?:@|%40).*(?:/powershell|/mapi|/ecp)"),
]
_COMPILED_SIGS = [(cid, re.compile(p, re.IGNORECASE)) for cid, p in SIGNATURES]


def _v(*nums):
    return tuple(int(n) for n in nums)


def _apache(m):
    return {"2.4.49": ["CVE-2021-41773", "CVE-2021-42013"], "2.4.50": ["CVE-2021-42013"]}.get(m.group(1), [])

def _openssh(m):  # regreSSHion affects 8.5p1 .. 9.7p1
    return ["CVE-2024-6387"] if _v(8, 5) <= _v(m.group(1), m.group(2)) <= _v(9, 7) else []

def _openssl(m):  # Heartbleed: 1.0.1 through 1.0.1f
    return ["CVE-2014-0160"] if m.group(1) <= "f" else []

def _log4j(m):    # log4j-core 2.0-beta9 .. 2.14.1
    return ["CVE-2021-44228"] if int(m.group(1)) <= 14 else []

VERSION_RULES = [
    ("Apache httpd", re.compile(r"Apache/(\d+\.\d+\.\d+)"), _apache),
    ("OpenSSH",      re.compile(r"OpenSSH[_ ](\d+)\.(\d+)"), _openssh),
    ("OpenSSL",      re.compile(r"OpenSSL[/ ]1\.0\.1([a-z]?)\b", re.IGNORECASE), _openssl),
    ("Log4j",        re.compile(r"log4j-core-2\.(\d+)", re.IGNORECASE), _log4j),
]


def _severity(cvss):
    if cvss is None:
        return "Unknown"
    return "Critical" if cvss >= 9 else "High" if cvss >= 7 else "Medium" if cvss >= 4 else "Low"


def _hit(cve_id, evidence, matched):
    name, cvss = CVE_INFO.get(cve_id.upper(), ("Referenced in log", None))
    return {
        "cve_id": cve_id.upper(), "name": name, "cvss": cvss,
        "severity": _severity(cvss), "evidence": evidence,
        "matched": matched[:80], "url": NVD_URL.format(cve_id.upper()),
    }


def map_cves(text):
    """Return a list of CVE hit dicts for one log event's text."""
    haystacks = [text, unquote(text)]
    hits, seen = [], set()

    def add(h):
        key = (h["cve_id"], h["evidence"])
        if key not in seen:
            seen.add(key)
            hits.append(h)

    for cid, rx in _COMPILED_SIGS:
        for hay in haystacks:
            m = rx.search(hay)
            if m:
                add(_hit(cid, "exploit_attempt", m.group(0)))
                break

    for product, rx, check in VERSION_RULES:
        m = rx.search(text)
        if m:
            for cid in check(m):
                add(_hit(cid, "vulnerable_version", f"{product}: {m.group(0)}"))

    for lit in RE_CVE_LITERAL.findall(text):
        if not any(h["cve_id"] == lit.upper() for h in hits):
            add(_hit(lit, "mentioned", lit))
    return hits


def enrich_cves(df):
    """Adds columns: cve_hits (list[dict]), cve_ids (list[str]), max_cvss (float)."""
    df = df.copy()
    texts = (df["message"].fillna("").astype(str) + " " + df["raw"].fillna("").astype(str))
    df["cve_hits"] = texts.apply(map_cves)
    df["cve_ids"] = df["cve_hits"].apply(lambda hs: sorted({h["cve_id"] for h in hs}))
    df["max_cvss"] = df["cve_hits"].apply(lambda hs: max([h["cvss"] or 0 for h in hs], default=0.0))
    return df
