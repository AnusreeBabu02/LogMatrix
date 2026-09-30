"""
MITRE & IOC Enricher
---------------------
Evaluates each normalized log event against the Sigma-style rule set (mitre_rules.py),
tagging matched MITRE ATT&CK tactics/techniques and extracting IOCs (IP addresses,
suspicious command-line indicators).
"""

import re
from core.mitre_rules import RULES, IOC_KEYWORDS

RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _compile_rules(strict: bool):
    """Compile rule regexes. Strict mode = case-sensitive + requires word boundary
    around the first alternative token (reduces false positives)."""
    compiled = []
    for r in RULES:
        flags = 0 if strict else re.IGNORECASE
        compiled.append({**r, "_re": re.compile(r["pattern"], flags)})
    return compiled


def enrich_event(record, compiled_rules):
    """Return (mitre_hits, iocs) for a single parsed log record."""
    text = f'{record.get("message","")} {record.get("raw","")}'

    mitre_hits = []
    for rule in compiled_rules:
        if rule["_re"].search(text):
            mitre_hits.append({
                "rule_id": rule["rule_id"],
                "rule_name": rule["name"],
                "tactic": rule["tactic"],
                "technique_id": rule["technique_id"],
                "technique_name": rule["technique_name"],
                "severity_weight": rule["severity_weight"],
            })

    ips = sorted(set(RE_IP.findall(text)))
    indicators = sorted({kw for kw in IOC_KEYWORDS if kw.lower() in text.lower()})

    iocs = {"ips": ips, "indicators": indicators}
    return mitre_hits, iocs


def enrich_dataframe(df, strict_sensitivity=False):
    """Apply MITRE + IOC enrichment across an entire dataframe of parsed log records.
    Adds columns: mitre_hits, iocs, mitre_technique_ids, tactic_list, ioc_ip_count.
    """
    compiled_rules = _compile_rules(strict_sensitivity)

    mitre_hits_col, iocs_col, technique_ids_col, tactics_col, ip_count_col = [], [], [], [], []

    for _, row in df.iterrows():
        hits, iocs = enrich_event(row.to_dict(), compiled_rules)
        mitre_hits_col.append(hits)
        iocs_col.append(iocs)
        technique_ids_col.append([h["technique_id"] for h in hits])
        tactics_col.append([h["tactic"] for h in hits])
        ip_count_col.append(len(iocs["ips"]))

    df = df.copy()
    df["mitre_hits"] = mitre_hits_col
    df["iocs"] = iocs_col
    df["technique_ids"] = technique_ids_col
    df["tactics"] = tactics_col
    df["ioc_ip_count"] = ip_count_col
    return df
