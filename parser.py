"""
Log Parser Module
------------------
Normalizes unstructured log entries (Windows/Sysmon text export, Linux auth.log,
Apache/Nginx access logs, SSH logs, generic JSON lines) into structured ECS-like
fields: timestamp, host, process, pid, user, message, raw, source_type.
"""

import re
import json
import uuid
from datetime import datetime
from dateutil import parser as dtparser

CURRENT_YEAR = datetime.now().year

# ---------------------------------------------------------------------------
# Regex patterns for known log formats
# ---------------------------------------------------------------------------

# Linux syslog / auth.log:  "Jan 15 10:23:11 ip-10-0-1-5 sshd[1234]: Failed password ..."
RE_SYSLOG = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[\w\-.]+)\s+(?P<process>[\w\-./]+)(\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

# Apache / Nginx combined log format
RE_ACCESS_LOG = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

# Sysmon-style key=value export:
# "2024-01-15 10:23:11 HOST=WIN-SRV01 PROC=powershell.exe PID=4521 CMD="powershell -enc ..." USER=jdoe"
RE_KV = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+'
    r'HOST=(?P<host>\S+)\s+PROC=(?P<process>\S+)\s+PID=(?P<pid>\d+)\s+'
    r'CMD="(?P<cmd>[^"]*)"\s+USER=(?P<user>\S+)'
)

RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_LEADING_TS = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(\.\d+)?)")


def _new_id():
    return uuid.uuid4().hex[:10]


def _safe_ts(ts_str, default=None):
    try:
        dt = dtparser.parse(ts_str, fuzzy=True)
        if dt.year == 1900:  # syslog lines with no year -> assume current year
            dt = dt.replace(year=CURRENT_YEAR)
        if dt.tzinfo is not None:
            # Normalize to naive (drop UTC offset) so all timestamps across
            # different log formats (e.g. Apache/Nginx "+0000") remain sortable
            # and comparable against naive timestamps from other parsers.
            dt = dt.replace(tzinfo=None)
        return dt
    except Exception:
        return default or datetime.now()


def _base_record(raw, source_type):
    return {
        "event_id": _new_id(),
        "timestamp": None,
        "host": "unknown-host",
        "process": "unknown",
        "pid": None,
        "user": None,
        "message": raw,
        "raw": raw,
        "source_type": source_type,
    }


def parse_line(line):
    """Parse a single raw log line into a normalized ECS-like dict, or None if blank."""
    line = line.rstrip("\n")
    if not line.strip():
        return None

    stripped = line.strip()

    # ---- JSON line -------------------------------------------------------
    if stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
            rec = _base_record(stripped, "json")
            rec["timestamp"] = _safe_ts(str(obj.get("timestamp") or obj.get("time") or obj.get("@timestamp") or ""))
            rec["host"] = obj.get("host") or obj.get("hostname") or obj.get("computer") or rec["host"]
            rec["process"] = obj.get("process") or obj.get("image") or obj.get("program") or rec["process"]
            rec["pid"] = obj.get("pid")
            rec["user"] = obj.get("user") or obj.get("username")
            rec["message"] = str(obj.get("message") or obj.get("cmdline") or obj.get("msg") or stripped)
            return rec
        except Exception:
            pass  # fall through to other parsers

    # ---- Sysmon-style KV ---------------------------------------------------
    m = RE_KV.match(stripped)
    if m:
        d = m.groupdict()
        rec = _base_record(stripped, "sysmon")
        rec["timestamp"] = _safe_ts(d["ts"])
        rec["host"] = d["host"]
        rec["process"] = d["process"]
        rec["pid"] = d["pid"]
        rec["user"] = d["user"]
        rec["message"] = f'{d["process"]} {d["cmd"]}'
        return rec

    # ---- Linux syslog / auth.log -------------------------------------------
    m = RE_SYSLOG.match(stripped)
    if m:
        d = m.groupdict()
        rec = _base_record(stripped, "syslog")
        ts_guess = f"{d['mon']} {d['day']} {CURRENT_YEAR} {d['time']}"
        rec["timestamp"] = _safe_ts(ts_guess)
        rec["host"] = d["host"]
        rec["process"] = d["process"]
        rec["pid"] = d.get("pid")
        rec["message"] = d["message"]
        # try to recover username / source ip mentioned in message
        um = re.search(r"user\s+(\S+)", d["message"], re.IGNORECASE)
        if um:
            rec["user"] = um.group(1)
        return rec

    # ---- Apache / Nginx access log -----------------------------------------
    m = RE_ACCESS_LOG.match(stripped)
    if m:
        d = m.groupdict()
        rec = _base_record(stripped, "web-access")
        rec["timestamp"] = _safe_ts(d["ts"].replace(":", " ", 1))
        rec["host"] = "web-server"
        rec["process"] = "httpd"
        rec["user"] = d["ip"]
        rec["message"] = f'{d["ip"]} "{d["request"]}" {d["status"]}'
        return rec

    # ---- Generic fallback ---------------------------------------------------
    rec = _base_record(stripped, "generic")
    ts_match = RE_LEADING_TS.match(stripped)
    rec["timestamp"] = _safe_ts(ts_match.group("ts")) if ts_match else datetime.now()
    ip_match = RE_IP.search(stripped)
    host_match = re.search(r"\b([\w\-]+-(?:srv|host|dc|ws|gw)\d*)\b", stripped, re.IGNORECASE)
    if host_match:
        rec["host"] = host_match.group(1)
    elif ip_match:
        rec["host"] = ip_match.group(0)
    rec["message"] = stripped
    return rec


def parse_log_text(text):
    """Parse a multi-line blob of raw log text into a list of normalized records."""
    records = []
    for line in text.splitlines():
        rec = parse_line(line)
        if rec:
            records.append(rec)
    return records
