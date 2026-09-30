# 🛡️ SOC Sentinel — Automated Logfile Anomaly & Threat Classifier

A lightweight, Wazuh-style SIEM dashboard that combines an unsupervised **Isolation
Forest** anomaly detector (TF-IDF log-message embeddings) with **Sigma-style
detection rules mapped to MITRE ATT&CK** tactics/techniques and IOC extraction.

## Features
- Parses Windows/Sysmon text exports, Linux `auth.log`, Apache/Nginx access logs,
  SSH logs, and JSON lines into ECS-like structured fields.
- Unsupervised ML anomaly scoring (no labeled data required) via TF-IDF + Isolation Forest.
- 15 built-in Sigma-style rules across 9 MITRE ATT&CK tactics (Initial Access,
  Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access,
  Discovery, Lateral Movement, Command & Control, Impact).
- IOC extraction: IP addresses + suspicious command-line indicators.
- Wazuh-style dark dashboard: KPI cards, tactic donut chart, technique leaderboard,
  anomaly timeline, searchable/filterable event explorer with color-coded severity
  badges and an expandable JSON detail viewer.
- One-click demo dataset with embedded attack scenarios (SSH brute force, PowerShell
  encoded execution, web shell + SQLi, port scan, C2 beacon, lateral movement,
  ransomware indicators, credential dumping).
- Export enriched results as CSV or JSON; one-click MITRE incident summary.

## Run locally

```bash
pip install -r requirements.txt
streamlit run app.py
```

Then open http://localhost:8501, click **Load Demo Dataset** in the sidebar, and
hit **Run Analysis Pipeline** — or upload your own `.log` / `.txt` / `.json` files.

## Run with Docker

```bash
docker build -t soc-dashboard .
docker run -p 8501:8501 soc-dashboard
```

Open http://localhost:8501.

## Deploy to Render / Railway / any container host

The Dockerfile respects the `$PORT` environment variable injected by most PaaS
providers (Render, Railway, Heroku-style buildpacks), so no config changes are
needed — just point the platform at this repo/Dockerfile and deploy.

## Project structure

```
soc-dashboard/
├── app.py                 # Streamlit dashboard (UI + orchestration)
├── core/
│   ├── parser.py           # Log Parser Module — normalizes raw logs to ECS-like fields
│   ├── ml_engine.py         # TF-IDF + Isolation Forest anomaly detector
│   ├── mitre_rules.py       # Sigma-style rule set mapped to MITRE ATT&CK
│   ├── enricher.py          # MITRE & IOC enrichment engine
│   └── demo_data.py         # Synthetic multi-format demo log generator
├── assets/
│   └── style.css            # Wazuh-inspired dark theme
├── requirements.txt
├── Dockerfile
└── .dockerignore
```

## Tuning

- **Contamination Rate** (0.01–0.20): expected proportion of anomalous events —
  raise it if you expect a noisier/dirtier log source, lower it for tight production baselines.
- **Strict Rule Sensitivity**: toggling ON makes MITRE rule matching case-sensitive
  (fewer, higher-confidence hits); OFF is case-insensitive/broader matching.

## Extending

- Add new detection rules in `core/mitre_rules.py` — just append a dict with
  `rule_id`, `name`, `tactic`, `technique_id`, `technique_name`, `pattern` (regex), `severity_weight`.
- Add new log format parsers in `core/parser.py` inside `parse_line()`.
