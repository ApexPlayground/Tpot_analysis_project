#!/usr/bin/env python3
import os
import subprocess
from pathlib import Path
from datetime import datetime, timezone

REMOTE_USER = "ogbe2002"
REMOTE_HOST = "34.150.86.49"
REMOTE_PORT = "64295"
REMOTE_BASE = f"/home/{REMOTE_USER}/tpotce/data"
LOCAL_BASE = Path.home() / "Documents" / "tPot_project" / "tpot_mini_logs_asia"
LOGFILE = Path.home() / "sync_tpot_honeypots_only_asia.log"

SERVICES = [
    "adbhoney", "conpot", "elasticpot", "galah", "heralding", "ipphoney", "nginx",
    "suricata", "wordpot", "beelzebub", "cowrie", "elk", "glutton", "honeyaml",
    "log4pot", "p0f", "tanner", "blackhole", "ddospot", "endlessh", "go-pot",
    "honeypots", "mailoney", "redishoneypot", "tpot", "ciscoasa", "dicompot",
    "ews", "h0neytr4p", "honeysap", "medpot", "sentrypeer", "citrixhoneypot",
    "dionaea", "fatt", "hellpot", "honeytrap", "miniprint", "spiderfoot"
]

def log(msg):
    ts = datetime.now(timezone.utc).strftime("%F %T")
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOGFILE, "a") as f:
        f.write(line + "\n")

def main():
    log("==== honeypot sync run started ====")
    os.makedirs(LOCAL_BASE, exist_ok=True)

    for svc in SERVICES:
        log(f"Syncing: {svc}")
        local_dir = LOCAL_BASE / svc
        os.makedirs(local_dir, exist_ok=True)

        remote_path = f"{REMOTE_USER}@{REMOTE_HOST}:{REMOTE_BASE}/{svc}/log/"
        cmd = [
            "rsync", "-avz", "--partial", "--progress",
            "-e", f"ssh -p {REMOTE_PORT}",
            remote_path, str(local_dir)
        ]

        try:
            subprocess.run(cmd, check=True)
            log(f"Done: {svc}")
        except subprocess.CalledProcessError:
            log(f"WARNING: rsync failed or missing logs for {svc}, skipping.")

    log("==== honeypot sync finished ====")

if __name__ == "__main__":
    main()
