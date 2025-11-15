#!/usr/bin/env python3
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

REMOTE_USER = "ogbe2002"
REMOTE_HOST = "34.140.69.173"
REMOTE_PORT = "64295"
REMOTE_BASE = f"/home/{REMOTE_USER}/tpotce/data"
LOCAL_BASE = Path.home() / "Documents" / "tPot_project" / "tpot_logs"
LOGFILE = Path.home() / "sync_tpot_honeypots_only.log"

SERVICES = [
    "adbhoney", "beelzebub", "blackhole", "ciscoasa", "citrixhoneypot", "conpot",
    "ddospot", "dicompot", "dionaea", "elasticpot", "endlessh", "ews", "glutton",
    "go-pot", "galah", "heralding", "honeyaml", "honeysap", "honeytrap", "ipphoney",
    "log4pot", "mailoney", "miniprint", "nginx", "redishoneypot", "sentrypeer",
    "tanner", "cowrie", "wordpot", "hellpot"
]

def log(msg):
    ts = datetime.now(timezone.utc).strftime("%F %T")
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOGFILE, "a") as f:
        f.write(line + "\n")

def main():
    log("==== honeypot sync started ====")
    os.makedirs(LOCAL_BASE, exist_ok=True)

    for svc in SERVICES:
        log(f"Syncing: {svc}")
        local_dir = LOCAL_BASE / svc
        os.makedirs(local_dir, exist_ok=True)
        remote = f"{REMOTE_USER}@{REMOTE_HOST}:{REMOTE_BASE}/{svc}/log/"

        cmd = [
            "rsync", "-avz", "--partial", "--progress",
            "-e", f"ssh -p {REMOTE_PORT}",
            remote, str(local_dir)
        ]

        try:
            subprocess.run(cmd, check=True)
            log(f"Done: {svc}")
        except subprocess.CalledProcessError:
            log(f"WARNING: Failed or missing logs for {svc}, skipping.")

    log("==== honeypot sync finished ====")

if __name__ == "__main__":
    main()
