import os
import json
import gzip
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
import geoip2.database

# geoip
try:
    from geoip2.database import Reader
    GEOIP_ENABLED = True
except ImportError:
    GEOIP_ENABLED = False

# path setup
BASE_DIR = os.path.dirname(__file__)
LOG_DIR = os.path.join(BASE_DIR, "logs")
OUTPUT_DIR = os.path.join(BASE_DIR, "santrypeer_output")
os.makedirs(OUTPUT_DIR, exist_ok=True)
GEOIP_DB = '/home/divine/Documents/Network Security/analysis_project/cowrie_analysis/GeoLite2-Country.mmdb'

# load logs
def load_sentrypeer_logs(LOG_DIR):
    records = []
    for root, _, files in os.walk(LOG_DIR):
        for file in files:
            if file.endswith(".gz"):
                with gzip.open(os.path.join(root, file), "rt", encoding="utf-8") as f:
                    for line in f:
                        try:
                            data = json.loads(line.strip())
                            records.append(data)
                        except json.JSONDecodeError:
                            continue
    return pd.DataFrame(records)

# geoip lookup
def resolve_country(ip, reader):
    try:
        return reader.country(ip).country.name
    except Exception:
        return "unknown"

# main analysis
def main():
    print("[+] loading sentrypeer logs...")
    df = load_sentrypeer_logs(LOG_DIR)
    print(f"[+] loaded {len(df)} entries")

    # split source ip and port
    df[["src_ip", "src_port"]] = df["source_ip"].str.split(":", expand=True)
    df["event_timestamp"] = pd.to_datetime(df["event_timestamp"])
    df["date"] = df["event_timestamp"].dt.date

    # daily activity
    daily = df.groupby("date").size()
    plt.figure(figsize=(10, 5))
    daily.plot(kind="line", marker="o", linewidth=2)
    plt.title("daily sip activity recorded by sentrypeer")
    plt.xlabel("date")
    plt.ylabel("number of events")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "sentrypeer_daily_activity.png"), dpi=300)
    plt.close()

    # top source ips
    top_ips = df["src_ip"].value_counts().head(10)
    plt.figure(figsize=(10, 5))
    top_ips.plot(kind="barh")
    plt.title("top 10 source ips (sip attackers)")
    plt.xlabel("number of requests")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "sentrypeer_top_ips.png"), dpi=300)
    plt.close()

    # top sip user agents
    top_agents = df["sip_user_agent"].value_counts().head(10)
    plt.figure(figsize=(10, 5))
    top_agents.plot(kind="barh")
    plt.title("top 10 sip user-agents observed")
    plt.xlabel("count")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "sentrypeer_top_useragents.png"), dpi=300)
    plt.close()

    # top called numbers
    top_numbers = df["called_number"].value_counts().head(10)
    plt.figure(figsize=(10, 5))
    top_numbers.plot(kind="barh")
    plt.title("top 10 called numbers (targets)")
    plt.xlabel("count")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "sentrypeer_top_called_numbers.png"), dpi=300)
    plt.close()

    # geoip analysis
    print("[+] resolving geoip...")
    reader = geoip2.database.Reader(GEOIP_DB)
    df["country"] = df["src_ip"].apply(lambda ip: resolve_country(ip, reader))
    reader.close()

    country_counts = df["country"].value_counts().head(10)
    plt.figure(figsize=(10, 5))
    country_counts.plot(kind="barh")
    plt.title("top 10 source countries of sip attempts")
    plt.xlabel("number of events")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "sentrypeer_top_countries.png"), dpi=300)
    plt.close()

    # summary statistics
    print("\n=== summary ===")
    print("total events:", len(df))
    print("unique source ips:", df["src_ip"].nunique())
    print("unique user-agents:", df["sip_user_agent"].nunique())
    print("unique called numbers:", df["called_number"].nunique())
    print("top source ips:\n", top_ips)
    print("top countries:\n", country_counts)
    print(f"\nsaved figures in: {OUTPUT_DIR}")

if __name__ == "__main__":
    main()
