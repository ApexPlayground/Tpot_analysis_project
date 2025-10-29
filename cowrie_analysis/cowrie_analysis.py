import json
import glob
import os
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from tqdm import tqdm
import geoip2.database


# Path setup
BASE_DIR = os.path.dirname(__file__)          
LOG_DIR = os.path.join(BASE_DIR, "logs")      
OUTPUT_DIR = os.path.join(BASE_DIR, "cowrie_output")  
os.makedirs(OUTPUT_DIR, exist_ok=True)
GEOIP_DB = '/home/divine/Documents/Network Security/analysis_project/cowrie_analysis/GeoLite2-Country.mmdb'

# Find all Cowrie daily JSON logs
log_files = sorted(glob.glob(os.path.join(LOG_DIR, "cowrie.json.20*")))
print(f"Found {len(log_files)} Cowrie log files\n")

rows = []

# Parse JSON lines from each file
for file in tqdm(log_files, desc="Parsing logs"):
    day = os.path.basename(file).split(".")[-1]
    with open(file) as f:
        for line in f:
            try:
                j = json.loads(line)
                rows.append({
                    "date": day,
                    "timestamp": j.get("timestamp"),
                    "eventid": j.get("eventid"),
                    "src_ip": j.get("src_ip"),
                    "username": j.get("username"),
                    "password": j.get("password"),
                    "input": j.get("input"),
                    "message": j.get("message")
                })
            except Exception:
                continue

# Convert to DataFrame and clean timestamps
df = pd.DataFrame(rows)
df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
df = df.dropna(subset=["timestamp"])
print(f"Parsed {len(df):,} total events\n")

# Save full structured log
df.to_csv(os.path.join(OUTPUT_DIR, "cowrie_parsed_full.csv"), index=False)

# Overview counts
total_ips = df["src_ip"].nunique()
print(f"Total events: {len(df):,}")
print(f"Unique attacking IPs: {total_ips:,}\n")

# Plot daily SSH activity
daily = df.groupby(df["timestamp"].dt.date).size()
daily.index = pd.to_datetime(daily.index)

fig, ax = plt.subplots(figsize=(10, 5))
ax.plot(daily.index, daily.values, linewidth=1.8, color="#2E6FBA")
ax.set_title("Daily SSH Connections (Cowrie)")
ax.set_ylabel("Connection Count")

locator = mdates.AutoDateLocator()
formatter = mdates.ConciseDateFormatter(locator)
ax.xaxis.set_major_locator(locator)
ax.xaxis.set_major_formatter(formatter)
plt.setp(ax.get_xticklabels(), rotation=30, ha="right")

plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "cowrie_daily_activity.png"), dpi=150)
plt.close()

# Top attacking IPs
top_ips = df["src_ip"].value_counts().head(10)
top_ips.to_csv(os.path.join(OUTPUT_DIR, "cowrie_top_ips.csv"))
plt.figure(figsize=(8, 4))
top_ips.plot(kind="bar", color="#2E6FBA")
plt.title("Top 10 Attacker IPs")
plt.ylabel("Connections")
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "cowrie_top_ips.png"), dpi=150)
plt.close()

# Separate failed vs successful login attempts
failed = df[df["eventid"] == "cowrie.login.failed"]
success = df[df["eventid"] == "cowrie.login.success"]

print(f"Failed login attempts: {len(failed):,}")
print(f"Successful logins: {len(success):,}\n")

# Top usernames used in brute-force
usernames = failed["username"].value_counts().head(10)
usernames.to_csv(os.path.join(OUTPUT_DIR, "cowrie_top_usernames.csv"))
plt.figure(figsize=(8, 4))
usernames.plot(kind="bar", color="#2E6FBA")
plt.title("Top Usernames Attempted")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "cowrie_top_usernames.png"), dpi=150)
plt.close()

# Top passwords
passwords = failed["password"].value_counts().head(10)
passwords.to_csv(os.path.join(OUTPUT_DIR, "cowrie_top_passwords.csv"))
plt.figure(figsize=(8, 4))
passwords.plot(kind="bar", color="#2E6FBA")
plt.title("Top Passwords Attempted")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "cowrie_top_passwords.png"), dpi=150)
plt.close()

# Commands executed after successful login
cmds = df[df["eventid"] == "cowrie.command.input"]
cmd_counts = cmds["input"].value_counts().head(15)
cmd_counts.to_csv(os.path.join(OUTPUT_DIR, "cowrie_top_commands.csv"))

plt.figure(figsize=(10, 6))
cmd_counts.plot(kind="barh", color="#2E6FBA")
plt.title("Top Commands Executed by Attackers")
plt.xlabel("Count")
plt.yticks(fontsize=8)
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "cowrie_top_commands.png"), dpi=150)
plt.close()

# Print quick summary
print("Top 5 Usernames:\n", usernames.head().to_string(), "\n")
print("Top 5 Passwords:\n", passwords.head().to_string(), "\n")
print("Top 5 Commands:\n", cmd_counts.head().to_string(), "\n")

# GeoIP lookup (Top attacker countries)
if os.path.exists(GEOIP_DB):
    print("Performing GeoIP country lookup...")
    reader = geoip2.database.Reader(GEOIP_DB)

    def ip_to_country(ip):
        try:
            return reader.country(ip).country.iso_code
        except:
            return "UNK"

    df['country'] = df['src_ip'].apply(ip_to_country)
    country_counts = df['country'].value_counts().head(10)
    country_counts.to_csv(os.path.join(OUTPUT_DIR, "cowrie_top_countries.csv"))

    plt.figure(figsize=(8, 4))
    country_counts.plot(kind='bar', color="#2E6FBA", title='Top Attacker Countries')
    plt.ylabel("Connection Count")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "cowrie_top_countries.png"), dpi=150)
    plt.close()
    print("Saved cowrie_top_countries.png\n")
else:
    print("GeoLite2-Country.mmdb not found. Skipping GeoIP lookup.\n")

print("Analysis Complete. Files saved to:", OUTPUT_DIR)
print("\nGenerated files:")
print("  • cowrie_parsed_full.csv")
print("  • cowrie_daily_activity.png")
print("  • cowrie_top_ips.png")
print("  • cowrie_top_usernames.png")
print("  • cowrie_top_passwords.png")
print("  • cowrie_top_commands.png")
print("  • cowrie_top_countries.png")
