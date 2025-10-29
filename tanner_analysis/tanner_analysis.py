import os, gzip, json, pandas as pd, matplotlib.pyplot as plt
import matplotlib.dates as mdates

# Optional GeoIP (you can skip if not using)
try:
    from geoip2.database import Reader
    GEOIP_ENABLED = True
except ImportError:
    GEOIP_ENABLED = False

# Paths
LOG_DIR = "logs/"
OUTPUT_DIR = "tanner_output"
GEO_DB_PATH = "/home/divine/Documents/Network Security/analysis_project/tanner_analysis/GeoLite2-City.mmdb"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Global style (white background + blue accents)
plt.rcParams.update({
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "axes.edgecolor": "black",
    "axes.labelcolor": "black",
    "xtick.color": "black",
    "ytick.color": "black",
    "figure.dpi": 150,
})
COLOR = "#2E6FBA"  # main blue color

# Helper to save plots
def save_plot(ax, name):
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, name))
    plt.close()

# Read Tanner logs (both .json and .gz)
records = []
for file in sorted(os.listdir(LOG_DIR)):
    if not file.startswith("tanner_report.json"):
        continue
    opener = gzip.open if file.endswith(".gz") else open
    with opener(os.path.join(LOG_DIR, file), "rt", encoding="utf-8") as f:
        for line in f:
            try:
                d = json.loads(line)
                records.append({
                    "timestamp": d.get("timestamp"),
                    "ip": d.get("peer", {}).get("ip"),
                    "method": d.get("method"),
                    "path": d.get("path"),
                    "status": d.get("status"),
                    "user_agent": d.get("headers", {}).get("user-agent", "N/A"),
                    "detection": d.get("response_msg", {}).get("response", {}).get("message", {}).get("detection", {}).get("name", "N/A")
                })
            except:
                continue

# Convert to DataFrame
df = pd.DataFrame(records)
df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
df.dropna(subset=["timestamp"], inplace=True)
df["date"] = df["timestamp"].dt.date
df["hour"] = df["timestamp"].dt.hour

print(f"Loaded {len(df)} Tanner records")

# -------------------- #
# Visualization Section
# -------------------- #

# 1. Daily request trends
daily = df.groupby("date").size()
fig, ax = plt.subplots(figsize=(8, 4))
ax.plot(daily.index, daily.values, color=COLOR, linewidth=2)
ax.set_title("Daily Tanner HTTP Requests", fontsize=12)
ax.set_xlabel("Date")
ax.set_ylabel("Requests")
ax.xaxis.set_major_locator(mdates.AutoDateLocator())
ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
plt.xticks(rotation=45, ha="right")
save_plot(ax, "daily.png")

# 2. Top 10 source IPs
fig, ax = plt.subplots(figsize=(8, 4))
top_ips = df["ip"].value_counts().head(10)
ax.bar(top_ips.index, top_ips.values, color=COLOR)
ax.set_title("Top Source IPs", fontsize=12)
ax.set_xlabel("IP Address")
ax.set_ylabel("Request Count")
plt.xticks(rotation=30, ha="right", fontsize=8)
save_plot(ax, "top_ips.png")

# 3. Top requested paths
fig, ax = plt.subplots(figsize=(8, 5))
top_paths = df["path"].value_counts().head(10)
ax.barh(top_paths.index, top_paths.values, color=COLOR)
ax.set_title("Top Requested Paths", fontsize=12)
ax.set_xlabel("Request Count")
ax.invert_yaxis()
save_plot(ax, "top_paths.png")

# 4. Detection types
top_det = df["detection"].value_counts().head(10)
if not top_det.empty:
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.barh(top_det.index, top_det.values, color=COLOR)
    ax.set_title("Top Detection Types", fontsize=12)
    ax.set_xlabel("Count")
    ax.invert_yaxis()
    save_plot(ax, "detections.png")

# HTTP Method Distribution
methods = df["method"].value_counts()
fig, ax = plt.subplots(figsize=(7, 4))
ax.bar(methods.index, methods.values, color=COLOR)
ax.set_title("HTTP Methods", fontsize=12)
ax.set_xlabel("Method")
ax.set_ylabel("Request Count")
plt.xticks(rotation=20, ha="right")
save_plot(ax, "methods.png")


# 6. HTTP status codes
fig, ax = plt.subplots(figsize=(7, 4))
status = df["status"].value_counts().sort_index()
ax.bar(status.index.astype(str), status.values, color=COLOR)
ax.set_title("HTTP Status Codes", fontsize=12)
ax.set_xlabel("Status Code")
ax.set_ylabel("Count")
save_plot(ax, "status.png")

# Top user agents
import textwrap

uas = df["user_agent"].value_counts().head(10)

# wrap each long user-agent string to multiple lines
wrapped_labels = [ "\n".join(textwrap.wrap(label, width=60)) for label in uas.index ]
fig, ax = plt.subplots(figsize=(10, 6))
ax.barh(range(len(uas)), uas.values, color=COLOR)
ax.set_yticks(range(len(uas)))
ax.set_yticklabels(wrapped_labels, fontsize=8)
ax.set_title("Top User Agents", fontsize=12)
ax.set_xlabel("Request Count")
ax.invert_yaxis()
plt.subplots_adjust(left=0.45, right=0.95, top=0.9, bottom=0.1)
save_plot(ax, "user_agents.png")

# 8. Hourly activity
fig, ax = plt.subplots(figsize=(7, 4))
hourly = df.groupby("hour").size()
ax.bar(hourly.index, hourly.values, color=COLOR)
ax.set_title("Hourly Request Distribution", fontsize=12)
ax.set_xlabel("Hour (UTC)")
ax.set_ylabel("Requests")
save_plot(ax, "hourly.png")

# 9. GeoIP – Top Attacker Countries
if GEOIP_ENABLED:
    reader = Reader(GEO_DB_PATH)
    countries = []
    for ip in df["ip"].dropna().unique():
        try:
            countries.append(reader.city(ip).country.name)
        except:
            continue
    top_countries = pd.Series(countries).value_counts().head(10)
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(top_countries.index, top_countries.values, color=COLOR)
    ax.set_title("Top Attacker Countries", fontsize=12)
    ax.set_xlabel("Country")
    ax.set_ylabel("Connections")
    plt.xticks(rotation=30, ha="right")
    save_plot(ax, "countries.png")


# Summary CSV

summary = {
    "total_requests": len(df),
    "unique_ips": df["ip"].nunique(),
    "unique_paths": df["path"].nunique(),
    "top_ip": df["ip"].value_counts().idxmax(),
    "top_path": df["path"].value_counts().idxmax(),
}
pd.DataFrame([summary]).to_csv(os.path.join(OUTPUT_DIR, "summary.csv"), index=False)

print("Analysis complete — all charts saved in", OUTPUT_DIR)
