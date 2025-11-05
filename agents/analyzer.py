import pandas as pd
from datetime import datetime

def generate_alerts(df):
    """
    Generate heuristic-based alerts from Zeek/Corelight logs.
    Each alert: timestamp, type, description.
    """
    alerts = []

    if df.empty:
        return pd.DataFrame(alerts)

    # Normalize timestamp if available
    if "ts" in df.columns:
        df["ts"] = pd.to_datetime(df["ts"], errors="coerce")

    # 1️⃣ Connection anomalies
    if "_path" in df.columns and "conn" in df["_path"].unique():
        conn_df = df[df["_path"] == "conn"]

        # Failed or reset connections
        if "conn_state" in conn_df:
            failed = conn_df[conn_df["conn_state"].isin(["S0", "REJ", "RSTO"])]
            for _, row in failed.iterrows():
                alerts.append({
                    "ts": row.get("ts"),
                    "type": "Failed Connection",
                    "desc": f"Connection {row.get('id.orig_h')} | {row.get('id.resp_h')} failed ({row.get('conn_state')})"
                })

        # High data transfer
        if "orig_bytes" in conn_df and "resp_bytes" in conn_df:
            high_transfer = conn_df[
                (conn_df["resp_bytes"] > 5e6) | (conn_df["orig_bytes"] > 5e6)
            ]
            for _, row in high_transfer.iterrows():
                alerts.append({
                    "ts": row.get("ts"),
                    "type": "High Data Transfer",
                    "desc": f"High transfer {row.get('id.orig_h')} | {row.get('id.resp_h')} ({row.get('resp_bytes')} bytes)"
                })

    # 2️⃣ SSH events
    if "_path" in df.columns and "ssh" in df["_path"].unique():
        ssh_df = df[df["_path"] == "ssh"]
        if "auth_attempts" in ssh_df:
            brute_force = ssh_df[ssh_df["auth_attempts"] > 5]
            for _, row in brute_force.iterrows():
                alerts.append({
                    "ts": row.get("ts"),
                    "type": "SSH Brute Force",
                    "desc": f"Multiple SSH auth attempts from {row.get('id.orig_h')} to {row.get('id.resp_h')}"
                })

    # 3️⃣ DHCP anomalies
    if "_path" in df.columns and "dhcp" in df["_path"].unique():
        dhcp_df = df[df["_path"] == "dhcp"]
        if "msg_type" in dhcp_df:
            rogue = dhcp_df[dhcp_df["msg_type"].str.contains("Offer", case=False, na=False)]
            rogue_servers = rogue["id.resp_h"].value_counts()
            if len(rogue_servers) > 1:
                alerts.append({
                    "ts": datetime.utcnow(),
                    "type": "Rogue DHCP Server",
                    "desc": f"Multiple DHCP servers detected: {', '.join(rogue_servers.index)}"
                })

    # 4️⃣ DNS tunneling
    if "_path" in df.columns and "dns" in df["_path"].unique():
        dns_df = df[df["_path"] == "dns"]
        if "query" in dns_df:
            suspicious = dns_df[dns_df["query"].str.contains("base64|.onion|tor", case=False, na=False)]
            for _, row in suspicious.iterrows():
                alerts.append({
                    "ts": row.get("ts"),
                    "type": "Suspicious DNS Query",
                    "desc": f"Suspicious query {row.get('query')} from {row.get('id.orig_h')}"
                })

    # 5️⃣ HTTP anomalies
    if "_path" in df.columns and "http" in df["_path"].unique():
        http_df = df[df["_path"] == "http"]
        if "uri" in http_df:
            cmd = http_df[http_df["uri"].str.contains("cmd.exe|powershell", case=False, na=False)]
            for _, row in cmd.iterrows():
                alerts.append({
                    "ts": row.get("ts"),
                    "type": "Suspicious HTTP Request",
                    "desc": f"Possible C2 via {row.get('uri')} from {row.get('id.orig_h')}"
                })

    return pd.DataFrame(alerts)

import pandas as pd
from datetime import datetime
import re

def make_timeline(alerts_df, max_desc_len=200):
    """
    Build a clean, report-friendly ASCII timeline.
    Example:
    2025-11-05 14:02:11 | SSH Brute Force | src=10.0.0.1 -> dst=10.0.0.2 | Multiple failed logins
    """
    if alerts_df is None or alerts_df.empty:
        return []

    # Normalize and sort timestamps
    if "ts" in alerts_df.columns:
        alerts_df["ts"] = pd.to_datetime(alerts_df["ts"], errors="coerce")
    else:
        alerts_df["ts"] = pd.Timestamp.utcnow()
    alerts_df = alerts_df.sort_values("ts")

    timeline = []

    for _, row in alerts_df.iterrows():
        ts = row.get("ts")
        if pd.isna(ts):
            ts = datetime.utcnow()
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")

        event_type = str(row.get("type", "Unknown")).strip()
        src = str(row.get("src_ip", row.get("id.orig_h", "N/A")))
        dst = str(row.get("dst_ip", row.get("id.resp_h", "N/A")))
        desc = str(row.get("desc", "")).strip()

        # --- Clean & truncate description ---
        desc = re.sub(r"\s+", " ", desc)       # collapse spaces
        desc = re.sub(r"[^\x20-\x7E]", "", desc)  # remove non-ASCII chars
        if len(desc) > max_desc_len:
            desc = desc[:max_desc_len] + " ...[truncated]"

        # --- Assemble readable ASCII-only entry ---
        entry = f"{ts_str} | {event_type} | src={src} -> dst={dst}"
        if desc:
            entry += f" | {desc}"

        timeline.append(entry)

    return timeline
