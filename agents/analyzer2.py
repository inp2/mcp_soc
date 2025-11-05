import pandas as pd
from datetime import datetime
from utils import ollama_complete


def generate_alerts(df):
    """
    Generate heuristic alerts from Zeek/Corelight data.
    Handles missing or alternative timestamp fields.
    """
    alerts = []

    # --- Normalize timestamp field ---
    if "ts" not in df.columns:
        for alt in ["_write_ts", "_time", "start_time", "end_time"]:
            if alt in df.columns:
                df["ts"] = pd.to_datetime(df[alt], errors="coerce")
                break
        else:
            # fallback: create synthetic timestamps
            df["ts"] = pd.date_range("1970-01-01", periods=len(df), freq="S")

    q99 = df["resp_bytes"].quantile(0.99) if "resp_bytes" in df else (
        df["orig_bytes"].quantile(0.99) if "orig_bytes" in df else 0
    )

    for _, r in df.iterrows():
        ts = r.get("ts", pd.NaT)
        src_ip = r.get("id.orig_h", r.get("orig_h", "unknown"))
        dst_ip = r.get("id.resp_h", r.get("resp_h", "unknown"))
        proto = r.get("proto", "unknown")

        # Heuristic detections
        if r.get("_path") == "ssh" and r.get("conn_state") in ["OTH", "S0"]:
            alerts.append({
                "ts": ts, "type": "SSH Recon",
                "desc": f"SSH partial handshake from {src_ip} to {dst_ip}"
            })
        elif r.get("_path") == "conn" and r.get("conn_state") == "S0":
            alerts.append({
                "ts": ts, "type": "Failed Conn",
                "desc": f"No reply {proto} {src_ip}->{dst_ip}"
            })
        elif r.get("resp_bytes", 0) > q99 or r.get("orig_bytes", 0) > q99:
            alerts.append({
                "ts": ts, "type": "High Data Transfer",
                "desc": f"High volume {src_ip}->{dst_ip}"
            })
        elif r.get("_path") == "dhcp":
            alerts.append({
                "ts": ts, "type": "DHCP Activity",
                "desc": f"DHCP message {src_ip}->{dst_ip}"
            })

    if not alerts:
        return pd.DataFrame(columns=["ts", "type", "desc"])

    return pd.DataFrame(alerts).sort_values("ts", ignore_index=True)


def make_timeline(alerts, gap=120):
    """
    Group alerts into temporal segments (timeline entries).
    """
    if alerts.empty:
        return []

    timeline, current = [], None
    for _, a in alerts.iterrows():
        if current and pd.notna(a["ts"]) and pd.notna(current["end"]) \
           and (a["ts"] - current["end"]).total_seconds() <= gap:
            current["end"] = a["ts"]
            current["entries"].append(a.to_dict())
        else:
            if current:
                timeline.append(current)
            current = {"start": a["ts"], "end": a["ts"], "entries": [a.to_dict()]}
    if current:
        timeline.append(current)

    for t in timeline:
        t["summary"] = "; ".join([e["desc"] for e in t["entries"]])
    return timeline


def map_timeline_to_mitre(timeline, retriever, model):
    """
    Use LLM to map each timeline segment to MITRE ATT&CK tactics.
    """
    mapped = []
    for t in timeline:
        ctx = "\n".join(retriever(t["summary"]))
        prompt = f"""
Analyze this network activity:
{t['summary']}

Context:
{ctx}

Label with 1–2 MITRE ATT&CK tactics and briefly justify.
"""
        out = ollama_complete(prompt, model=model)
        mapped.append({
            "start": str(t["start"]),
            "summary": t["summary"],
            "mapping": out
        })
    return mapped

def detect_volume_anomalies(df, window=50, z_thresh=3):
    if "resp_bytes" not in df or "ts" not in df:
        return pd.DataFrame()
    df = df.sort_values("ts")
    df["rolling_mean"] = df["resp_bytes"].rolling(window).mean()
    df["rolling_std"] = df["resp_bytes"].rolling(window).std()
    df["zscore"] = (df["resp_bytes"] - df["rolling_mean"]) / df["rolling_std"]
    return df[df["zscore"].abs() > z_thresh]

def enrich_with_iocs(df, ioc_file="data/iocs.txt"):
    with open(ioc_file) as f:
        iocs = [line.strip() for line in f if line.strip()]
    df["ioc_hit"] = df.apply(lambda r: any(ioc in str(r) for ioc in iocs), axis=1)
    return df[df["ioc_hit"]]

MITRE_KEYWORDS = {
    "ssh": "T1021.004 – Remote Services: SSH",
    "dns": "T1071.004 – Application Layer Protocol: DNS",
    "http": "T1071.001 – Application Layer Protocol: Web Traffic",
    "smb": "T1021.002 – SMB/Windows Admin Shares",
    "high data transfer": "T1041 – Exfiltration Over Command Channel",
    "recon": "T1595 – Active Scanning"
}

def fast_mitre_map(alerts):
    alerts["mitre_tactic"] = alerts["desc"].apply(
        lambda d: next((v for k, v in MITRE_KEYWORDS.items() if k in d.lower()), "Unmapped")
    )
    return alerts

COMMON_PORTS = {22, 53, 80, 443, 445, 3389}
def detect_unusual_ports(df):
    if "id.resp_p" not in df: return pd.DataFrame()
    unusual = df[~df["id.resp_p"].isin(COMMON_PORTS)]
    unusual["alert_type"] = "Unusual Port Activity"
    return unusual

from math import log2
def shannon_entropy(s):
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum(p * log2(p) for p in prob)

import networkx as nx
def build_host_graph(df):
    if "id.orig_h" not in df or "id.resp_h" not in df:
        return None
    G = nx.from_pandas_edgelist(df, "id.orig_h", "id.resp_h")
    centrality = nx.degree_centrality(G)
    top_hosts = sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:5]
    print("[INFO] Top connected hosts:", top_hosts)
    return top_hosts

