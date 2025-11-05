import pandas as pd
from utils import ollama_complete

def generate_alerts(df):
    alerts = []
    q99 = df["bytes_out"].quantile(0.99) if "bytes_out" in df else 0
    for _, r in df.iterrows():
        ts = r.get("ts")
        if r.get("service") == "ssh" and r.get("conn_state") in ["OTH","S0"]:
            alerts.append({"ts":ts,"type":"SSH Recon",
                           "desc":f"SSH probe {r.get('src_ip')}->{r.get('dest_ip')}"})
        if r.get("conn_state")=="S0":
            alerts.append({"ts":ts,"type":"Failed Conn",
                           "desc":f"No reply {r.get('proto')} {r.get('src_ip')}->{r.get('dest_ip')}"})
        if r.get("bytes_out",0)>q99:
            alerts.append({"ts":ts,"type":"High Outbound",
                           "desc":f"{r.get('bytes_out')} bytes {r.get('src_ip')}->{r.get('dest_ip')}"})
    return pd.DataFrame(alerts).sort_values("ts")

def make_timeline(alerts, gap=120):
    timeline=[]
    cur=None
    for _,a in alerts.iterrows():
        if cur and (a["ts"]-cur["end"]).total_seconds()<=gap:
            cur["end"]=a["ts"];cur["entries"].append(a.to_dict())
        else:
            if cur: timeline.append(cur)
            cur={"start":a["ts"],"end":a["ts"],"entries":[a.to_dict()]}
    if cur: timeline.append(cur)
    for t in timeline:
        t["summary"]="; ".join([e["desc"] for e in t["entries"]])
    return timeline

def map_timeline_to_mitre(timeline, retriever, model):
    mapped=[]
    for t in timeline:
        ctx="\n".join(retriever(t["summary"]))
        prompt=f"""
Analyze this network activity:
{t['summary']}

Context:
{ctx}

Label with 1–2 MITRE ATT&CK tactics and justify briefly.
"""
        out=ollama_complete(prompt, model=model)
        mapped.append({"start":str(t["start"]),"summary":t["summary"],"mapping":out})
    return mapped
