from flask import Flask, jsonify, request
import yaml
from utils import extract_text_from_pdf, generate_pdf_report, print_timeline_to_terminal
from embeddings import EmbeddingIndex
from agents.collector import collect_logs
# from agents.analyzer import generate_alerts, make_timeline, map_timeline_to_mitre, fast_mitre_map, detect_unusual_ports
from agents.analyzer import generate_alerts, make_timeline
from agents.reporter import query_tactic
# from agents.summarizer import summarize_dataset, generate_pdf_report
from threading import Thread

# ----------------------------------------------------------
# Configuration
# ----------------------------------------------------------
with open("config.yaml") as f:
    cfg = yaml.safe_load(f)

OLLAMA_MODEL = cfg["ollama_model"]
EMBED_MODEL = cfg["embedding_model"]

app = Flask(__name__)

# ----------------------------------------------------------
# Corpus: Corelight PDF + MITRE tactics
# ----------------------------------------------------------
corelight_text = extract_text_from_pdf("data/Corelight-cheatsheet-poster.pdf")
mitre_seed = {
    "Reconnaissance": "Information gathering: scanning, enumeration.",
    "Discovery": "Identifying internal assets and topology.",
    "Exfiltration": "Extracting data from systems.",
    "Command and Control": "Maintaining remote access."
}
docs = [{"id": f"mitre_{k}", "text": f"{k}: {v}"} for k,v in mitre_seed.items()]
docs.append({"id":"corelight","text":corelight_text})

embed_index = EmbeddingIndex(EMBED_MODEL)
embed_index.add_docs(docs)

# ----------------------------------------------------------
# Pipeline memory
# ----------------------------------------------------------
incident_cache = {}

# ----------------------------------------------------------
# Endpoints
# ----------------------------------------------------------
@app.route("/collector", methods=["GET"])
def collect():
    df, stats = collect_logs("data/AI_MCP_ENG.json")
    incident_cache["df"] = df
    return jsonify(stats)

@app.route("/analyzer", methods=["GET"])
def analyze():
    df = incident_cache.get("df")
    if df is None:
        return jsonify({"error":"No logs loaded"}),400

    alerts = generate_alerts(df)
    if alerts.empty:
        return jsonify({"status": "ok", "alerts": [], "summary": {}})

    # alerts = fast_mitre_map(alerts)
    summary = alerts["type"].value_counts().to_dict()
    # Build summary + timeline
    timeline = make_timeline(alerts)

    print_timeline_to_terminal(summary, timeline)

    # Generate PDF report
    # pdf_path = generate_pdf_report(summary=summary, timeline=timeline)
    
    return jsonify({
        "status": "ok",
        "summary": summary,
        "alerts": alerts.to_dict(orient="records")
    })
    # alerts = fast_mitre_map(alerts)
    # summary = alerts["type"].value_counts().to_dict()
    # return jsonify({"alerts": alerts.to_dict(orient="records"),
    #                 "summary": summary})
    # timeline = make_timeline(alerts)
    # mapped = map_timeline_to_mitre(timeline, embed_index.retrieve, OLLAMA_MODEL)
    # incident_cache["timeline"] = mapped
    # return jsonify(mapped)

@app.route("/reporter", methods=["POST"])
def report():
    data = request.json
    tactic = data.get("tactic")
    mapped = incident_cache.get("timeline", [])
    result = query_tactic(tactic, mapped, embed_index.retrieve, OLLAMA_MODEL)
    return jsonify({"tactic": tactic, "response": result})

@app.route("/summarizer", methods=["POST"])
def summarizer():
    global incident_cache
    df = incident_cache.get("df")
    if df is None:
        return jsonify({"error": "No dataset loaded. Run /collector first."}), 400

    data = request.get_json(force=True)
    event_filter = data.get("event_filter", "dhcp")

    try:
        summary_text, stats = summarize_dataset(df, event_filter=event_filter)
        output_path = generate_pdf_report(summary_text, stats, f"store/soc_summary_{event_filter}.pdf")
        return jsonify({
            "status": "ok",
            "pdf_path": output_path,
            "event_filter": event_filter,
            "summary_excerpt": summary_text[:300] + "..."
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=cfg["port"])
