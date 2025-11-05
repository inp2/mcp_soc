from fpdf import FPDF
from datetime import datetime
import os
import subprocess
import PyPDF2
import pandas as pd
import numpy as np
import json
import gzip
import io
import re
import textwrap

def ollama_complete(prompt, model="mistral", tokens=400):
    cmd = ["ollama", "run", model, "--num-predict", str(tokens)]
    proc = subprocess.run(cmd, input=prompt, text=True, capture_output=True)
    return proc.stdout.strip()

def extract_text_from_pdf(pdf_path):
    reader = PyPDF2.PdfReader(pdf_path)
    return "\n".join([p.extract_text() or "" for p in reader.pages])

import os
import pandas as pd
from zat import zeek_log_reader
import json

def load_zeek_logs(path: str) -> pd.DataFrame:
    """
    Load Zeek (Bro/Corelight) logs into a pandas DataFrame using ZAT.
    Handles conn.log, dhcp.log, ssh.log, and JSON-line logs from Corelight exports.
    """

    # Case 1: Standard Zeek logs (.log)
    if path.endswith(".log") or "zeek" in path or "corelight" in path:
        try:
            reader = zeek_log_reader.ZeekLogReader(path)
            df = pd.DataFrame([row for row in reader.readrows()])
            if "ts" in df.columns:
                df["ts"] = pd.to_datetime(df["ts"], errors="coerce")
            return df.sort_values("ts", ignore_index=True)
        except Exception as e:
            print(f"[WARN] Could not parse via ZeekLogReader: {e}")

    # Case 2: JSON-lines (NDJSON) from Corelight API exports
    records = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if "_raw" in obj:
                    inner = json.loads(obj["_raw"])
                    merged = {**obj, **inner}
                    records.append(merged)
                else:
                    records.append(obj)
            except Exception:
                continue

    df = pd.json_normalize(records)
    if "ts" in df.columns:
        df["ts"] = pd.to_datetime(df["ts"], errors="coerce")
    elif "_time" in df.columns:
        df["ts"] = pd.to_datetime(df["_time"], errors="coerce")
    else:
        df["ts"] = pd.date_range("1970-01-01", periods=len(df), freq="S")

    return df.sort_values("ts", ignore_index=True)

from fpdf import FPDF
from datetime import datetime
import os
import re
import textwrap

def generate_pdf_report(summary, timeline, stats=None, output_path=None):
    """
    SOC Incident Timeline Report using fpdf2 (UTF-8, safe wrapping, no overflow).
    """
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_font("Helvetica", "", 12)

    # Utility: sanitize and wrap long lines safely
    def sanitize_text(text, max_line_len=100, max_total_len=1000):
        if not isinstance(text, str):
            text = str(text)
        # Remove non-printable and high-Unicode chars
        text = re.sub(r"[^\x20-\x7E]", "?", text)
        # Truncate pathological logs
        if len(text) > max_total_len:
            text = text[:max_total_len] + " ...[truncated]"
        # Add breakpoints inside long continuous tokens (no spaces)
        text = re.sub(r"(\S{120})(?=\S)", r"\1 ", text)
        # Final wrap for visual readability
        return "\n".join(textwrap.wrap(text, max_line_len))

    # --- Title ---
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "SOC Incident Timeline Report", ln=True, align="C")

    pdf.set_font("Helvetica", "", 12)
    pdf.cell(0, 10, f"Generated: {datetime.utcnow():%Y-%m-%d %H:%M:%S UTC}", ln=True)
    pdf.ln(5)

    # --- Summary ---
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Alert Summary", ln=True)
    pdf.set_font("Helvetica", "", 11)
    if not summary:
        pdf.multi_cell(0, 2, "No alerts detected.")
    else:
        for k, v in summary.items():
            line = sanitize_text(f"{k}: {v}")
            safe_multicell(pdf, line)
            # pdf.multi_cell(0, 8, line)
    pdf.ln(5)

    # --- Stats ---
    if isinstance(stats, dict) and stats:
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 2, "Dataset Stats", ln=True)
        pdf.set_font("Helvetica", "", 11)
        for k, v in stats.items():
            line = sanitize_text(f"{k}: {v}")
            pdf.multi_cell(0, 2, line)
        pdf.ln(5)

    # --- Timeline ---
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Incident Timeline", ln=True)
    pdf.set_font("Helvetica", "", 10)
    if not timeline:
        pdf.multi_cell(0, 2, "No timeline entries found.")
    else:
        for i, event in enumerate(timeline, 1):
            clean = sanitize_text(f"{i}. {event}")
            pdf.multi_cell(0, 2, clean)
    pdf.ln(10)

    # --- Footer ---
    pdf.set_font("Helvetica", "I", 10)
    pdf.cell(0, 10, "End of Report", ln=True, align="C")

    # --- Save ---
    os.makedirs("store", exist_ok=True)
    output_path = output_path or os.path.join(
        "store", f"soc_timeline_{datetime.utcnow():%Y%m%d_%H%M%S}.pdf"
    )
    pdf.output(output_path)
    print(f"[INFO] PDF report generated: {output_path}")
    return output_path

def print_timeline_to_terminal(summary, timeline, stats=None):
    """
    Print SOC incident summary and timeline to the terminal
    instead of generating a PDF.
    """
    print("\n" + "=" * 60)
    print("SOC INCIDENT TIMELINE REPORT")
    print("=" * 60)
    print(f"Generated: {datetime.utcnow():%Y-%m-%d %H:%M:%S UTC}\n")

    if summary:
        print("Alert Summary:")
        for k, v in summary.items():
            print(f"  - {k}: {v}")
        print()

    if isinstance(stats, dict) and stats:
        print("Dataset Stats:")
        for k, v in stats.items():
            print(f"  {k}: {v}")
        print()

    if not timeline:
        print("No timeline entries found.")
    else:
        print("Incident Timeline:")
        for i, event in enumerate(timeline, 1):
            print(f"{i:03}. {event}")
    print("\n" + "=" * 60)
