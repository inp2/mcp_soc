from __future__ import annotations

from datetime import datetime
from pathlib import Path
import gzip
import json
import os
import re
import subprocess
import textwrap

import pandas as pd
import PyPDF2
from fpdf import FPDF
from zat import zeek_log_reader


def _open_log_text(path: Path):
    """Open a Zeek/Corelight export as text, transparently handling gzip files."""

    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="ignore")
    return path.open("rt", encoding="utf-8", errors="ignore")


def _extract_records_from_container(container):
    """Return the first list of records found inside a JSON container."""

    if isinstance(container, list):
        return container

    if isinstance(container, dict):
        # Prefer common keys used by various APIs
        for key in ("records", "data", "results", "items", "events", "rows", "log", "entries"):
            value = container.get(key)
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                nested = _extract_records_from_container(value)
                if nested:
                    return nested

        # Fallback: search remaining nested containers depth-first
        for value in container.values():
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                nested = _extract_records_from_container(value)
                if nested:
                    return nested

        return [container]

    return []


def _merge_embedded_raw(record):
    """If Zeek embeds JSON blobs inside *_raw fields, merge them into the record."""

    if not isinstance(record, dict):
        return record

    for raw_key in ("_raw", "result._raw"):
        raw_value = record.get(raw_key)
        if isinstance(raw_value, str):
            try:
                inner = json.loads(raw_value)
            except json.JSONDecodeError:
                continue
            if isinstance(inner, dict):
                record = {**record, **inner}

    return record

def ollama_complete(prompt, model="mistral", tokens=400):
    cmd = ["ollama", "run", model, "--num-predict", str(tokens)]
    proc = subprocess.run(cmd, input=prompt, text=True, capture_output=True)
    return proc.stdout.strip()

def extract_text_from_pdf(pdf_path):
    reader = PyPDF2.PdfReader(pdf_path)
    return "\n".join([p.extract_text() or "" for p in reader.pages])

def load_zeek_logs(path: str | os.PathLike[str]) -> pd.DataFrame:
    """
    Load Zeek (Bro/Corelight) logs into a pandas DataFrame using ZAT.
    Handles conn.log, dhcp.log, ssh.log, and JSON-line logs from Corelight exports.
    """

    path = Path(path)
    path_str = str(path)

    # Case 1: Standard Zeek logs (.log)
    if path.suffix == ".log" or "zeek" in path_str.lower() or "corelight" in path_str.lower():
        try:
            reader = zeek_log_reader.ZeekLogReader(path_str)
            df = pd.DataFrame(list(reader.readrows()))
            if "ts" in df.columns:
                df["ts"] = pd.to_datetime(df["ts"], errors="coerce")
            return df.sort_values("ts", ignore_index=True)
        except Exception as e:
            print(f"[WARN] Could not parse via ZeekLogReader: {e}")

    # Case 2: Structured JSON containers or NDJSON exports
    records = []

    try:
        with _open_log_text(path) as handle:
            container = json.load(handle)
        records = _extract_records_from_container(container)
    except json.JSONDecodeError:
        # Fallback: NDJSON / JSON-lines
        with _open_log_text(path) as handle:
            for line in handle:
                line = line.strip()
                if not line or line in ("[", "]", ","):
                    continue
                try:
                    obj = json.loads(line.rstrip(","))
                except json.JSONDecodeError:
                    continue
                records.append(_merge_embedded_raw(obj))
    except FileNotFoundError:
        raise

    if not records:
        return pd.DataFrame()

    df = pd.json_normalize([_merge_embedded_raw(rec) for rec in records])

    if not df.empty:
        if "ts" in df.columns:
            df["ts"] = pd.to_datetime(df["ts"], errors="coerce")
        elif "_time" in df.columns:
            df["ts"] = pd.to_datetime(df["_time"], errors="coerce")
        elif len(df) > 0:
            df["ts"] = pd.date_range("1970-01-01", periods=len(df), freq="S")

        if "ts" in df.columns:
            df = df.sort_values("ts", ignore_index=True)
        else:
            df = df.reset_index(drop=True)

    return df

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
