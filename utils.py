import subprocess
import PyPDF2
import pandas as pd
import numpy as np
import json
import gzip
import io

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
