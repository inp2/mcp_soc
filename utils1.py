import subprocess, PyPDF2, pandas as pd, numpy as np, json

def ollama_complete(prompt, model="mistral", tokens=400):
    cmd = ["ollama", "run", model, "--num-predict", str(tokens)]
    proc = subprocess.run(cmd, input=prompt, text=True, capture_output=True)
    return proc.stdout.strip()

def extract_text_from_pdf(pdf_path):
    reader = PyPDF2.PdfReader(pdf_path)
    return "\n".join([p.extract_text() or "" for p in reader.pages])

def load_json_lines(path):
    records = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                # Case 1: normal NDJSON
                if "_raw" not in obj:
                    records.append(obj)
                    continue

                # Case 2: Splunk/Corelight _raw field (stringified JSON)
                raw_val = obj["_raw"]
                if isinstance(raw_val, str):
                    try:
                        inner = json.loads(raw_val)
                        # merge the inner JSON with top-level metadata
                        merged = {**obj, **inner}
                        records.append(merged)
                    except json.JSONDecodeError:
                        # if _raw isn’t valid JSON, keep the outer object
                        records.append(obj)
                else:
                    records.append(obj)
            except json.JSONDecodeError:
                continue

    # normalize nested structures (like id.orig_h, etc.)
    if not records:
        raise ValueError("No valid JSON lines parsed.")
    df = pd.json_normalize(records)

     # ---- Timestamp normalization ----
    candidate_ts_fields = [
        "ts", "_time", "timestamp", "start_time", "end_time", "time", "datetime"
    ]
    ts_col = None
    for c in candidate_ts_fields:
        if c in df.columns:
            ts_col = c
            break

    if ts_col:
        df["ts"] = pd.to_datetime(df[ts_col], errors="coerce")
    else:
        # no timestamp — fabricate one for sorting/temporal analysis
        df["ts"] = pd.date_range(
            start="1970-01-01", periods=len(df), freq="S"
        )

    df = df.sort_values("ts", ignore_index=True)
    return df
