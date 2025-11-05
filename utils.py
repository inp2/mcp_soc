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
            try:
                obj = json.loads(line)
                records.append(obj)
            except:
                continue
    df = pd.json_normalize(records)
    if "ts" in df.columns:
        df["ts"] = pd.to_datetime(df["ts"], errors="coerce")
    return df.sort_values("ts")
