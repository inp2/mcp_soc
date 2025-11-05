from utils import load_zeek_logs

import json
import pandas as pd

def expand_raw_json(df):
    """
    Parse Zeek raw JSON strings (if in '_raw' or 'result._raw') into columns.
    """
    raw_col = None
    for c in ["_raw", "result._raw"]:
        if c in df.columns:
            raw_col = c
            break
    if not raw_col:
        return df

    # Parse each row's JSON
    expanded_rows = []
    for row in df[raw_col]:
        try:
            data = json.loads(row)
            expanded_rows.append(data)
        except Exception:
            continue

    if not expanded_rows:
        return df

    expanded_df = pd.json_normalize(expanded_rows)
    return expanded_df

def collect_logs(json_path):
    df = load_zeek_logs(json_path)
    stats = {
        "rows": len(df),
        "time_range": [str(df["ts"].min()), str(df["ts"].max())],
        "columns": list(df.columns),
        "paths": df["_path"].value_counts().to_dict() if "_path" in df else {},
    }
    df = expand_raw_json(df)
    print(df["_path"].value_counts())
    return df, stats
