from utils import load_zeek_logs

def collect_logs(json_path):
    df = load_zeek_logs(json_path)
    stats = {
        "rows": len(df),
        "time_range": [str(df["ts"].min()), str(df["ts"].max())],
        "columns": list(df.columns),
        "paths": df["_path"].value_counts().to_dict() if "_path" in df else {},
    }
    return df, stats
