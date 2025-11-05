from utils import load_json_lines

def collect_logs(json_path):
    df = load_json_lines(json_path)
    stats = {
        "rows": len(df),
        "time_range": [str(df["ts"].min()), str(df["ts"].max())],
        "columns": list(df.columns)
    }
    return df, stats
