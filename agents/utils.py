import pandas as pd

COLUMNS_BY_PATH = {
    "conn": [
        "ts", "id.orig_h", "id.resp_h", "proto", "service",
        "conn_state", "orig_bytes", "resp_bytes"
    ],
    "ssh": [
        "ts", "id.orig_h", "id.resp_h", "user", "auth_attempts",
        "success", "password"
    ],
    "dhcp": [
        "ts", "id.orig_h", "id.resp_h", "mac",
        "assigned_addr", "msg_type", "hostname", "vendor_class"
    ],
    "dns": [
        "ts", "id.orig_h", "id.resp_h", "query", "qtype_name",
        "answers", "rcode_name"
    ],
    "http": [
        "ts", "id.orig_h", "id.resp_h", "method", "host", "uri",
        "status_code", "user_agent"
    ],
}

def clean_zeek_logs(df, event_filter="dhcp"):
    """
    Drop unneeded fields and normalize Zeek/Corelight logs by event type.
    """
    if "_path" not in df.columns:
        return df

    # Filter by the chosen log type
    df = df[df["_path"].str.lower() == event_filter.lower()]
    if df.empty:
        return df

    keep_cols = COLUMNS_BY_PATH.get(event_filter.lower(), [])
    keep_cols = [c for c in keep_cols if c in df.columns]
    df = df[keep_cols].dropna(how="all")

    # Normalize timestamp
    if "ts" in df.columns:
        df["ts"] = pd.to_datetime(df["ts"], errors="coerce")
        df = df.sort_values("ts")

    return df
