#!/usr/bin/env python3
"""CLI helper to load the AI_MCP_ENG dataset and inspect its structure."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from agents.collector import collect_logs
except ModuleNotFoundError as exc:
    if exc.name == "zat":
        raise SystemExit(
            "The 'zat' package is required to parse Zeek logs. Install it with 'pip install zat'."
        ) from exc
    raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Load Corelight/Zeek data into a pandas DataFrame and print summary stats.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default="../data/AI_MCP_ENG.json",
        help="Path to the AI_MCP_ENG dataset (supports .json and .json.gz).",
    )
    parser.add_argument(
        "--head",
        type=int,
        default=5,
        metavar="N",
        help="Number of rows to display from the loaded DataFrame (default: 5).",
    )
    parser.add_argument(
        "--no-stats",
        dest="show_stats",
        action="store_false",
        help="Skip printing the JSON-formatted dataset statistics.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    dataset_path = Path(args.path)
    if not dataset_path.exists():
        raise SystemExit(f"Dataset not found: {dataset_path}")

    df, stats = collect_logs(str(dataset_path), verbose=False)

    df = df.rename(columns={"_path": "protocol", "_system_name": "system_name", "_write_ts": "write_ts"})
    print(df.head(20))

if __name__ == "__main__":
    main()
