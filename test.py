from agents.summarizer import summarize_dataset
from agents.collector import collect_logs

# ✅ Try to get the dataset either from Flask cache or direct load
try:
    df = incident_cache.get("df")   # Works if running inside server.py context
except NameError:
    # Fallback for standalone use (e.g., in notebook or test script)
    df, _ = collect_logs("data/AI_MCP_ENG.json")

# ✅ Run the summarizer
summary, stats = summarize_dataset(df)
print(summary[:500])
print("\n--- Summary Stats ---")
print(stats)
