import pandas as pd
from fpdf import FPDF
from transformers import pipeline
from threading import Thread
import pandas as pd
from transformers import pipeline

import pandas as pd
from transformers import pipeline
import pandas as pd
from transformers import pipeline

def summarize_dataset(
    df,
    model_name="sshleifer/distilbart-cnn-12-6",
    max_chars_per_chunk=1800,   # much smaller chunks
    max_summary_tokens=256
):
    """
    Highly robust summarizer for Zeek/Corelight data.
    - Uses small chunk sizes to avoid embedding overflow
    - Removes conflicting token args
    - Gracefully skips failed chunks
    """
    if df.empty:
        return "No data available to summarize.", {}

    stats = {
        "rows": len(df),
        "columns": len(df.columns),
        "unique_src": df.get("id.orig_h", pd.Series()).nunique(),
        "unique_dst": df.get("id.resp_h", pd.Series()).nunique(),
        "event_types": df["_path"].value_counts().to_dict() if "_path" in df else {},
    }

    # Sample top 300 rows for readability
    sample_text = df.head(300).to_csv(index=False)
    text = (
        "Summarize these Zeek/Corelight logs for a SOC analyst. "
        "Highlight main event types, notable patterns, and anomalies.\n\n"
        f"{sample_text}"
    )

    # Split text into *very small* pieces to stay under 512 tokens per chunk
    chunks = [text[i:i + max_chars_per_chunk] for i in range(0, len(text), max_chars_per_chunk)]

    summarizer = pipeline("summarization", model=model_name)

    summaries = []
    for i, chunk in enumerate(chunks):
        try:
            result = summarizer(
                chunk,
                truncation=True,
                max_length=max_summary_tokens,
                min_length=60,
                do_sample=False,
            )
            summaries.append(result[0]["summary_text"])
        except Exception as e:
            print(f"[WARN] Summarizer failed on chunk {i}: {e}")
            continue

    if not summaries:
        final_summary = "No summary could be generated (all chunks skipped)."
    else:
        merged = " ".join(summaries)
        # re-summarize merged text for coherence
        try:
            final_summary = summarizer(
                merged[:max_chars_per_chunk * 2],
                truncation=True,
                max_length=max_summary_tokens,
                min_length=80,
                do_sample=False,
            )[0]["summary_text"]
        except Exception as e:
            print(f"[WARN] Final merge summarization failed: {e}")
            final_summary = merged

    return final_summary, stats

def generate_pdf_report(summary_text, stats, output_path="store/soc_summary.pdf"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "MCP-SOC Incident Summary Report", ln=True, align="C")
    pdf.ln(10)

    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 8, "Key Statistics:")
    for k, v in stats.items():
        pdf.cell(0, 8, f"• {k}: {v}", ln=True)

    pdf.ln(10)
    pdf.multi_cell(0, 8, "Summary of Findings:")
    pdf.set_font("Arial", size=11)
    pdf.multi_cell(0, 8, summary_text)
    pdf.output(output_path)
    return output_path
