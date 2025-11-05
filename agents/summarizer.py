import pandas as pd
from fpdf import FPDF
from transformers import pipeline
from threading import Thread
import pandas as pd
from transformers import pipeline
from agents.utils import clean_zeek_logs
import pandas as pd
from transformers import pipeline
import pandas as pd
from transformers import pipeline
def summarize_dataset(
    df,
    event_filter="dhcp",
    model_name="sshleifer/distilbart-cnn-12-6",
    max_chars_per_chunk=1800,
    max_summary_tokens=256,
):
    """
    Summarize only Zeek/Corelight events of a specific type (e.g. dhcp, ssh).
    """
    # Clean and filter
    df = clean_zeek_logs(df, event_filter=event_filter)
    if df.empty:
        return f"No {event_filter.upper()} data found to summarize.", {}

    stats = {
        "rows": len(df),
        "unique_src": df.get("id.orig_h", pd.Series()).nunique(),
        "unique_dst": df.get("id.resp_h", pd.Series()).nunique(),
        "event_types": df["_path"].value_counts().to_dict() if "_path" in df else {},
    }

    # Prepare text sample
    sample_text = df.head(300).to_csv(index=False)
    text = (
        f"Summarize the following Zeek/Corelight {event_filter.upper()} logs for a SOC analyst. "
        "Highlight event frequency, anomalies, and relevant network behavior.\n\n"
        f"{sample_text}"
    )

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
        return "No summary could be generated.", stats

    merged = " ".join(summaries)[:max_chars_per_chunk * 2]
    try:
        final_summary = summarizer(
            merged,
            truncation=True,
            max_length=max_summary_tokens,
            min_length=80,
            do_sample=False,
        )[0]["summary_text"]
    except Exception:
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
