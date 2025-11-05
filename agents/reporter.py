from utils import ollama_complete

def query_tactic(tactic, mapped_timeline, retriever, model):
    ctx="\n".join(retriever(tactic))
    timeline_text="\n".join([f"{m['summary']}\n{m['mapping']}" for m in mapped_timeline])
    prompt=f"""
Tactic: {tactic}
Timeline:
{timeline_text}

Explain where this tactic appears in the attack, 
how it fits into an adversary playbook, 
and list 3 SOC actions to take.
Context:
{ctx}
"""
    return ollama_complete(prompt, model=model)
