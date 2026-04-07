import os
from backend.ollama.client import OllamaClient


def build_rag_index(job_id=None, pcap_path=None, log_dir=None):
    """
    Placeholder RAG index builder.
    Accepts the arguments the app currently passes.
    """
    print(f"DEBUG: build_rag_index called")
    print(f"DEBUG: job_id={job_id}")
    print(f"DEBUG: pcap_path={pcap_path}")
    print(f"DEBUG: log_dir={log_dir}")

    return {
        "status": "ok",
        "job_id": str(job_id) if job_id else None,
        "pcap_path": pcap_path,
        "log_dir": log_dir,
    }


def query_rag_context(question, context_chunks=None, model=None):
    client = OllamaClient(model=model)

    context_text = ""
    if context_chunks:
        if isinstance(context_chunks, list):
            context_text = "\n".join(str(c) for c in context_chunks)
        else:
            context_text = str(context_chunks)

    messages = [
        {
            "role": "system",
            "content": (
                "You are a network traffic analysis assistant. "
                "Answer only using the provided context. "
                "If the context is insufficient, say so."
            ),
        },
        {
            "role": "user",
            "content": f"Context:\n{context_text}\n\nQuestion:\n{question}",
        },
    ]

    return client.chat(messages)