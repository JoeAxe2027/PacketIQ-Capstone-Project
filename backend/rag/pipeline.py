from pathlib import Path
from typing import Optional
import os
import psycopg

from langchain_ollama import OllamaEmbeddings
from .chunker import build_chunks_from_logs, chunk_detection_alerts

EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")
DB_DSN = os.getenv("DATABASE_URL")

def get_embeddings():
    return OllamaEmbeddings(model=EMBED_MODEL)


def build_rag_index(job_id: str, log_dir: Path, detection_results: Optional[dict] = None) -> str:
    """
    Build chunk records for a job, embed them, and store them in PostgreSQL.
    Returns the same job_id.    """
    chunks = build_chunks_from_logs(log_dir)

    if detection_results:
        chunks.extend(chunk_detection_alerts(detection_results))

    if not chunks:
        return job_id

    MAX_RAG_CHUNKS = 300
    if len(chunks) > MAX_RAG_CHUNKS:
        print(f"Limiting RAG chunks from {len(chunks)} to {MAX_RAG_CHUNKS} for {job_id}")
        chunks = chunks[:MAX_RAG_CHUNKS]
    embeddings = get_embeddings()
    vectors = embeddings.embed_documents(chunks)

    with psycopg.connect(DB_DSN) as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM rag_chunks WHERE job_id = %s", (job_id,))

            for chunk_text, vector in zip(chunks, vectors):
                cur.execute(
                    """
                    INSERT INTO rag_chunks (job_id, source, chunk_text, embedding)
                    VALUES (%s, %s, %s, %s::vector)
                    """,
                    (
                        job_id,
                        "zeek",
                        chunk_text,
                        str(vector),
                    ),
                )
        conn.commit()

    return job_id

def query_rag_context(job_id: str, question: str, k: int = 10) -> str:
    """
    Embed the user's question and retrieve top-k similar chunks from PostgreSQL.
    """
    embeddings = get_embeddings()
    query_vector = embeddings.embed_query(question)

    with psycopg.connect(DB_DSN) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT chunk_text
                FROM rag_chunks
                WHERE job_id = %s
                ORDER BY embedding <=> %s::vector
                LIMIT %s
                """,
                (job_id, str(query_vector), k),
            )
            rows = cur.fetchall()

    if not rows:
        return "No relevant context found."

    return "\n".join(f"{i+1}. {row[0]}" for i, row in enumerate(rows))

def build_rag_context(job_id: str, log_dir: Path, question: str, detection_results: Optional[dict] = None) -> str:
    build_rag_index(job_id, log_dir, detection_results)
    return query_rag_context(job_id, question)