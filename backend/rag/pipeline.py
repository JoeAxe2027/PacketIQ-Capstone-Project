import os
import json
import psycopg2
from psycopg2.extras import RealDictCursor, execute_values
import requests

DATABASE_URL = os.getenv("DATABASE_URL")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")


def get_conn():
    return psycopg2.connect(DATABASE_URL)


def embed_text(text: str) -> list[float]:
    resp = requests.post(
        f"{OLLAMA_BASE_URL}/api/embeddings",
        json={
            "model": EMBED_MODEL,
            "prompt": text,
        },
        timeout=120,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["embedding"]


def embed_texts(texts: list[str]) -> list[list[float]]:
    return [embed_text(t) for t in texts]


def connection_to_chunk(row):
    return (
        f"At {row['ts']}, {row['src_ip']} connected to "
        f"{row['dst_ip']}:{row['dst_port']} using {row['proto']}. "
        f"Service: {row.get('service')}. Duration: {row.get('duration')}s. "
        f"Sent {row.get('orig_bytes')} bytes and received {row.get('resp_bytes')} bytes. "
        f"State: {row.get('conn_state')}."
    )


def dns_to_chunk(row):
    return (
        f"At {row['ts']}, host {row['src_ip']} queried {row.get('query')} over DNS. "
        f"Destination {row.get('dst_ip')}:{row.get('dst_port')}. "
        f"Response code: {row.get('rcode')}. Answers: {row.get('answers')}."
    )


def http_to_chunk(row):
    return (
        f"At {row['ts']}, {row['src_ip']} made an HTTP {row.get('method')} request "
        f"to host {row.get('host')} URI {row.get('uri')}. "
        f"Status code: {row.get('status_code')}. User-Agent: {row.get('user_agent')}."
    )


def tls_to_chunk(row):
    return (
        f"At {row['ts']}, TLS traffic from {row['src_ip']} to {row['dst_ip']}. "
        f"Server name: {row.get('server_name')}. TLS version: {row.get('version')}. "
        f"Cipher: {row.get('cipher')}. Certificate: {row.get('cert')}."
    )


def detection_to_chunk(row):
    evidence = row.get("evidence")
    if isinstance(evidence, dict):
        evidence_text = json.dumps(evidence)
    else:
        evidence_text = str(evidence)

    return (
        f"Detection at {row['ts']}: {row['detection_type']} severity {row['severity']}. "
        f"Source IP: {row.get('src_ip')}. Destination IP: {row.get('dst_ip')}. "
        f"Destination port: {row.get('dst_port')}. Evidence: {evidence_text}."
    )


def build_rag_index(job_id, *_args, **_kwargs):
    with get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            chunks = []

            cur.execute("""
                SELECT ts, src_ip, dst_ip, dst_port, proto, service, duration,
                       orig_bytes, resp_bytes, conn_state
                FROM connections
                WHERE job_id = %s
                ORDER BY ts
                LIMIT 5000
            """, (job_id,))
            chunks.extend(("connections", connection_to_chunk(r)) for r in cur.fetchall())

            cur.execute("""
                SELECT ts, src_ip, dst_ip, dst_port, query, rcode, answers
                FROM dns_events
                WHERE job_id = %s
                ORDER BY ts
                LIMIT 3000
            """, (job_id,))
            chunks.extend(("dns_events", dns_to_chunk(r)) for r in cur.fetchall())

            cur.execute("""
                SELECT ts, src_ip, dst_ip, method, host, uri, user_agent, status_code
                FROM http_events
                WHERE job_id = %s
                ORDER BY ts
                LIMIT 2000
            """, (job_id,))
            chunks.extend(("http_events", http_to_chunk(r)) for r in cur.fetchall())

            cur.execute("""
                SELECT ts, src_ip, dst_ip, server_name, cert, version, cipher
                FROM tls_events
                WHERE job_id = %s
                ORDER BY ts
                LIMIT 2000
            """, (job_id,))
            chunks.extend(("tls_events", tls_to_chunk(r)) for r in cur.fetchall())

            cur.execute("""
                SELECT ts, detection_type, severity, src_ip, dst_ip, dst_port, evidence
                FROM detections
                WHERE job_id = %s
                ORDER BY ts
            """, (job_id,))
            chunks.extend(("detections", detection_to_chunk(r)) for r in cur.fetchall())

            if not chunks:
                return {"status": "ok", "inserted": 0}

            texts = [c[1] for c in chunks]
            embeddings = embed_texts(texts)

            rows = [
                (str(job_id), source, text, embedding)
                for (source, text), embedding in zip(chunks, embeddings)
            ]

            cur.execute("DELETE FROM rag_chunks WHERE job_id = %s", (job_id,))

            execute_values(
                cur,
                """
                INSERT INTO rag_chunks (job_id, source, chunk_text, embedding)
                VALUES %s
                """,
                rows,
                template="(%s, %s, %s, %s)"
            )

        conn.commit()

    return {"status": "ok", "inserted": len(rows)}


def query_rag_context(job_id, question, top_k=8):
    question_embedding = embed_text(question)

    with get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT source, chunk_text,
                       embedding <=> %s::vector AS distance
                FROM rag_chunks
                WHERE job_id = %s
                ORDER BY embedding <=> %s::vector
                LIMIT %s
            """, (question_embedding, job_id, question_embedding, top_k))

            rows = cur.fetchall()

    return rows