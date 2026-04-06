import json
import time
from pathlib import Path
from datetime import datetime, timezone

import psycopg


def parse_ts(value):
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except Exception:
        return None


def parse_int(value):
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def parse_float(value):
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None


def load_json_log(path: Path):
    records = []

    if not path.exists():
        return records

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return records


def insert_connections(conn, job_id, records):
    rows = []
    for r in records:
        rows.append(
            (
                job_id,
                parse_ts(r.get("ts")),
                r.get("id.orig_h"),
                parse_int(r.get("id.orig_p")),
                r.get("id.resp_h"),
                parse_int(r.get("id.resp_p")),
                r.get("proto"),
                r.get("service"),
                parse_float(r.get("duration")),
                parse_int(r.get("orig_bytes")),
                parse_int(r.get("resp_bytes")),
                r.get("conn_state"),
            )
        )

    if not rows:
        return

    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO connections
            (job_id, ts, src_ip, src_port, dst_ip, dst_port,
             proto, service, duration, orig_bytes, resp_bytes, conn_state)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            rows,
        )


def insert_dns(conn, job_id, records):
    rows = []
    for r in records:
        rows.append(
            (
                job_id,
                parse_ts(r.get("ts")),
                r.get("id.orig_h"),
                parse_int(r.get("id.orig_p")),
                r.get("id.resp_h"),
                parse_int(r.get("id.resp_p")),
                r.get("proto"),
                r.get("query"),
                parse_int(r.get("qtype")),
                parse_int(r.get("rcode")),
                str(r.get("answers")),
            )
        )

    if not rows:
        return

    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO dns_events
            (job_id, ts, src_ip, src_port, dst_ip, dst_port,
             proto, query, qtype, rcode, answers)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            rows,
        )


def insert_http(conn, job_id, records):
    rows = []
    for r in records:
        rows.append(
            (
                job_id,
                parse_ts(r.get("ts")),
                r.get("id.orig_h"),
                parse_int(r.get("id.orig_p")),
                r.get("id.resp_h"),
                parse_int(r.get("id.resp_p")),
                r.get("proto"),
                r.get("method"),
                r.get("host"),
                r.get("uri"),
                r.get("user_agent"),
                parse_int(r.get("status_code")),
            )
        )

    if not rows:
        return

    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO http_events
            (job_id, ts, src_ip, src_port, dst_ip, dst_port,
             proto, method, host, uri, user_agent, status_code)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            rows,
        )


def insert_tls(conn, job_id, records):
    rows = []
    for r in records:
        rows.append(
            (
                job_id,
                parse_ts(r.get("ts")),
                r.get("id.orig_h"),
                r.get("id.resp_h"),
                r.get("server_name"),
                r.get("subject"),
                r.get("version"),
                r.get("cipher"),
            )
        )

    if not rows:
        return

    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO tls_events
            (job_id, ts, src_ip, dst_ip, server_name, cert, version, cipher)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            rows,
        )


def insert_notice(conn, job_id, records):
    rows = []
    for r in records:
        rows.append(
            (
                job_id,
                r.get("note"),
                "medium",
                r.get("src"),
                r.get("dst"),
                parse_int(r.get("p")),
                json.dumps(r),
            )
        )

    if not rows:
        return

    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO detections
            (job_id, detection_type, severity, src_ip, dst_ip, dst_port, evidence)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            """,
            rows,
        )


def ingest_job_logs(job_id, filename, file_size_bytes, log_dir, dsn):
    log_dir = Path(log_dir)

    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO jobs (id, filename, file_size_bytes, status)
                VALUES (%s,%s,%s,'processing')
                """,
                (job_id, filename, file_size_bytes),
            )

        conn.commit()

        start = time.perf_counter()
        print("Inserting connections...")
        insert_connections(conn, job_id, load_json_log(log_dir / "conn.log"))
        print(f"Connections inserted in {time.perf_counter() - start:.2f}s")

        start = time.perf_counter()
        print("Inserting DNS events...")
        insert_dns(conn, job_id, load_json_log(log_dir / "dns.log"))
        print(f"DNS events inserted in {time.perf_counter() - start:.2f}s")

        start = time.perf_counter()
        print("Inserting HTTP events...")
        insert_http(conn, job_id, load_json_log(log_dir / "http.log"))
        print(f"HTTP events inserted in {time.perf_counter() - start:.2f}s")

        start = time.perf_counter()
        print("Inserting TLS events...")
        insert_tls(conn, job_id, load_json_log(log_dir / "ssl.log"))
        print(f"TLS events inserted in {time.perf_counter() - start:.2f}s")

        start = time.perf_counter()
        print("Inserting notice events...")
        insert_notice(conn, job_id, load_json_log(log_dir / "notice.log"))
        print(f"Notice events inserted in {time.perf_counter() - start:.2f}s")

        with conn.cursor() as cur:
            cur.execute(
                "UPDATE jobs SET status='completed' WHERE id=%s",
                (job_id,),
            )

        conn.commit()