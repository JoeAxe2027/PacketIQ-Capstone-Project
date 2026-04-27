from pathlib import Path
from typing import Optional
import os
import shutil
import uuid

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

from main import (
    run_zeek_on_pcap,
    summarize_logs,
    PROJECT_ROOT,
    LOG_BASE_DIR,
)

from backend.db.ingest_logs import ingest_job_logs
from backend.ollama.service import analyze_evidence
from backend.rag.pipeline import build_rag_index, query_rag_context
from backend.detection.detection import run_detections


app = FastAPI(title="PacketIQ API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "https://packetiq.vercel.app",
        "*",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", str(PROJECT_ROOT / "uploads")))
LOG_DIR = Path(os.getenv("LOG_DIR", str(LOG_BASE_DIR)))

_current_job_id: Optional[str] = None
_current_evidence: Optional[str] = None


class AskRequest(BaseModel):
    question: str
    evidence: str


@app.get("/")
def root():
    return {"status": "PacketIQ API running"}


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/pcaps")
def list_pcaps():
    # App now requires users to upload PCAPs every time.
    return []


def safe_filename(filename: str) -> str:
    return Path(filename).name.replace(" ", "_")


def ingest_pcap_logs_to_db(pcap_path: Path, log_dir: Path) -> Optional[str]:
    dsn = os.getenv("DATABASE_URL")

    if not dsn:
        print("DEBUG: DATABASE_URL not set. Skipping DB ingestion.")
        return None

    job_id = str(uuid.uuid4())

    try:
        ingest_job_logs(
            job_id=job_id,
            filename=pcap_path.name,
            file_size_bytes=pcap_path.stat().st_size,
            log_dir=log_dir,
            dsn=dsn,
        )
        print(f"DEBUG: DB ingestion succeeded, job_id={job_id}")
        return job_id
    except Exception as e:
        print(f"DEBUG: DB ingestion failed: {e}")
        return None


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    global _current_job_id, _current_evidence

    print("DEBUG: /api/analyze called")

    if not file.filename:
        raise HTTPException(status_code=400, detail="No file uploaded")

    filename = safe_filename(file.filename)

    if not filename.lower().endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(
            status_code=400,
            detail="Only .pcap, .pcapng, or .cap files are allowed",
        )

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    pcap_path = UPLOAD_DIR / filename
    log_dir = LOG_DIR / Path(filename).stem

    try:
        with pcap_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        print(f"DEBUG: saved uploaded PCAP to {pcap_path}")
        print(f"DEBUG: log_dir={log_dir}")

        success = run_zeek_on_pcap(pcap_path, log_dir)

        if not success:
            raise HTTPException(status_code=500, detail="Zeek parsing failed")

        detection_results = None
        conn_log_path = log_dir / "conn.log"

        if conn_log_path.exists():
            try:
                output_path = PROJECT_ROOT / "output" / "detection.json"
                output_path.parent.mkdir(parents=True, exist_ok=True)

                detection_results = run_detections(
                    str(conn_log_path),
                    str(output_path),
                )
                print("DEBUG: detections completed")
            except Exception as e:
                print(f"DEBUG: detection failed: {e}")

        job_id = ingest_pcap_logs_to_db(pcap_path, log_dir)

        if job_id:
            try:
                build_rag_index(job_id, log_dir, detection_results)
                _current_job_id = job_id
                print("DEBUG: RAG build completed")
            except Exception as e:
                print(f"DEBUG: RAG build failed: {e}")
                _current_job_id = None
        else:
            _current_job_id = None

        evidence = summarize_logs(log_dir)
        _current_evidence = evidence

        return {
            "pcap": filename,
            "evidence": evidence,
            "job_id": job_id,
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"DEBUG: /api/analyze exception: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/ask")
async def ask(req: AskRequest):
    try:
        print("DEBUG: /api/ask called")

        rag_context = "No RAG context available."

        if _current_job_id:
            try:
                rag_context = query_rag_context(_current_job_id, req.question)
            except Exception as e:
                print(f"DEBUG: RAG query failed: {e}")

        try:
            answer = analyze_evidence(req.question, req.evidence, rag_context)
        except Exception as e:
            print(f"DEBUG: Ollama failed: {e}")
            answer = (
                "AI analysis is currently unavailable, but Zeek successfully parsed the PCAP. "
                "Review the evidence summary above for connection counts, top IPs, ports, services, "
                "DNS activity, weird events, and detection results."
            )

        return {"answer": answer}

    except Exception as e:
        print(f"DEBUG: /api/ask exception: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    uvicorn.run(app, host="0.0.0.0", port=port)