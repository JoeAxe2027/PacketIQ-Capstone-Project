import os
import json
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Iterable, Tuple, Any


# -------------------------
# Config (tune these)
# -------------------------

DEFAULT_CONN_LOG = r"C:\zeek-project\logs\conn.log"
DEFAULT_WEIRD_LOG = r"C:\zeek-project\logs\weird.log"

# DoS / flood detection: count connections per source per sliding window
DOS_WINDOW_SECONDS = 5
DOS_CONN_THRESHOLD = 1500   # raise/lower depending on your PCAP

# Port scan detection: unique destination ports contacted by a source
PORTSCAN_UNIQUE_PORTS_THRESHOLD = 100

# Reporting
TOP_N_TALKERS = 10
TOP_N_WEIRD = 15


# -------------------------
# Zeek TSV parsing helpers
# -------------------------

@dataclass
class ZeekLogHeader:
    separator: str = "\t"
    fields: List[str] = None
    types: List[str] = None

def _parse_zeek_header(path: str) -> ZeekLogHeader:
    """
    Reads Zeek log header lines (starting with '#') to discover:
      - separator
      - fields
      - types (optional)
    """
    header = ZeekLogHeader(fields=[], types=[])
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.startswith("#"):
                break
            line = line.rstrip("\n")

            if line.startswith("#separator"):
                # Example: "#separator \x09"
                parts = line.split(" ", 1)
                if len(parts) == 2:
                    # decode escaped sequences
                    raw = parts[1].strip()
                    try:
                        header.separator = raw.encode("utf-8").decode("unicode_escape")
                    except Exception:
                        header.separator = "\t"

            elif line.startswith("#fields"):
                header.fields = line.split()[1:]  # everything after '#fields'

            elif line.startswith("#types"):
                header.types = line.split()[1:]

    if not header.fields:
        raise ValueError(f"Could not find '#fields' header in {path}. Is this a Zeek TSV log?")

    return header

def _zeek_rows(path: str) -> Iterable[Dict[str, str]]:
    """
    Stream Zeek log rows as dicts, using #fields header.
    Does NOT load entire file into memory.
    """
    hdr = _parse_zeek_header(path)
    sep = hdr.separator
    fields = hdr.fields

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#"):
                continue
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split(sep)
            # Zeek uses '-' for unset values
            row = {}
            for i, field in enumerate(fields):
                row[field] = parts[i] if i < len(parts) else "-"
            yield row

def _to_int(val: str, default: int = 0) -> int:
    if val in ("-", "", None):
        return default
    try:
        return int(val)
    except Exception:
        try:
            return int(float(val))
        except Exception:
            return default

def _to_float(val: str, default: float = 0.0) -> float:
    if val in ("-", "", None):
        return default
    try:
        return float(val)
    except Exception:
        return default


# -------------------------
# Analysis modules
# -------------------------

@dataclass
class DosHit:
    source_ip: str
    window_start_ts: int
    window_end_ts: int
    connections: int

def analyze_conn_log(
    conn_log_path: str,
    dos_window_seconds: int = DOS_WINDOW_SECONDS,
    dos_threshold: int = DOS_CONN_THRESHOLD,
    portscan_unique_ports_threshold: int = PORTSCAN_UNIQUE_PORTS_THRESHOLD,
    top_n_talkers: int = TOP_N_TALKERS,
) -> Dict[str, Any]:
    """
    Stream conn.log and compute:
      - summary counts
      - top talkers by connections
      - possible DoS windows (sliding)
      - possible port scans
      - destination summaries
    """
    # Basic counts
    total_conns = 0
    unique_sources = set()
    unique_dests = set()
    proto_counts = Counter()
    service_counts = Counter()

    # Talkers
    conn_count_by_src = Counter()

    # Port scan tracking: unique destination ports per source (bounded memory approach)
    # For big datasets, store set; still manageable for typical lab PCAPs.
    ports_by_src: Dict[str, set] = defaultdict(set)

    # DoS sliding window: per source maintain timestamps in deque (ints)
    ts_by_src: Dict[str, deque] = defaultdict(deque)
    dos_hits: List[DosHit] = []

    # Destination per source (optional quick context)
    dests_by_src: Dict[str, Counter] = defaultdict(Counter)

    for row in _zeek_rows(conn_log_path):
        total_conns += 1

        ts = _to_float(row.get("ts", "-"), 0.0)
        ts_i = int(ts)

        src = row.get("id.orig_h", "-")
        dst = row.get("id.resp_h", "-")
        dport = row.get("id.resp_p", "-")
        proto = row.get("proto", "-")
        service = row.get("service", "-")

        if src != "-":
            unique_sources.add(src)
            conn_count_by_src[src] += 1

            if dst != "-":
                dests_by_src[src][dst] += 1

            # Port scan feature
            if dport != "-":
                ports_by_src[src].add(dport)

            # DoS sliding window
            dq = ts_by_src[src]
            dq.append(ts_i)
            # pop old entries outside window
            cutoff = ts_i - dos_window_seconds
            while dq and dq[0] < cutoff:
                dq.popleft()

            if len(dq) >= dos_threshold:
                # record hit once per "burst" window: suppress duplicates by clearing deque
                dos_hits.append(DosHit(
                    source_ip=src,
                    window_start_ts=dq[0],
                    window_end_ts=dq[-1],
                    connections=len(dq),
                ))
                # Clear to avoid spamming hits continuously
                dq.clear()

        if dst != "-":
            unique_dests.add(dst)

        if proto != "-":
            proto_counts[proto] += 1
        if service != "-":
            service_counts[service] += 1

    # Top talkers
    top_talkers = conn_count_by_src.most_common(top_n_talkers)

    # Port scan candidates
    port_scans = []
    for src, ports in ports_by_src.items():
        if len(ports) >= portscan_unique_ports_threshold:
            # Provide top destination hosts for context
            top_dsts = dests_by_src[src].most_common(3)
            port_scans.append({
                "source_ip": src,
                "unique_destination_ports": len(ports),
                "top_destinations": [{"ip": ip, "connections": c} for ip, c in top_dsts],
            })

    # Summarize DoS hits
    dos_summary = []
    for hit in dos_hits[:200]:  # cap output
        dos_summary.append({
            "source_ip": hit.source_ip,
            "window_start_ts": hit.window_start_ts,
            "window_end_ts": hit.window_end_ts,
            "connections_in_window": hit.connections,
            "window_seconds": dos_window_seconds,
        })

    results = {
        "summary": {
            "total_connections": total_conns,
            "unique_sources": len(unique_sources),
            "unique_destinations": len(unique_dests),
            "protocol_breakdown": dict(proto_counts),
            "service_breakdown": dict(service_counts),
        },
        "top_talkers": [
            {"source_ip": ip, "connections": c} for ip, c in top_talkers
        ],
        "detections": {
            "possible_dos": {
                "threshold_connections_in_window": dos_threshold,
                "window_seconds": dos_window_seconds,
                "hits": dos_summary,
            },
            "possible_port_scans": {
                "threshold_unique_destination_ports": portscan_unique_ports_threshold,
                "hits": port_scans,
            },
        },
    }

    return results


def analyze_weird_log(weird_log_path: str, top_n: int = TOP_N_WEIRD) -> Dict[str, Any]:
    """
    Stream weird.log and compute:
      - counts by weird 'name'
      - top sources generating weird events (if present)
    """
    weird_name_counts = Counter()
    weird_src_counts = Counter()

    # Not all weird.log include id.orig_h depending on config/version.
    for row in _zeek_rows(weird_log_path):
        name = row.get("name", "-")
        if name != "-":
            weird_name_counts[name] += 1

        src = row.get("id.orig_h", row.get("src", "-"))
        if src != "-":
            weird_src_counts[src] += 1

    return {
        "weird_events_top": [{"name": k, "count": v} for k, v in weird_name_counts.most_common(top_n)],
        "weird_sources_top": [{"source_ip": k, "count": v} for k, v in weird_src_counts.most_common(top_n)],
        "total_weird_events": sum(weird_name_counts.values()),
    }


# -------------------------
# Main runner / CLI
# -------------------------

def run(
    conn_log_path: str,
    weird_log_path: Optional[str] = None,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    if not os.path.exists(conn_log_path):
        raise FileNotFoundError(f"conn.log not found: {conn_log_path}")

    results = {
        "conn": analyze_conn_log(conn_log_path),
    }

    if weird_log_path and os.path.exists(weird_log_path):
        results["weird"] = analyze_weird_log(weird_log_path)
    else:
        results["weird"] = {"note": "weird.log not provided or not found"}

    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
    return results


if __name__ == "__main__":
    # Quick default paths for your current setup
    conn_path = os.environ.get("ZEEK_CONN_LOG", DEFAULT_CONN_LOG)
    weird_path = os.environ.get("ZEEK_WEIRD_LOG", DEFAULT_WEIRD_LOG)

    out_path = os.environ.get("ZEEK_ANALYSIS_OUT", r"C:\zeek-project\output\analysis.json")

    res = run(conn_path, weird_path, out_path)
    print(json.dumps(res, indent=2))