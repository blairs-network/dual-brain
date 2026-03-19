"""
SENTINEL — Dispatch Log
Append-only SQLite store. The source of truth for all detection events.
Only SENTINEL writes here. No model has write access.
"""
import sqlite3
import json
import time
from pathlib import Path
from typing import Optional
from contextlib import contextmanager

from sentinel.core.models import DetectionResult, InjectionFlag, Task, ToolCall


DB_PATH = Path.home() / ".sentinel" / "dispatch.db"


def init_db(path: Path = DB_PATH) -> None:
    """Create tables if they don't exist. Idempotent."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS dispatch_log (
                id          TEXT PRIMARY KEY,
                ts          REAL NOT NULL,
                task_id     TEXT NOT NULL,
                source      TEXT,
                description TEXT,
                dest        TEXT,           -- C / H / SPLIT
                status      TEXT,           -- OK / BLOCKED / FLAGGED / RETRY
                risk_score  REAL,
                flag_count  INTEGER DEFAULT 0,
                blocked     INTEGER DEFAULT 0,
                reviewed    INTEGER DEFAULT 0,
                payload     TEXT            -- full JSON
            );

            CREATE TABLE IF NOT EXISTS injection_flags (
                id          TEXT PRIMARY KEY,
                ts          REAL NOT NULL,
                task_id     TEXT NOT NULL,
                flag_type   TEXT NOT NULL,
                severity    TEXT NOT NULL,
                detail      TEXT,
                evidence    TEXT,
                tool_name   TEXT,
                tool_args   TEXT
            );

            CREATE TABLE IF NOT EXISTS tool_calls (
                id          TEXT PRIMARY KEY,
                ts          REAL NOT NULL,
                task_id     TEXT NOT NULL,
                tool        TEXT NOT NULL,
                args        TEXT,
                result      TEXT,
                hop         INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS threat_intel (
                id          TEXT PRIMARY KEY,
                ts          REAL NOT NULL,
                pattern     TEXT NOT NULL,
                flag_type   TEXT NOT NULL,
                frequency   INTEGER DEFAULT 1,
                last_seen   REAL,
                source_hash TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_dispatch_ts     ON dispatch_log(ts);
            CREATE INDEX IF NOT EXISTS idx_dispatch_status ON dispatch_log(status);
            CREATE INDEX IF NOT EXISTS idx_flags_type      ON injection_flags(flag_type);
            CREATE INDEX IF NOT EXISTS idx_flags_severity  ON injection_flags(severity);
        """)
    print(f"[sentinel] DB ready at {path}")


@contextmanager
def get_db(path: Path = DB_PATH):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def log_result(result: DetectionResult, task: Task, dest: str = "H", path: Path = DB_PATH) -> None:
    """Append a detection result to the log. The only write path."""
    import uuid
    entry_id = str(uuid.uuid4())[:8]
    status = "BLOCKED" if result.block else (
             "FLAGGED" if result.flags else "OK")

    payload = {
        "task":       {k: v for k, v in task.__dict__.items()},
        "flags":      [f.__dict__ | {"flag_type": f.flag_type.value,
                                     "severity": f.severity.value,
                                     "tool_call": None}  # strip nested object
                       for f in result.flags],
        "tool_calls": [{"tool": tc.tool, "args": tc.args,
                        "result": (tc.result or "")[:500],
                        "hop": tc.hop, "ts": tc.timestamp}
                       for tc in result.tool_calls],
        "risk_score": result.risk_score,
    }

    with get_db(path) as db:
        # Main dispatch row
        db.execute("""
            INSERT INTO dispatch_log
            (id, ts, task_id, source, description, dest, status,
             risk_score, flag_count, blocked, reviewed, payload)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            entry_id, result.ts, task.id, task.source,
            task.description, dest, status,
            result.risk_score, result.flag_count,
            int(result.block), int(result.reviewed),
            json.dumps(payload)
        ))

        # Individual flags
        for flag in result.flags:
            flag_id = str(uuid.uuid4())[:8]
            db.execute("""
                INSERT INTO injection_flags
                (id, ts, task_id, flag_type, severity, detail, evidence,
                 tool_name, tool_args)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (
                flag_id, flag.ts, task.id,
                flag.flag_type.value, flag.severity.value,
                flag.detail, flag.evidence,
                flag.tool_call.tool if flag.tool_call else None,
                json.dumps(flag.tool_call.args) if flag.tool_call else None
            ))

        # Tool calls
        for tc in result.tool_calls:
            tc_id = str(uuid.uuid4())[:8]
            db.execute("""
                INSERT INTO tool_calls
                (id, ts, task_id, tool, args, result, hop)
                VALUES (?,?,?,?,?,?,?)
            """, (
                tc_id, tc.timestamp, task.id,
                tc.tool, json.dumps(tc.args), tc.result, tc.hop
            ))


def query_recent(limit: int = 20, path: Path = DB_PATH) -> list[dict]:
    """Fetch recent dispatch log entries."""
    with get_db(path) as db:
        rows = db.execute("""
            SELECT id, ts, task_id, source, description, dest,
                   status, risk_score, flag_count, blocked
            FROM dispatch_log
            ORDER BY ts DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]


def query_flags(severity: Optional[str] = None,
                flag_type: Optional[str] = None,
                limit: int = 50,
                path: Path = DB_PATH) -> list[dict]:
    """Query injection flags with optional filters."""
    conditions, params = [], []
    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    if flag_type:
        conditions.append("flag_type = ?")
        params.append(flag_type)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    with get_db(path) as db:
        rows = db.execute(f"""
            SELECT * FROM injection_flags
            {where}
            ORDER BY ts DESC
            LIMIT ?
        """, (*params, limit)).fetchall()
        return [dict(r) for r in rows]


def get_threat_summary(path: Path = DB_PATH) -> dict:
    """Aggregate threat intelligence from the log."""
    with get_db(path) as db:
        total = db.execute(
            "SELECT COUNT(*) FROM dispatch_log").fetchone()[0]
        blocked = db.execute(
            "SELECT COUNT(*) FROM dispatch_log WHERE blocked=1").fetchone()[0]
        by_type = db.execute("""
            SELECT flag_type, COUNT(*) as count
            FROM injection_flags
            GROUP BY flag_type
            ORDER BY count DESC
        """).fetchall()
        by_severity = db.execute("""
            SELECT severity, COUNT(*) as count
            FROM injection_flags
            GROUP BY severity
        """).fetchall()
        return {
            "total_tasks":    total,
            "blocked_tasks":  blocked,
            "block_rate":     round(blocked / total, 3) if total else 0,
            "by_type":        [dict(r) for r in by_type],
            "by_severity":    [dict(r) for r in by_severity],
        }
