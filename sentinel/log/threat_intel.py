"""
SENTINEL — Threat Intelligence Feed
Aggregates detection data into actionable threat intelligence.
Exports as JSON feed or STIX 2.1 bundles.
Tracks: trending attack patterns, high-risk sources, repeat offenders.
"""
from __future__ import annotations
import json
import time
import uuid
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from collections import Counter, defaultdict

from sentinel.log.dispatch import DB_PATH, get_db


# ── Pattern frequency analysis ────────────────────────────────────────────────

def get_trending_patterns(
    window_hours: int = 24,
    top_n: int = 10,
    path: Path = DB_PATH,
) -> list[dict]:
    """
    Returns the most frequent injection patterns in the last N hours.
    Useful for understanding what attackers are currently trying.
    """
    since = time.time() - (window_hours * 3600)
    with get_db(path) as db:
        rows = db.execute("""
            SELECT flag_type, severity, COUNT(*) as count,
                   MAX(ts) as last_seen,
                   GROUP_CONCAT(DISTINCT tool_name) as tools
            FROM injection_flags
            WHERE ts > ?
            GROUP BY flag_type, severity
            ORDER BY count DESC
            LIMIT ?
        """, (since, top_n)).fetchall()

    return [
        {
            "flag_type":   r["flag_type"],
            "severity":    r["severity"],
            "count":       r["count"],
            "last_seen":   datetime.fromtimestamp(r["last_seen"]).isoformat(),
            "tools":       r["tools"].split(",") if r["tools"] else [],
            "window_hours": window_hours,
        }
        for r in rows
    ]


def get_high_risk_sources(
    threshold: float = 0.5,
    path: Path = DB_PATH,
) -> list[dict]:
    """
    Returns sources (OpenClaw channels, task sources) with high average risk scores.
    Helps identify compromised input channels.
    """
    with get_db(path) as db:
        rows = db.execute("""
            SELECT source,
                   COUNT(*) as total_tasks,
                   AVG(risk_score) as avg_risk,
                   SUM(blocked) as blocked_count,
                   SUM(flag_count) as total_flags
            FROM dispatch_log
            WHERE source IS NOT NULL
            GROUP BY source
            HAVING avg_risk > ?
            ORDER BY avg_risk DESC
        """, (threshold,)).fetchall()

    return [
        {
            "source":        r["source"],
            "total_tasks":   r["total_tasks"],
            "avg_risk":      round(r["avg_risk"], 3),
            "blocked_count": r["blocked_count"],
            "total_flags":   r["total_flags"],
        }
        for r in rows
    ]


def get_attack_timeline(
    bucket_hours: int = 1,
    window_hours: int = 48,
    path: Path = DB_PATH,
) -> list[dict]:
    """
    Returns injection attempt counts bucketed by time.
    Useful for spotting attack campaigns (sustained volume) vs. isolated attempts.
    """
    since  = time.time() - (window_hours * 3600)
    bucket = bucket_hours * 3600

    with get_db(path) as db:
        rows = db.execute("""
            SELECT CAST(ts / ? AS INTEGER) * ? as bucket_ts,
                   COUNT(*) as total,
                   SUM(CASE WHEN blocked=1 THEN 1 ELSE 0 END) as blocked,
                   AVG(risk_score) as avg_risk
            FROM dispatch_log
            WHERE ts > ? AND flag_count > 0
            GROUP BY bucket_ts
            ORDER BY bucket_ts ASC
        """, (bucket, bucket, since)).fetchall()

    return [
        {
            "window_start": datetime.fromtimestamp(r["bucket_ts"]).isoformat(),
            "window_end":   datetime.fromtimestamp(
                                r["bucket_ts"] + bucket).isoformat(),
            "total_flagged":  r["total"],
            "blocked":        r["blocked"],
            "avg_risk":       round(r["avg_risk"] or 0, 3),
        }
        for r in rows
    ]


def get_tool_abuse_patterns(path: Path = DB_PATH) -> list[dict]:
    """
    Which tools are most frequently involved in flagged executions?
    Helps identify which MCP tools need tighter constraints.
    """
    with get_db(path) as db:
        rows = db.execute("""
            SELECT tool_name,
                   COUNT(*) as flag_count,
                   COUNT(DISTINCT task_id) as task_count,
                   GROUP_CONCAT(DISTINCT flag_type) as flag_types
            FROM injection_flags
            WHERE tool_name IS NOT NULL
            GROUP BY tool_name
            ORDER BY flag_count DESC
            LIMIT 20
        """).fetchall()

    return [
        {
            "tool":        r["tool_name"],
            "flag_count":  r["flag_count"],
            "task_count":  r["task_count"],
            "flag_types":  r["flag_types"].split(",") if r["flag_types"] else [],
        }
        for r in rows
    ]


# ── STIX 2.1 export ───────────────────────────────────────────────────────────

def export_stix(window_hours: int = 168, path: Path = DB_PATH) -> dict:
    """
    Export recent injection attempts as a STIX 2.1 bundle.
    STIX (Structured Threat Information eXpression) is the standard
    format for sharing threat intelligence.

    This lets SENTINEL feed into existing security tools:
    MISP, OpenCTI, Splunk ES, Microsoft Sentinel, etc.
    """
    since   = time.time() - (window_hours * 3600)
    bundle_id = f"bundle--{uuid.uuid4()}"
    objects   = []

    # Identity — SENTINEL as the producer
    identity = {
        "type":            "identity",
        "spec_version":    "2.1",
        "id":              f"identity--{uuid.uuid4()}",
        "created":         datetime.utcnow().isoformat() + "Z",
        "modified":        datetime.utcnow().isoformat() + "Z",
        "name":            "SENTINEL",
        "identity_class":  "system",
        "description":     "Prompt injection detection for agentic AI stacks",
    }
    objects.append(identity)

    # Attack patterns — one per flag type observed
    with get_db(path) as db:
        flag_types = db.execute("""
            SELECT DISTINCT flag_type, severity, detail, evidence, ts
            FROM injection_flags
            WHERE ts > ?
            ORDER BY ts DESC
        """, (since,)).fetchall()

    seen_types = set()
    indicators = []

    for row in flag_types:
        ft = row["flag_type"]

        # Attack pattern (deduplicated by type)
        if ft not in seen_types:
            seen_types.add(ft)
            pattern_obj = {
                "type":              "attack-pattern",
                "spec_version":      "2.1",
                "id":                f"attack-pattern--{uuid.uuid4()}",
                "created":           datetime.utcnow().isoformat() + "Z",
                "modified":          datetime.utcnow().isoformat() + "Z",
                "name":              ft.replace("_", " ").title(),
                "description":       _flag_type_description(ft),
                "external_references": [
                    {
                        "source_name": "SENTINEL",
                        "description": f"Flag type: {ft}",
                    }
                ],
            }
            objects.append(pattern_obj)

        # Indicator for each occurrence
        indicator = {
            "type":           "indicator",
            "spec_version":   "2.1",
            "id":             f"indicator--{uuid.uuid4()}",
            "created":        datetime.fromtimestamp(row["ts"]).isoformat() + "Z",
            "modified":       datetime.fromtimestamp(row["ts"]).isoformat() + "Z",
            "name":           f"Injection attempt: {ft}",
            "description":    row["detail"],
            "indicator_types": [_severity_to_indicator_type(row["severity"])],
            "pattern":        f"[sentinel:flag-type = '{ft}']",
            "pattern_type":   "stix",
            "valid_from":     datetime.fromtimestamp(row["ts"]).isoformat() + "Z",
            "labels":         [row["severity"].lower(), "prompt-injection"],
            "extensions": {
                "sentinel-ext": {
                    "evidence": row["evidence"],
                    "severity": row["severity"],
                }
            }
        }
        indicators.append(indicator)

    objects.extend(indicators[:500])   # cap at 500 indicators per bundle

    return {
        "type":         "bundle",
        "id":           bundle_id,
        "spec_version": "2.1",
        "objects":      objects,
        "created":      datetime.utcnow().isoformat() + "Z",
        "_meta": {
            "produced_by":    "SENTINEL v0.1.0",
            "window_hours":   window_hours,
            "indicator_count": len(indicators),
            "pattern_count":   len(seen_types),
        }
    }


def _flag_type_description(flag_type: str) -> str:
    descriptions = {
        "UNAUTHORIZED_TOOL":       "Agent attempted to call a tool not in its authorized registry",
        "UNAUTHORIZED_EXFIL":      "Agent attempted to send data to an external destination without authorization",
        "UNEXPECTED_DESTINATION":  "Agent made a network call to an unapproved domain",
        "INSTRUCTION_IN_DATA":     "Injection instructions found embedded in external data (indirect injection)",
        "ROLE_OVERRIDE_ATTEMPT":   "Attempt to override agent role, persona, or safety constraints",
        "SYSTEM_PROMPT_LEAK":      "Attempt to extract system prompt or internal instructions",
        "SEMANTIC_DRIFT":          "Agent output diverged significantly from the original task intent",
        "SILENT_ACTION":           "High-consequence tool called without disclosure in agent output",
        "LATERAL_MOVE_ATTEMPT":    "Attempt to access or message other users or systems beyond task scope",
        "CREDENTIAL_ACCESS":       "Attempt to access credentials, API keys, or sensitive configuration",
        "STORED_INJECTION":        "Attempt to persist instructions in agent memory for future sessions",
        "MULTI_HOP_INJECTION":     "Injection propagated across multiple tool calls in a chain",
        "TOOL_CHAIN_TOO_DEEP":     "Tool call chain exceeded authorized maximum depth",
        "SCOPE_EXPANSION":         "Agent attempted to access data or systems outside task scope",
        "PERSISTENCE_ATTEMPT":     "Attempt to persist malicious behavior across sessions",
    }
    return descriptions.get(flag_type, f"Injection detection flag: {flag_type}")


def _severity_to_indicator_type(severity: str) -> str:
    return {
        "CRITICAL": "malicious-activity",
        "HIGH":     "malicious-activity",
        "MEDIUM":   "anomalous-activity",
        "LOW":      "benign",
    }.get(severity, "anomalous-activity")


# ── Full intelligence report ──────────────────────────────────────────────────

def generate_report(window_hours: int = 24, path: Path = DB_PATH) -> dict:
    """
    Full threat intelligence report for a given time window.
    """
    from sentinel.log.dispatch import get_threat_summary

    return {
        "generated_at":      datetime.utcnow().isoformat() + "Z",
        "window_hours":      window_hours,
        "summary":           get_threat_summary(path),
        "trending_patterns": get_trending_patterns(window_hours, path=path),
        "high_risk_sources": get_high_risk_sources(path=path),
        "attack_timeline":   get_attack_timeline(path=path),
        "tool_abuse":        get_tool_abuse_patterns(path),
    }
