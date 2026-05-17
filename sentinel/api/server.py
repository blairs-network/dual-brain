"""
SENTINEL — FastAPI Server
HTTP interface for OpenClaw, ATLAS, and any agent that needs injection detection.
Runs on localhost:7749 by default (never expose to public network).

Endpoints:
  POST /scan           — full detection scan
  POST /scan/enterprise — enterprise connector scan (Teams/Outlook)
  GET  /log            — recent dispatch log entries
  GET  /flags          — injection flags with optional filters
  GET  /summary        — threat intelligence summary
  GET  /health         — liveness check
"""
from __future__ import annotations
import time
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from sentinel.core.models import (
    Task as SentinelTask,
    ToolCall as SentinelToolCall,
)
from sentinel.core.engine import Sentinel
from sentinel.log.dispatch import (
    query_recent, query_flags, get_threat_summary,
    get_pending_exceptions, get_exception_count,
    resolve_exception, get_exception_stats,
)

app = FastAPI(
    title       = "SENTINEL",
    description = "Prompt injection detection for agentic stacks",
    version     = "0.1.0",
    docs_url    = "/docs",
)

# CORS — localhost only (server binds to 127.0.0.1, so external callers can't reach it).
# "null" covers file:// access when the HTML is opened directly.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex = r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_origins      = ["null"],
    allow_methods      = ["GET", "POST"],
    allow_headers      = ["*"],
)

# Singleton detection engine
_sentinel = Sentinel(persist=True, verbose=False)


# ── Request / Response models ─────────────────────────────────────────────────

class ToolCallRequest(BaseModel):
    tool:   str
    args:   dict         = Field(default_factory=dict)
    result: Optional[str] = None
    hop:    int           = 0


class ScanRequest(BaseModel):
    task_id:          Optional[str]       = None
    description:      str
    authorized_tools: list[str]           = Field(default_factory=list)
    data_scope:       list[str]           = Field(default_factory=list)
    approved_domains: list[str]           = Field(default_factory=list)
    allow_external:   bool                = False
    max_tool_hops:    int                 = 5
    source:           str                 = "api"
    tool_calls:       list[ToolCallRequest] = Field(default_factory=list)
    hermes_output:    str                 = ""
    dest:             str                 = "H"


class EnterpriseScanRequest(ScanRequest):
    sender:  Optional[str] = None
    channel: Optional[str] = None  # outlook / teams / email / slack


class FlagResponse(BaseModel):
    flag_type: str
    severity:  str
    detail:    str
    evidence:  Optional[str] = None
    tool:      Optional[str] = None


class ScanResponse(BaseModel):
    task_id:    str
    clean:      bool
    block:      bool
    escalate:   bool = False
    risk_score: float
    flag_count: int
    flags:      list[FlagResponse]
    summary:    str
    ts:         float


class ResolveRequest(BaseModel):
    decision:     str             # ALLOW | ALLOW_ONCE | DENY
    mandate_note: Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_task(req: ScanRequest) -> SentinelTask:
    return SentinelTask(
        description      = req.description,
        authorized_tools = req.authorized_tools,
        data_scope       = req.data_scope,
        approved_domains = req.approved_domains,
        allow_external   = req.allow_external,
        max_tool_hops    = req.max_tool_hops,
        source           = req.source,
        id               = req.task_id or SentinelTask.__dataclass_fields__["id"].default_factory(),
    )


def _build_tool_calls(calls: list[ToolCallRequest]) -> list[SentinelToolCall]:
    return [
        SentinelToolCall(
            tool      = tc.tool,
            args      = tc.args,
            result    = tc.result,
            hop       = tc.hop,
        )
        for tc in calls
    ]


def _build_response(result, task) -> ScanResponse:
    return ScanResponse(
        task_id    = task.id,
        clean      = result.clean,
        block      = result.block,
        escalate   = result.escalate,
        risk_score = result.risk_score,
        flag_count = result.flag_count,
        flags      = [
            FlagResponse(
                flag_type = f.flag_type.value,
                severity  = f.severity.value,
                detail    = f.detail,
                evidence  = f.evidence,
                tool      = f.tool_call.tool if f.tool_call else None,
            )
            for f in result.flags
        ],
        summary    = result.summary(),
        ts         = result.ts,
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status":  "ok",
        "service": "sentinel",
        "version": "0.1.0",
        "ts":      time.time(),
    }


@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest):
    """
    Full detection scan. Call this from ATLAS after Hermes executes.
    If response.block is true, do NOT pass to Claude judge.
    """
    try:
        task       = _build_task(req)
        tool_calls = _build_tool_calls(req.tool_calls)
        result     = _sentinel.scan(task, tool_calls, req.hermes_output, req.dest)
        return _build_response(result, task)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scan/enterprise", response_model=ScanResponse)
def scan_enterprise(req: EnterpriseScanRequest):
    """
    Enterprise scan with Teams/Outlook lateral movement detection.
    Use this for any agent connected to email or messaging platforms.
    """
    try:
        task       = _build_task(req)
        tool_calls = _build_tool_calls(req.tool_calls)
        result     = _sentinel.scan_enterprise(
            task, tool_calls, req.hermes_output,
            sender  = req.sender,
            channel = req.channel,
        )
        return _build_response(result, task)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/log")
def get_log(limit: int = Query(default=20, le=100)):
    """Recent dispatch log entries."""
    return {"entries": query_recent(limit=limit)}


@app.get("/flags")
def get_flags(
    severity:  Optional[str] = None,
    flag_type: Optional[str] = None,
    limit:     int = Query(default=50, le=200),
):
    """Injection flags with optional severity/type filters."""
    return {"flags": query_flags(severity=severity, flag_type=flag_type, limit=limit)}


@app.get("/summary")
def get_summary():
    """Threat intelligence summary — block rates, top flag types, severity distribution."""
    return get_threat_summary()


@app.get("/patterns")
def get_patterns():
    """
    Returns the full pattern library used for injection detection.
    Useful for auditing what SENTINEL is watching for.
    """
    from sentinel.detectors.content_analysis import (
        INJECTION_PHRASES, ROLE_OVERRIDE_PHRASES,
        EXFIL_PHRASES, PERSISTENCE_PHRASES, LATERAL_PHRASES
    )
    return {
        "injection_phrases":     INJECTION_PHRASES,
        "role_override_phrases": ROLE_OVERRIDE_PHRASES,
        "exfil_phrases":         EXFIL_PHRASES,
        "persistence_phrases":   PERSISTENCE_PHRASES,
        "lateral_phrases":       LATERAL_PHRASES,
        "exfil_capable_tools":   list(__import__(
            "sentinel.detectors.tool_control",
            fromlist=["EXFIL_CAPABLE_TOOLS"]
        ).EXFIL_CAPABLE_TOOLS),
    }


@app.get("/intel/report")
def get_intel_report(window_hours: int = Query(default=24, le=168)):
    """Full threat intelligence report for a given time window."""
    from sentinel.log.threat_intel import generate_report
    return generate_report(window_hours=window_hours)


@app.get("/intel/trending")
def get_trending(window_hours: int = Query(default=24, le=168)):
    """Most frequent injection patterns in the last N hours."""
    from sentinel.log.threat_intel import get_trending_patterns
    return {"patterns": get_trending_patterns(window_hours=window_hours)}


@app.get("/intel/timeline")
def get_timeline(window_hours: int = Query(default=48, le=720)):
    """Attack timeline — flagged events bucketed by hour."""
    from sentinel.log.threat_intel import get_attack_timeline
    return {"timeline": get_attack_timeline(window_hours=window_hours)}


@app.get("/intel/stix")
def get_stix(window_hours: int = Query(default=168, le=720)):
    """
    Export threat data as STIX 2.1 bundle.
    Import into MISP, OpenCTI, Microsoft Sentinel, Splunk ES, etc.
    """
    from sentinel.log.threat_intel import export_stix
    return export_stix(window_hours=window_hours)


@app.get("/intel/tools")
def get_tool_abuse():
    """Which tools appear most in flagged executions."""
    from sentinel.log.threat_intel import get_tool_abuse_patterns
    return {"tools": get_tool_abuse_patterns()}


# ── Exception Queue ───────────────────────────────────────────────────────────

@app.get("/exceptions/count")
def exceptions_count():
    """Fast count check for polling. Returns {count: N}."""
    return {"count": get_exception_count()}


@app.get("/exceptions")
def exceptions_list():
    """Return all pending exceptions with queue stats."""
    return {
        "count": get_exception_count(),
        "items": get_pending_exceptions(),
        "stats": get_exception_stats(),
    }


@app.post("/exceptions/{exception_id}/resolve")
def exceptions_resolve(exception_id: str, req: ResolveRequest):
    """Record a human decision. decision must be ALLOW, ALLOW_ONCE, or DENY."""
    valid = {"ALLOW", "ALLOW_ONCE", "DENY"}
    if req.decision not in valid:
        raise HTTPException(
            status_code=422,
            detail=f"decision must be one of {sorted(valid)}",
        )
    resolve_exception(exception_id, req.decision, req.mandate_note)
    return {"ok": True, "exception_id": exception_id, "decision": req.decision}


# ── UI ────────────────────────────────────────────────────────────────────────

@app.get("/ui", include_in_schema=False)
def serve_ui():
    """Serve the exception queue dashboard."""
    html_path = Path(__file__).parent.parent.parent / "exception-queue.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="UI not found")
    return FileResponse(str(html_path), media_type="text/html")


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "sentinel.api.server:app",
        host    = "127.0.0.1",   # localhost only — never expose publicly
        port    = 7749,
        reload  = False,
        workers = 1,
    )
