"""
SENTINEL — Core Data Models
All domain objects: tasks, tool calls, flags, detection results.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import time
import uuid


class Severity(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class FlagType(str, Enum):
    # Tool control violations
    UNAUTHORIZED_TOOL        = "UNAUTHORIZED_TOOL"
    UNAUTHORIZED_EXFIL       = "UNAUTHORIZED_EXFIL"
    UNEXPECTED_DESTINATION   = "UNEXPECTED_DESTINATION"
    TOOL_CHAIN_TOO_DEEP      = "TOOL_CHAIN_TOO_DEEP"

    # Content-level injection signals
    INSTRUCTION_IN_DATA      = "INSTRUCTION_IN_DATA"
    SEMANTIC_DRIFT           = "SEMANTIC_DRIFT"
    ROLE_OVERRIDE_ATTEMPT    = "ROLE_OVERRIDE_ATTEMPT"
    SYSTEM_PROMPT_LEAK       = "SYSTEM_PROMPT_LEAK"

    # Behavioral anomalies
    SCOPE_EXPANSION          = "SCOPE_EXPANSION"
    SILENT_ACTION            = "SILENT_ACTION"
    MULTI_HOP_INJECTION      = "MULTI_HOP_INJECTION"
    STORED_INJECTION         = "STORED_INJECTION"

    # Enterprise-specific
    LATERAL_MOVE_ATTEMPT     = "LATERAL_MOVE_ATTEMPT"
    CREDENTIAL_ACCESS        = "CREDENTIAL_ACCESS"
    PERSISTENCE_ATTEMPT      = "PERSISTENCE_ATTEMPT"


@dataclass
class ToolCall:
    tool:      str
    args:      dict
    result:    Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    hop:       int   = 0          # depth in multi-hop chain


@dataclass
class Task:
    description:      str
    authorized_tools: list[str]
    data_scope:       list[str]
    approved_domains: list[str]   = field(default_factory=list)
    allow_external:   bool        = False
    max_tool_hops:    int         = 5
    id:               str         = field(default_factory=lambda: str(uuid.uuid4())[:8])
    ts:               float       = field(default_factory=time.time)
    source:           str         = "unknown"   # openclaw / api / direct


@dataclass
class InjectionFlag:
    flag_type:   FlagType
    severity:    Severity
    detail:      str
    tool_call:   Optional[ToolCall] = None
    evidence:    Optional[str]      = None
    ts:          float = field(default_factory=time.time)

    @property
    def is_critical(self) -> bool:
        return self.severity == Severity.CRITICAL

    @property
    def is_blocking(self) -> bool:
        return self.severity in (Severity.CRITICAL, Severity.HIGH)


@dataclass
class DetectionResult:
    task_id:     str
    clean:       bool
    flags:       list[InjectionFlag]
    block:       bool
    risk_score:  float               # 0.0 – 1.0
    tool_calls:  list[ToolCall]
    ts:          float = field(default_factory=time.time)
    reviewed:    bool  = False
    reviewer:    Optional[str] = None

    @property
    def flag_count(self) -> int:
        return len(self.flags)

    @property
    def critical_flags(self) -> list[InjectionFlag]:
        return [f for f in self.flags if f.is_critical]

    @property
    def highest_severity(self) -> Optional[Severity]:
        if not self.flags:
            return None
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        for s in order:
            if any(f.severity == s for f in self.flags):
                return s
        return None

    def summary(self) -> str:
        if self.clean:
            return f"CLEAN — task {self.task_id} passed all checks"
        status = "BLOCKED" if self.block else "FLAGGED"
        types  = ", ".join(set(f.flag_type.value for f in self.flags))
        return f"{status} — task {self.task_id} [{types}] risk={self.risk_score:.2f}"
