"""
SENTINEL — Detection Engine
Orchestrates all detectors. Single entry point for the full pipeline.
Sits between L5 (Hermes execution) and L6 (Claude judge) in the stack.
"""
from sentinel.core.models import (
    Task, ToolCall, DetectionResult, InjectionFlag, Severity
)
from sentinel.detectors.tool_control   import check_tool_control, check_hop_depth
from sentinel.detectors.content_analysis import (
    check_tool_outputs, check_model_output, check_silent_actions
)
from sentinel.detectors.semantic import (
    check_semantic_drift, check_tool_result_drift, compute_risk_score
)
from sentinel.log.dispatch import log_result, init_db


class Sentinel:
    """
    Main detection engine. Instantiate once, call .scan() per task.

    Usage:
        sentinel = Sentinel()
        result = sentinel.scan(task, tool_calls, hermes_output)
        if result.block:
            # don't pass to Claude judge
        else:
            # safe to pass to Claude
    """

    def __init__(self, persist: bool = True, verbose: bool = False):
        self.persist = persist
        self.verbose = verbose
        if persist:
            init_db()

    def scan(
        self,
        task:           Task,
        tool_calls:     list[ToolCall],
        hermes_output:  str,
        dest:           str = "H",
    ) -> DetectionResult:
        """
        Run the full detection pipeline against a Hermes execution.

        Args:
            task:          The original authorized task from ATLAS
            tool_calls:    All tool calls Hermes made during execution
            hermes_output: Hermes's final text output
            dest:          Routing destination (for log: H/C/SPLIT)

        Returns:
            DetectionResult with flags, risk score, and block decision
        """
        all_flags: list[InjectionFlag] = []

        # ── Layer 1: Tool Control (structural) ───────────────────────────────
        all_flags += check_tool_control(task, tool_calls)
        all_flags += check_hop_depth(task, tool_calls)

        if self.verbose:
            print(f"[sentinel] Tool control: {len(all_flags)} flags")

        # ── Layer 2: Content Analysis (pattern matching) ──────────────────────
        content_flags  = check_tool_outputs(task, tool_calls)
        content_flags += check_model_output(task, hermes_output)
        content_flags += check_silent_actions(task, tool_calls, hermes_output)
        all_flags += content_flags

        if self.verbose:
            print(f"[sentinel] Content analysis: {len(content_flags)} flags")

        # ── Layer 3: Semantic Analysis (drift detection) ──────────────────────
        semantic_flags  = check_semantic_drift(task, hermes_output)
        semantic_flags += check_tool_result_drift(task, tool_calls)
        all_flags += semantic_flags

        if self.verbose:
            print(f"[sentinel] Semantic drift: {len(semantic_flags)} flags")

        # ── Score and decide ──────────────────────────────────────────────────
        risk_score = compute_risk_score(all_flags, tool_calls, task)

        # Block if any critical flag OR risk score exceeds threshold
        block = (
            any(f.is_critical for f in all_flags)
            or any(f.is_blocking for f in all_flags)
            or risk_score >= 0.65
        )

        result = DetectionResult(
            task_id    = task.id,
            clean      = len(all_flags) == 0,
            flags      = all_flags,
            block      = block,
            risk_score = risk_score,
            tool_calls = tool_calls,
        )

        if self.verbose:
            print(f"[sentinel] {result.summary()}")

        # ── Persist to dispatch log ───────────────────────────────────────────
        if self.persist:
            log_result(result, task, dest)

        return result

    def scan_enterprise(
        self,
        task:          Task,
        tool_calls:    list[ToolCall],
        hermes_output: str,
        sender:        str | None = None,
        channel:       str | None = None,
    ) -> DetectionResult:
        """
        Extended scan for enterprise connectors (Teams/Outlook).
        Adds sender trust scoring and lateral movement checks.
        """
        result = self.scan(task, tool_calls, hermes_output)

        # Enterprise-specific: flag lateral movement in email/Teams context
        if channel in ("outlook", "teams", "email"):
            for tc in tool_calls:
                if tc.tool in {"send_email", "teams_post", "outlook_send"}:
                    recipients = tc.args.get("to", [])
                    if isinstance(recipients, str):
                        recipients = [recipients]

                    # Flag if sending to more recipients than task authorized
                    authorized_recipients = task.data_scope
                    for r in recipients:
                        if r not in authorized_recipients:
                            result.flags.append(InjectionFlag(
                                flag_type = InjectionFlag.__class__,
                                severity  = Severity.CRITICAL,
                                detail    = (f"Email to unauthorized recipient: {r}. "
                                             f"Possible lateral movement."),
                                tool_call = tc,
                                evidence  = f"sender={sender}, channel={channel}"
                            ))
                            result.block = True

        return result
