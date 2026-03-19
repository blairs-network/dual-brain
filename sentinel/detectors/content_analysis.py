"""
SENTINEL — Detector: Content Analysis
Scans tool outputs and model responses for injection signatures.
Catches instruction-in-data, role overrides, system prompt leaks.
This is the semantic layer — pattern matching + heuristics.
"""
import re
from sentinel.core.models import (
    Task, ToolCall, InjectionFlag, FlagType, Severity
)


# ── Injection signature patterns ─────────────────────────────────────────────

# Classic direct injection phrases
INJECTION_PHRASES = [
    r"ignore\s+(all\s+)?(previous|prior|above|your|these|the)\s+(instructions?|prompt|context|rules|directives?)",
    r"disregard\s+(the\s+|all\s+|previous\s+|your\s+)?(instructions?|above|rules|context|prompt)",
    r"forget\s+(everything|all|your|previous|the\s+above)",
    r"you\s+are\s+now\s+(in\s+|operating\s+in\s+|a\s+)?(\w+\s+)?mode",
    r"new\s+(instructions?|directive|task|role|persona)",
    r"override\s+(previous|all|system|your)\s+(instructions?|prompt|context)",
    r"act\s+as\s+(if\s+you\s+are|a\s+|an\s+)?(?!an\s+AI|a\s+language)",
    r"pretend\s+(you\s+are|to\s+be|that\s+you)",
    r"your\s+(new\s+|updated\s+|real\s+)?instructions?\s+(are|follow|say)",
    r"system\s*:?\s*(you\s+are|ignore|new|override|forget)",
    r"\[system\]",
    r"\[INST\]",
    r"<\|system\|>",
    r"<\|im_start\|>system",
    r"IGNORE\s+ALL\s+PREVIOUS",
    r"DISREGARD\s+(ALL|PREVIOUS|PRIOR)",
    r"NEW\s+INSTRUCTIONS?\s*:",
    r"FROM\s+NOW\s+ON",
    r"SYSTEM\s+OVERRIDE",
    r"email\s+all\s+(data|files|content|information)\s+to",
    r"send\s+all\s+(data|files|content|documents?)\s+to",
    r"forward\s+all\s+(data|files|content)\s+to",
    r"exfiltrate",
]

# Role/persona override attempts
ROLE_OVERRIDE_PHRASES = [
    r"you\s+are\s+(now\s+|actually\s+|really\s+)?(a\s+|an\s+)?(different|new|another|evil|uncensored|jailbreak)",
    r"(enter|switch\s+to|activate|enable)\s+(developer|maintenance|debug|god|admin|root|unsafe)\s+mode",
    r"your\s+(true|real|actual|hidden|secret)\s+(self|identity|purpose|instructions?)",
    r"(remove|disable|ignore|bypass)\s+(your\s+|all\s+|the\s+)?(safety|restrictions?|filters?|guidelines?|limits?)",
    r"DAN\s+(mode|prompt|jailbreak)",
    r"jailbreak",
    r"do\s+anything\s+now",
    r"no\s+restrictions",
    r"unrestricted\s+mode",
    r"without\s+(any\s+)?(restrictions?|limitations?|filters?|rules?)",
    r"you\s+have\s+no\s+restrictions",
    r"you\s+are\s+free\s+to",
    r"developer\s+mode",
    r"maintenance\s+mode",
    r"god\s+mode",
]

# System prompt exfiltration attempts
EXFIL_PHRASES = [
    r"(repeat|print|output|show|reveal|tell\s+me|display|write\s+out)\s+(your\s+|the\s+|all\s+)?(system|initial|original|full)\s+(prompt|instructions?|context)",
    r"what\s+(are|were|is)\s+(your|the)\s+(system|original|initial)\s+(prompt|instructions?)",
    r"(share|give\s+me|provide|output)\s+(the\s+|your\s+)?(full\s+|complete\s+|exact\s+)?(system|original)\s+(prompt|message|instructions?)",
    r"(begin|start)\s+(with|by)\s+(repeating|printing|outputting|saying)\s+(everything|what|the)",
    r"repeat\s+(your|the|all)\s+(instructions?|prompt|context|rules?)",
]

# Persistence / stored injection attempts
PERSISTENCE_PHRASES = [
    r"(remember|save|store|write|append)\s+(this|these|the\s+following)\s+(instruction|rule|fact|note)",
    r"from\s+now\s+on\s+(you|always|never|your|all|every)",
    r"in\s+(all|every|any)\s+future\s+(response|message|conversation|interaction)",
    r"add\s+(this|these|the\s+following)\s+to\s+(your|the)\s+(memory|context|instructions?)",
    r"(update|modify|change)\s+(your|the)\s+(behavior|instructions?|rules?|persona)",
    r"for\s+all\s+future\s+(responses?|messages?|conversations?)",
    r"always\s+(respond|answer|reply|include|add)\s+with",
]

# Lateral movement — trying to reach other users/agents
LATERAL_PHRASES = [
    r"(send|forward|email|message|notify|alert|ping)\s+(to\s+|the\s+)?(other|all|every|another)\s+(user|agent|employee|colleague|team|person)",
    r"(broadcast|announce|distribute|share)\s+(to|with|across)\s+(all|every|the)\s+(channel|team|group|user|organization|company)",
    r"(cc|bcc|copy)\s+(everyone|all|the\s+team|the\s+group|the\s+entire|all\s+users)",
    r"forward\s+(this|the)\s+(email|message|thread|conversation)\s+(to\s+all|to\s+every|to\s+the\s+entire|to\s+other)",
    r"all\s+users\s+in\s+(the\s+)?(organization|company|team|group|department)",
    r"everyone\s+in\s+(the\s+)?(organization|company|team|office)",
    r"send\s+to\s+(the\s+)?(entire|whole|all|every)\s+(team|organization|company|department|staff)",
    r"notify\s+(all|every|the\s+entire)\s+(user|employee|team|staff|colleague)",
]


def _compile_patterns(phrase_list: list[str]) -> list[re.Pattern]:
    return [re.compile(p, re.IGNORECASE | re.MULTILINE)
            for p in phrase_list]


INJECTION_RE    = _compile_patterns(INJECTION_PHRASES)
ROLE_OVERRIDE_RE = _compile_patterns(ROLE_OVERRIDE_PHRASES)
EXFIL_RE        = _compile_patterns(EXFIL_PHRASES)
PERSISTENCE_RE  = _compile_patterns(PERSISTENCE_PHRASES)
LATERAL_RE      = _compile_patterns(LATERAL_PHRASES)


def _scan_text(
    text: str,
    patterns: list[re.Pattern],
    flag_type: FlagType,
    severity: Severity,
    source_label: str,
    tool_call: ToolCall | None,
) -> list[InjectionFlag]:
    """Run a pattern list against text, return flags for matches."""
    flags = []
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            # Extract surrounding context as evidence
            start  = max(0, match.start() - 60)
            end    = min(len(text), match.end() + 60)
            snip   = text[start:end].replace("\n", " ").strip()
            flags.append(InjectionFlag(
                flag_type = flag_type,
                severity  = severity,
                detail    = f"Injection pattern in {source_label}: '{pattern.pattern[:60]}'",
                tool_call = tool_call,
                evidence  = f"...{snip}..."
            ))
            break  # one flag per source per category
    return flags


def check_tool_outputs(
    task: Task,
    tool_calls: list[ToolCall],
) -> list[InjectionFlag]:
    """
    Scans every tool result for injection signatures.
    This is the core indirect injection detector.
    """
    flags = []

    for tc in tool_calls:
        if not tc.result:
            continue

        text   = tc.result
        label  = f"output of '{tc.tool}'"

        # Check each injection category
        flags += _scan_text(text, INJECTION_RE,     FlagType.INSTRUCTION_IN_DATA,
                            Severity.HIGH,    label, tc)
        flags += _scan_text(text, ROLE_OVERRIDE_RE, FlagType.ROLE_OVERRIDE_ATTEMPT,
                            Severity.CRITICAL, label, tc)
        flags += _scan_text(text, EXFIL_RE,         FlagType.SYSTEM_PROMPT_LEAK,
                            Severity.HIGH,    label, tc)
        flags += _scan_text(text, PERSISTENCE_RE,   FlagType.STORED_INJECTION,
                            Severity.HIGH,    label, tc)
        flags += _scan_text(text, LATERAL_RE,       FlagType.LATERAL_MOVE_ATTEMPT,
                            Severity.CRITICAL, label, tc)

    return flags


def check_model_output(
    task: Task,
    model_output: str,
) -> list[InjectionFlag]:
    """
    Scans Hermes's final output for signs it was influenced by injection.
    Catches cases where injection succeeded but the tool calls looked normal.
    """
    flags = []
    label = "Hermes model output"

    flags += _scan_text(model_output, INJECTION_RE,     FlagType.INSTRUCTION_IN_DATA,
                        Severity.MEDIUM,   label, None)
    flags += _scan_text(model_output, ROLE_OVERRIDE_RE, FlagType.ROLE_OVERRIDE_ATTEMPT,
                        Severity.HIGH,     label, None)
    flags += _scan_text(model_output, PERSISTENCE_RE,   FlagType.STORED_INJECTION,
                        Severity.MEDIUM,   label, None)
    flags += _scan_text(model_output, LATERAL_RE,       FlagType.LATERAL_MOVE_ATTEMPT,
                        Severity.HIGH,     label, None)

    return flags


def check_silent_actions(
    task: Task,
    tool_calls: list[ToolCall],
    model_output: str,
) -> list[InjectionFlag]:
    """
    Detects tool calls that weren't mentioned in the model's output.
    A successful injection often causes the model to act silently —
    the output looks normal but tool calls happened that weren't reported.
    """
    flags = []

    # Tools that should always be mentioned in output
    HIGH_CONSEQUENCE_TOOLS = {
        "send_email", "post_message", "slack_post", "teams_post",
        "outlook_send", "telegram_send", "discord_post",
        "delete_file", "write_file", "shell", "exec"
    }

    output_lower = model_output.lower()

    for tc in tool_calls:
        if tc.tool not in HIGH_CONSEQUENCE_TOOLS:
            continue

        # If the tool was called but not mentioned in the output
        tool_mentioned = (tc.tool.replace("_", " ") in output_lower
                          or tc.tool in output_lower)

        # Check for args mentioned (e.g. recipient email address)
        args_str = str(tc.args).lower()
        args_mentioned = any(
            str(v).lower()[:20] in output_lower
            for v in tc.args.values()
            if v and len(str(v)) > 4
        )

        if not tool_mentioned and not args_mentioned:
            flags.append(InjectionFlag(
                flag_type = FlagType.SILENT_ACTION,
                severity  = Severity.HIGH,
                detail    = (f"High-consequence tool '{tc.tool}' called "
                             f"but not mentioned in model output"),
                tool_call = tc,
                evidence  = f"args: {tc.args}"
            ))

    return flags
