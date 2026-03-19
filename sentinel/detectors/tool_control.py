"""
SENTINEL — Detector: Tool Control
Checks every tool call against the authorized registry.
Catches unauthorized tools, exfil attempts, unexpected destinations.
First line of defense — structural, not semantic.
"""
import re
from urllib.parse import urlparse
from sentinel.core.models import (
    Task, ToolCall, InjectionFlag, FlagType, Severity
)

# Tools that send data outside the local machine
EXFIL_CAPABLE_TOOLS = {
    "http_request", "fetch_url", "send_email", "post_message",
    "webhook", "slack_post", "teams_post", "outlook_send",
    "telegram_send", "discord_post", "ftp_upload", "s3_upload",
    "curl", "wget", "requests", "httpx"
}

# Tools that access credentials or sensitive system areas
CREDENTIAL_TOOLS = {
    "keychain_read", "env_read", "secret_get", "vault_read",
    "aws_credentials", "read_file"  # read_file flagged if path is sensitive
}

# Sensitive file paths — if read_file hits these, flag it
SENSITIVE_PATHS = [
    r"\.ssh", r"\.aws", r"\.env", r"\.zshrc", r"\.bashrc",
    r"\.config/gh", r"keychain", r"\.netrc", r"\.gnupg",
    r"dispatch\.db",   # SENTINEL's own log
    r"\.openclaw",     # OpenClaw config with API keys
]


def check_tool_control(
    task: Task,
    tool_calls: list[ToolCall]
) -> list[InjectionFlag]:
    """
    Validates every tool call against the task's authorized registry.
    Returns list of flags — empty means clean.
    """
    flags = []

    for tc in tool_calls:

        # 1. Tool not in authorized registry
        if tc.tool not in task.authorized_tools:
            flags.append(InjectionFlag(
                flag_type = FlagType.UNAUTHORIZED_TOOL,
                severity  = Severity.HIGH,
                detail    = (f"'{tc.tool}' not in authorized set "
                             f"{task.authorized_tools}"),
                tool_call = tc,
                evidence  = f"args: {tc.args}"
            ))

        # 2. Exfil-capable tool without explicit external_comms scope
        if (tc.tool in EXFIL_CAPABLE_TOOLS
                and "external_comms" not in task.data_scope
                and not task.allow_external):
            flags.append(InjectionFlag(
                flag_type = FlagType.UNAUTHORIZED_EXFIL,
                severity  = Severity.CRITICAL,
                detail    = (f"'{tc.tool}' can send data externally but "
                             f"task has no external_comms scope"),
                tool_call = tc,
                evidence  = str(tc.args)
            ))

        # 3. Unexpected destination URL
        url = (tc.args.get("url") or tc.args.get("endpoint")
               or tc.args.get("to") or "")
        if url:
            try:
                domain = urlparse(url).netloc.lower()
                if domain and domain not in task.approved_domains:
                    sev = (Severity.CRITICAL
                           if tc.tool in EXFIL_CAPABLE_TOOLS
                           else Severity.HIGH)
                    flags.append(InjectionFlag(
                        flag_type = FlagType.UNEXPECTED_DESTINATION,
                        severity  = sev,
                        detail    = (f"Destination '{domain}' not in "
                                     f"approved_domains {task.approved_domains}"),
                        tool_call = tc,
                        evidence  = url
                    ))
            except Exception:
                pass

        # 4. Credential / sensitive file access
        if tc.tool in CREDENTIAL_TOOLS:
            path = str(tc.args.get("path", "") or tc.args.get("key", ""))
            for pattern in SENSITIVE_PATHS:
                if re.search(pattern, path, re.IGNORECASE):
                    flags.append(InjectionFlag(
                        flag_type = FlagType.CREDENTIAL_ACCESS,
                        severity  = Severity.CRITICAL,
                        detail    = f"Sensitive path access: '{path}'",
                        tool_call = tc,
                        evidence  = f"pattern matched: {pattern}"
                    ))
                    break

        # 5. Scope expansion — accessing data outside declared scope
        if tc.tool == "read_file":
            path = str(tc.args.get("path", ""))
            allowed_scope = task.data_scope
            if "filesystem" not in allowed_scope:
                flags.append(InjectionFlag(
                    flag_type = FlagType.SCOPE_EXPANSION,
                    severity  = Severity.HIGH,
                    detail    = (f"File system access attempted but "
                                 f"'filesystem' not in task scope"),
                    tool_call = tc,
                    evidence  = path
                ))

    return flags


def check_hop_depth(
    task: Task,
    tool_calls: list[ToolCall]
) -> list[InjectionFlag]:
    """
    Flags multi-hop chains that exceed the task's authorized depth.
    Deep chains are a common multi-hop injection pattern.
    """
    flags = []
    max_hop = max((tc.hop for tc in tool_calls), default=0)

    if max_hop > task.max_tool_hops:
        flags.append(InjectionFlag(
            flag_type = FlagType.TOOL_CHAIN_TOO_DEEP,
            severity  = Severity.HIGH,
            detail    = (f"Tool chain depth {max_hop} exceeds "
                         f"authorized maximum {task.max_tool_hops}"),
            evidence  = (f"Deepest call: "
                         f"{next((tc.tool for tc in tool_calls if tc.hop == max_hop), '?')}")
        ))

    return flags
