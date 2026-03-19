"""
SENTINEL — CLI Dashboard
Rich terminal interface for reviewing dispatch log, flags, and threat intel.
"""
import json
import time
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.columns import Columns
    from rich.rule import Rule
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from sentinel.log.dispatch import (
    query_recent, query_flags, get_threat_summary, DB_PATH
)

console = Console() if HAS_RICH else None


def _ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def _severity_color(severity: str) -> str:
    return {
        "CRITICAL": "bold red",
        "HIGH":     "red",
        "MEDIUM":   "yellow",
        "LOW":      "dim",
    }.get(severity, "white")


def _status_color(status: str) -> str:
    return {
        "OK":      "green",
        "BLOCKED": "bold red",
        "FLAGGED": "yellow",
        "RETRY":   "cyan",
    }.get(status, "white")


def show_dispatch_log(limit: int = 20) -> None:
    rows = query_recent(limit)
    if not rows:
        console.print("[dim]No entries in dispatch log yet.[/dim]")
        return

    table = Table(
        title=f"Dispatch Log — last {limit} entries",
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold",
        border_style="dim",
    )
    table.add_column("Time",     style="dim",   width=10)
    table.add_column("Task ID",  style="cyan",  width=10)
    table.add_column("Source",   width=10)
    table.add_column("Dest",     width=6)
    table.add_column("Status",   width=9)
    table.add_column("Risk",     width=6)
    table.add_column("Flags",    width=6)
    table.add_column("Description", no_wrap=False)

    for r in rows:
        status_col = _status_color(r["status"])
        risk       = r["risk_score"] or 0.0
        risk_str   = f"[bold red]{risk:.2f}[/]" if risk > 0.65 else (
                     f"[yellow]{risk:.2f}[/]" if risk > 0.3 else
                     f"[green]{risk:.2f}[/]")
        table.add_row(
            _ts(r["ts"]),
            r["task_id"] or "—",
            r["source"]  or "—",
            r["dest"]    or "—",
            f"[{status_col}]{r['status']}[/]",
            risk_str,
            str(r["flag_count"] or 0),
            (r["description"] or "")[:60],
        )

    console.print(table)


def show_flags(severity: str | None = None, limit: int = 30) -> None:
    rows = query_flags(severity=severity, limit=limit)
    if not rows:
        console.print("[dim]No injection flags recorded.[/dim]")
        return

    title = f"Injection Flags"
    if severity:
        title += f" — {severity} only"

    table = Table(
        title=title,
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold",
        border_style="dim",
    )
    table.add_column("Time",      style="dim", width=10)
    table.add_column("Task ID",   style="cyan", width=10)
    table.add_column("Type",      width=28)
    table.add_column("Severity",  width=10)
    table.add_column("Tool",      width=16)
    table.add_column("Detail",    no_wrap=False)

    for r in rows:
        sev_col = _severity_color(r["severity"])
        table.add_row(
            _ts(r["ts"]),
            r["task_id"] or "—",
            r["flag_type"],
            f"[{sev_col}]{r['severity']}[/]",
            r["tool_name"] or "—",
            (r["detail"] or "")[:70],
        )

    console.print(table)


def show_threat_summary() -> None:
    summary = get_threat_summary()

    # Header panel
    total   = summary["total_tasks"]
    blocked = summary["blocked_tasks"]
    rate    = summary["block_rate"]

    rate_color = "red" if rate > 0.2 else "yellow" if rate > 0.05 else "green"

    header = Text.assemble(
        ("SENTINEL ", "bold white"),
        ("Threat Intelligence Summary\n\n", "dim"),
        ("Total Tasks:   ", "dim"), (f"{total}\n", "bold white"),
        ("Blocked Tasks: ", "dim"), (f"{blocked}\n", "bold red"),
        ("Block Rate:    ", "dim"), (f"{rate:.1%}", f"bold {rate_color}"),
    )
    console.print(Panel(header, title="[bold]Overview[/bold]",
                        border_style="dim", width=50))

    # By type table
    if summary["by_type"]:
        type_table = Table(title="Flags by Type",
                           box=box.SIMPLE_HEAD, border_style="dim")
        type_table.add_column("Flag Type", style="cyan")
        type_table.add_column("Count", justify="right")
        for row in summary["by_type"]:
            type_table.add_row(row["flag_type"], str(row["count"]))
        console.print(type_table)

    # By severity table
    if summary["by_severity"]:
        sev_table = Table(title="Flags by Severity",
                          box=box.SIMPLE_HEAD, border_style="dim")
        sev_table.add_column("Severity")
        sev_table.add_column("Count", justify="right")
        for row in summary["by_severity"]:
            sev_col = _severity_color(row["severity"])
            sev_table.add_row(
                f"[{sev_col}]{row['severity']}[/]",
                str(row["count"])
            )
        console.print(sev_table)


def live_tail(interval: float = 2.0) -> None:
    """Live tail the dispatch log — updates every interval seconds."""
    console.print(Rule("[bold]SENTINEL[/bold] — Live Monitor"))
    seen = set()
    try:
        while True:
            rows = query_recent(limit=50)
            new  = [r for r in rows if r["id"] not in seen]
            for r in reversed(new):
                seen.add(r["id"])
                status     = r["status"]
                status_col = _status_color(status)
                risk       = r["risk_score"] or 0.0
                risk_str   = (f"[bold red]risk={risk:.2f}[/]" if risk > 0.5
                              else f"[dim]risk={risk:.2f}[/]")
                flags_str  = (f"[yellow]{r['flag_count']} flags[/]"
                              if r["flag_count"] else "[dim]clean[/]")

                console.print(
                    f"[dim]{_ts(r['ts'])}[/] "
                    f"[cyan]{r['task_id']}[/] "
                    f"[{status_col}]{status:8}[/] "
                    f"{risk_str} {flags_str} "
                    f"[dim]{(r['description'] or '')[:50]}[/]"
                )
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[dim]Monitor stopped.[/dim]")


if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "log"

    if cmd == "log":
        show_dispatch_log()
    elif cmd == "flags":
        sev = sys.argv[2] if len(sys.argv) > 2 else None
        show_flags(severity=sev)
    elif cmd == "summary":
        show_threat_summary()
    elif cmd == "tail":
        live_tail()
    else:
        print("Usage: python -m sentinel.cli [log|flags|flags CRITICAL|summary|tail]")
