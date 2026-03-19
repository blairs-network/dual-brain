# sentinel/__init__.py
"""
SENTINEL — Prompt Injection Detection for Agentic Stacks
"""
from sentinel.core.engine import Sentinel
from sentinel.core.models import Task, ToolCall, DetectionResult

__version__ = "0.1.0"
__all__ = ["Sentinel", "Task", "ToolCall", "DetectionResult"]
