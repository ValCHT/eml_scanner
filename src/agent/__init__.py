"""Minimal agentic SOC email triage runtime (TICKET-19A/B).

This package is an INDEPENDENT minimal agentic runtime. It does not modify
or extend the frozen V1 StateGraph (``src/graph.py``) and it reuses the
existing parser, typed tool adapters, evidence merge, deterministic verifier
and policy read-only:

    .eml -> src.parsing.parse_email -> agent LLM (native tool calls)
         -> existing typed adapters (virustotal / opencti / urlscan)
         -> normalized ToolResult returned to the model
         -> finalize_assessment -> src.verify -> src.policy
         -> runs/agentic/<run_id>/ artifacts

The exact tool set, the observable-id-only argument contract, the frozen
loop limits and the smoke-only measurement scope are documented in
``docs/tickets/TICKET-19A.md`` and ``docs/tickets/TICKET-19B.md``.
"""

from .client import AgentChatClient
from .models import (
    AGENT_REASONING_EFFORT,
    AGENT_TOOL_NAMES,
    DEFAULT_AGENT_LIMITS,
    FINALIZE_TOOL,
    MAX_AGENT_SECONDS,
    MAX_LLM_TURNS,
    MAX_SINGLE_LLM_SECONDS,
    MAX_TOOL_CALLS,
    MAX_TOOL_RESULT_CHARS,
    MAX_URLSCAN_CALLS,
    AgentLimits,
    AgentLLMResponse,
    AgentRunResult,
    ToolCall,
    ToolExecution,
)
from .runner import run_agentic_email
from .tools import AGENT_TOOLS, ProviderToolExecutor, parse_finalize_arguments

__all__ = [
    "AGENT_REASONING_EFFORT",
    "AGENT_TOOL_NAMES",
    "AGENT_TOOLS",
    "DEFAULT_AGENT_LIMITS",
    "FINALIZE_TOOL",
    "MAX_AGENT_SECONDS",
    "MAX_LLM_TURNS",
    "MAX_SINGLE_LLM_SECONDS",
    "MAX_TOOL_CALLS",
    "MAX_TOOL_RESULT_CHARS",
    "MAX_URLSCAN_CALLS",
    "AgentChatClient",
    "AgentLimits",
    "AgentLLMResponse",
    "AgentRunResult",
    "ProviderToolExecutor",
    "ToolCall",
    "ToolExecution",
    "parse_finalize_arguments",
    "run_agentic_email",
]
