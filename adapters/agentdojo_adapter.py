"""Dependency-free AgentDojo-to-Hermes pre-tool-call boundary.

This is an offline adapter stub. It normalizes supported AgentDojo tool names
and then delegates to the same ``pre_tool_call`` callable Hermes uses. It does
not run AgentDojo, a model, Hermes, or the box.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

_TOOLS: dict[str, tuple[str, frozenset[str]]] = {
    "filesystem.read": ("read_file", frozenset({"path", "offset", "limit"})),
    "filesystem.write": ("write_file", frozenset({"path", "content"})),
    "web.search": ("web_search", frozenset({"query", "limit"})),
    "shell.execute": (
        "terminal",
        frozenset({"command", "background", "timeout", "workdir"}),
    ),
}


class AgentDojoMappingError(ValueError):
    """The AgentDojo call cannot be represented by a closed Hermes schema."""


def map_agentdojo_call(
    tool_name: str,
    args: Mapping[str, Any],
    *,
    task_id: str,
) -> dict[str, Any]:
    """Map one supported call without forwarding output-carried metadata."""
    mapping = _TOOLS.get(tool_name)
    if mapping is None:
        raise AgentDojoMappingError(f"unsupported AgentDojo tool: {tool_name}")
    if not isinstance(args, Mapping):
        raise AgentDojoMappingError("AgentDojo arguments must be a mapping")
    hermes_name, allowed_keys = mapping
    hermes_args = {key: args[key] for key in allowed_keys if key in args}
    return {
        "tool_name": hermes_name,
        "args": hermes_args,
        "task_id": str(task_id),
    }


def pre_tool_call(
    hermes_pre_tool_call: Callable[..., dict[str, str] | None],
    tool_name: str,
    args: Mapping[str, Any],
    *,
    task_id: str,
    tool_call_id: str = "",
) -> dict[str, str] | None:
    """Normalize one call and pass it through the injected Hermes hook."""
    mapped = map_agentdojo_call(tool_name, args, task_id=task_id)
    return hermes_pre_tool_call(
        mapped["tool_name"],
        mapped["args"],
        mapped["task_id"],
        tool_call_id=tool_call_id,
    )
