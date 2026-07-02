"""Hermes plugin adapter for capability-gate (Stage 1, Branch B).

Skill identity is not available on the pre_tool_call dispatch path on Hermes
0.16.0, so enforcement uses the skill-agnostic "*" bucket until skill tracking
lands.
"""

from __future__ import annotations

import os
from typing import Any, Optional

import yaml

try:
    from .capability_gate import Gate, load_policy
except ImportError:
    from capability_gate import Gate, load_policy

_HERE = os.path.dirname(__file__)
_BLOCK = lambda msg: {"action": "block", "message": msg}

# Path-mediatable tools only (registry: file_tools.py). Opaque tools are
# require_approval, not path-mapped. web_search has no path arg.
_PATH_ARG = {
    "read_file": "path",
    "write_file": "path",
    "patch": "path",
    "search_files": "path",
}


def _hermes_home() -> str:
    return os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")


def _read_mode_from_config(default: str = "observe") -> str:
    from hermes_cli.config import cfg_get, load_config

    cfg = load_config()
    mode = cfg_get(cfg, "plugins", "entries", "capability-gate", "mode", default=default)
    if mode not in ("observe", "enforce"):
        return default
    return str(mode)


def _resolve_skill(kwargs: dict) -> str:
    return "*"


def _extract_trace(kwargs: dict, task_id: str) -> dict[str, str]:
    trace: dict[str, str] = {}
    for key in ("session_id", "turn_id", "tool_call_id"):
        val = kwargs.get(key)
        if val:
            trace[key] = str(val)
    if task_id:
        trace["task_id"] = str(task_id)
    return trace


def _extract_paths(tool_name: str, args: Any) -> list[str]:
    if not isinstance(args, dict):
        return []
    key = _PATH_ARG.get(tool_name)
    if not key or key not in args:
        if tool_name == "search_files" and isinstance(args.get("target"), str) and args["target"]:
            return [args["target"]]
        return []
    val = args[key]
    if isinstance(val, str) and val:
        return [val]
    return []


def _build_gate(mode: str) -> Gate:
    allowlist = os.path.join(_HERE, "allowlist.yaml")
    with open(allowlist, encoding="utf-8") as f:
        policy = load_policy(yaml.safe_load(f))
    log_path = os.path.join(_hermes_home(), "logs", "capability-gate.jsonl")
    return Gate(policy, log_path=log_path, mode=mode)


def register(ctx) -> None:
    mode = _read_mode_from_config(default="observe")
    try:
        gate = _build_gate(mode)
    except Exception as exc:
        def _closed(tool_name: str, args: dict, task_id: str, **kwargs: Any) -> Optional[dict]:
            if mode == "observe":
                return None
            return _BLOCK(f"capability-gate failed to load, failing closed: {exc!r}")

        ctx.register_hook("pre_tool_call", _closed)
        return

    def pre_tool_call(
        tool_name: str,
        args: dict,
        task_id: str,
        **kwargs: Any,
    ) -> Optional[dict]:
        try:
            skill = _resolve_skill(kwargs)
            paths = _extract_paths(tool_name, args)
            decision = gate.evaluate(
                skill,
                tool_name,
                paths,
                trace=_extract_trace(kwargs, task_id),
                args=args if isinstance(args, dict) else None,
            )
            if decision.verdict.value == "allow" or not decision.enforced:
                return None
            if decision.verdict.value == "ask":
                return _BLOCK(
                    "requires human approval (Stage 3 not yet wired): " + decision.reason
                )
            return _BLOCK(decision.reason)
        except Exception as exc:
            if gate.mode == "observe":
                return None
            return _BLOCK(f"capability-gate error, failing closed: {exc!r}")

    ctx.register_hook("pre_tool_call", pre_tool_call)
