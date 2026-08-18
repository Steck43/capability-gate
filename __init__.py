"""Hermes plugin adapter for capability-gate (Stage 1, Branch B).

Skill identity is not available on the pre_tool_call dispatch path on Hermes
0.16.0, so enforcement uses the skill-agnostic "*" bucket until skill tracking
lands.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

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


MODE_UNRESOLVED_PREFIX = "mode_unresolved_fail_closed"


def resolve_capability_gate_mode(
    hermes_home: str | None = None,
) -> tuple[str, str | None]:
    """Confirm mode from raw config.yaml bytes — never from merged DEFAULT.

    Returns ``(mode, unresolved_reason)``. ``unresolved_reason`` is set when a
    valid observe|enforce choice cannot be confirmed; callers must fail closed
    (block) and must not treat that as observe.
    """
    home = hermes_home or _hermes_home()
    cfg_path = Path(home) / "config.yaml"
    try:
        raw = cfg_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return "enforce", f"{MODE_UNRESOLVED_PREFIX}:unreadable"
    if not raw.strip():
        return "enforce", f"{MODE_UNRESOLVED_PREFIX}:empty"
    try:
        data = yaml.safe_load(raw)
    except Exception:
        return "enforce", f"{MODE_UNRESOLVED_PREFIX}:unparseable"
    if data is None:
        return "enforce", f"{MODE_UNRESOLVED_PREFIX}:empty"
    if not isinstance(data, dict):
        return "enforce", f"{MODE_UNRESOLVED_PREFIX}:unparseable"
    plugins = data.get("plugins")
    if not isinstance(plugins, dict):
        return "enforce", f"{MODE_UNRESOLVED_PREFIX}:missing"
    entries = plugins.get("entries")
    if not isinstance(entries, dict):
        return "enforce", f"{MODE_UNRESOLVED_PREFIX}:missing"
    entry = entries.get("capability-gate")
    if not isinstance(entry, dict):
        return "enforce", f"{MODE_UNRESOLVED_PREFIX}:missing"
    if "mode" not in entry:
        return "enforce", f"{MODE_UNRESOLVED_PREFIX}:missing"
    mode = entry.get("mode")
    if mode not in ("observe", "enforce"):
        return "enforce", f"{MODE_UNRESOLVED_PREFIX}:invalid"
    return str(mode), None


def _read_mode_from_config(default: str = "observe") -> str:
    """Legacy helper: confirmed mode only. Unknown → enforce (never silent observe)."""
    mode, unresolved = resolve_capability_gate_mode()
    if unresolved:
        return "enforce"
    return mode


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
        if (
            tool_name == "search_files"
            and isinstance(args.get("target"), str)
            and args["target"]
        ):
            return [args["target"]]
        return []
    val = args[key]
    if isinstance(val, str) and val:
        return [val]
    return []


def _build_gate(mode: str) -> Gate:
    # Guarantee HERMES_HOME before policy expansion so grants resolve the same
    # way the log path does. Without this, an unset var makes every grant match
    # nothing and the gate denies silently.
    os.environ.setdefault("HERMES_HOME", _hermes_home())
    allowlist = os.path.join(_HERE, "allowlist.yaml")
    with open(allowlist, encoding="utf-8") as f:
        policy = load_policy(yaml.safe_load(f))
    log_path = os.path.join(_hermes_home(), "logs", "capability-gate.jsonl")
    return Gate(policy, log_path=log_path, mode=mode)


def register(ctx) -> None:
    mode, _unresolved_at_register = resolve_capability_gate_mode()
    # Build Gate in confirmed or fail-closed-strict mode; unresolved calls block
    # in the hook before policy (E3).
    try:
        gate = _build_gate(mode)
    except Exception as exc:
        # Bind message before nested def — Python clears `exc` after the except suite.
        load_error = repr(exc)

        def _closed(
            tool_name: str, args: dict, task_id: str, **kwargs: Any
        ) -> dict | None:
            # E2/E3: decision-time mode; unknown mode → fail closed (not observe).
            mode_now, unresolved = resolve_capability_gate_mode()
            if unresolved:
                return _BLOCK(unresolved)
            if mode_now == "observe":
                return None
            return _BLOCK(
                f"capability-gate failed to load, failing closed: {load_error}"
            )

        ctx.register_hook("pre_tool_call", _closed)
        return

    def pre_tool_call(
        tool_name: str,
        args: dict,
        task_id: str,
        **kwargs: Any,
    ) -> dict | None:
        try:
            # E2/E3: mode at decision time from raw config — unknown → fail closed.
            mode, unresolved = resolve_capability_gate_mode()
            if unresolved:
                return _BLOCK(unresolved)
            if mode != gate.mode:
                gate.set_mode(mode)
            skill = _resolve_skill(kwargs)
            paths = _extract_paths(tool_name, args)
            decision = gate.evaluate(
                skill,
                tool_name,
                paths,
                trace=_extract_trace(kwargs, task_id),
                args=args if isinstance(args, dict) else None,
            )
            if decision.verdict.value == "allow":
                return None
            if not decision.enforced:
                # E3: reconfirm before observe passthrough — close mid-call enforce flip.
                mode2, unresolved2 = resolve_capability_gate_mode()
                if unresolved2:
                    return _BLOCK(unresolved2)
                if mode2 == "enforce":
                    gate.set_mode(mode2)
                    return _BLOCK(decision.reason)
                return None
            if decision.verdict.value == "ask":
                return _BLOCK(
                    "requires human approval (Stage 3 not yet wired): "
                    + decision.reason
                )
            return _BLOCK(decision.reason)
        except Exception as exc:
            # E3: reconfirm before observe fail-open on errors (same class as passthrough).
            mode_e, unresolved_e = resolve_capability_gate_mode()
            if unresolved_e:
                return _BLOCK(unresolved_e)
            if mode_e == "observe":
                return None
            return _BLOCK(f"capability-gate error, failing closed: {exc!r}")

    ctx.register_hook("pre_tool_call", pre_tool_call)
