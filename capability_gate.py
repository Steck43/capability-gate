"""
The tool-gate. Stage 1, the decider.

An agent thinks and it acts. Thinking is text and it is harmless. Acting is a
tool call, and every real consequence runs through one. In most setups the line
from thought to action is unbroken. This closes it. The agent does not run the
tool. It asks the gate, and the gate answers allow, deny, or ask. The model
proposes. The gate disposes.

The decision is deterministic code I can read, not the probabilistic model I
cannot fully trust, because the model is the thing being guarded against.
Safety is a property of what a skill can reach, not of what the model can be
talked into. Deny by default. If it is not on the list, it does not happen.

This file is the decider only, and it holds no Hermes import on purpose. The
logic has to be testable without the runtime in the loop and swappable under a
clean boundary. The Hermes adapter is the doorway. This is the doorman.

Four properties, each pinned by a test:
- Deny by default. An unlisted skill, tool, or path is denied.
- Complete mediation. Every call and every path it touches is checked.
- Least privilege. A skill does only what its entry grants.
- Fail closed. Any error in the decision path is a denial. This one is
  load-bearing. The Hermes hook framework catches hook errors and lets the
  agent continue, so it fails open. A gate cannot lean on the thing it guards.
  It stops itself.

Log before act. The decision is flushed to durable storage before it returns,
so the record survives a crash mid-action and the audit trail is real from the
first day.

Two modes, for safe rollout. In enforce mode a denial blocks. In observe mode
the gate decides and logs exactly as it would, and blocks nothing. Observe is
how a new allowlist gets built against real behavior without breaking the
skills already running. Read the log, write the grants to match, then flip to
enforce. Observe enforces nothing, including its own errors, because that is
what observe means. Protection lives in enforce mode. Do not lean on observe.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Iterable, Mapping, Sequence


_TRACE_FIELDS = ("session_id", "turn_id", "task_id", "tool_call_id")

_PATH_LIKE_KEYS = frozenset({
    "path", "target", "workdir", "output_path", "workspace_path",
    "file_path", "directory", "cwd",
})
_CONTENT_KEYS = frozenset({
    "content", "file_content", "patch", "code", "command", "text",
    "body", "message", "data", "stdout", "stderr", "output",
})


def summarize_args(args: Mapping | None) -> dict:
    """Safe argument summary: keys, path-like values, content byte lengths only."""
    if not isinstance(args, Mapping):
        return {"keys": []}
    keys = sorted(str(k) for k in args.keys())
    paths: dict[str, str] = {}
    content_lengths: dict[str, int] = {}
    for key, val in args.items():
        ks = str(key)
        if ks in _PATH_LIKE_KEYS or ks.endswith("_path"):
            if isinstance(val, str) and val:
                paths[ks] = val
        if ks in _CONTENT_KEYS or ks.endswith("_content"):
            if isinstance(val, str):
                content_lengths[ks] = len(val.encode("utf-8"))
            elif val is not None and not isinstance(val, (bool, int, float)):
                content_lengths[ks] = len(str(val).encode("utf-8"))
    out: dict = {"keys": keys}
    if paths:
        out["paths"] = paths
    if content_lengths:
        out["content_lengths"] = content_lengths
    return out


def _normalize_trace(trace: Mapping[str, str] | None) -> dict[str, str]:
    if not isinstance(trace, Mapping):
        return {}
    out: dict[str, str] = {}
    for field in _TRACE_FIELDS:
        val = trace.get(field)
        if val is not None and str(val):
            out[field] = str(val)
    return out


class Verdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"  # reserved for Stage 3; the Stage 1 adapter maps ASK -> block


ENFORCE = "enforce"
OBSERVE = "observe"


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: str
    skill: str
    tool: str
    paths: tuple[str, ...] = ()
    enforced: bool = True  # in observe mode this is False; a non-allow verdict is logged but not acted on

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "reason": self.reason,
            "skill": self.skill,
            "tool": self.tool,
            "paths": list(self.paths),
            "enforced": self.enforced,
        }


@dataclass(frozen=True)
class SkillRule:
    tools: frozenset[str]
    path_globs: tuple[str, ...]


@dataclass(frozen=True)
class Policy:
    skills: Mapping[str, SkillRule]
    require_approval: frozenset[str] = field(default_factory=frozenset)


class PolicyError(ValueError):
    """Raised only at load time. A malformed policy fails loudly here, never
    silently at decision time where the failure would be a security gap."""


# --- policy loading -------------------------------------------------------

def load_policy(mapping: Mapping) -> Policy:
    if not isinstance(mapping, Mapping):
        raise PolicyError("policy root must be a mapping")
    skills_in = mapping.get("skills", {})
    if not isinstance(skills_in, Mapping):
        raise PolicyError("'skills' must be a mapping")
    skills: dict[str, SkillRule] = {}
    for name, rule in skills_in.items():
        if not isinstance(rule, Mapping):
            raise PolicyError(f"skill '{name}' must be a mapping")
        tools = rule.get("tools", [])
        paths = rule.get("paths", [])
        if not isinstance(tools, Sequence) or isinstance(tools, str):
            raise PolicyError(f"skill '{name}': 'tools' must be a list")
        if not isinstance(paths, Sequence) or isinstance(paths, str):
            raise PolicyError(f"skill '{name}': 'paths' must be a list")
        expanded: list[str] = []
        for p in paths:
            ep = _expand(str(p))
            if "$" in ep:
                raise PolicyError(
                    f"skill '{name}': path '{p}' has an unresolved variable after expansion "
                    f"('{ep}'). Set the variable (e.g. HERMES_HOME) before loading, or use an "
                    f"absolute path. Refusing to load a grant that would silently match nothing."
                )
            expanded.append(ep)
        skills[str(name)] = SkillRule(
            tools=frozenset(str(t) for t in tools),
            path_globs=tuple(expanded),
        )
    approval = mapping.get("require_approval", [])
    if not isinstance(approval, Sequence) or isinstance(approval, str):
        raise PolicyError("'require_approval' must be a list")
    return Policy(skills=skills, require_approval=frozenset(str(t) for t in approval))


# --- path expansion and glob matching -------------------------------------
# Supports ~ and $VARS in policy paths, so an allowlist written against
# $HERMES_HOME is portable across machines and Hermes homes. An unset variable
# is left literal, which then matches no real path, so a missing env var fails
# closed (denies) rather than silently widening a grant.
#
# Glob syntax: ** (any depth, including separators), * (within one segment), ? .
# Small and readable on purpose, so the matching rule is auditable rather than
# hidden inside a glob dependency.

def _expand(path: str) -> str:
    return os.path.expandvars(os.path.expanduser(path))


def _glob_to_regex(glob: str) -> re.Pattern:
    i, n = 0, len(glob)
    out = ["^"]
    while i < n:
        c = glob[i]
        if c == "*":
            if i + 1 < n and glob[i + 1] == "*":
                out.append(".*")   # ** crosses separators
                i += 2
                if i < n and glob[i] == "/":
                    i += 1          # collapse the slash after **
                continue
            out.append("[^/]*")     # * stays within a segment
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    out.append("$")
    return re.compile("".join(out))


def _path_allowed(path: str, globs: Iterable[str]) -> bool:
    norm = os.path.normpath(_expand(path))
    return any(_glob_to_regex(os.path.normpath(g)).match(norm) for g in globs)


# --- the decision ---------------------------------------------------------

def _decide(policy: Policy, skill: str, tool: str, paths: Sequence[str]) -> Decision:
    ptuple = tuple(paths)
    rule = policy.skills.get(skill)
    if rule is None:
        return Decision(Verdict.DENY, f"skill '{skill}' not in allowlist", skill, tool, ptuple)
    if tool not in rule.tools:
        return Decision(Verdict.DENY, f"tool '{tool}' not granted to '{skill}'", skill, tool, ptuple)
    for p in paths:
        if not _path_allowed(p, rule.path_globs):
            return Decision(Verdict.DENY, f"path '{p}' outside allowlist for '{skill}'", skill, tool, ptuple)
    if tool in policy.require_approval:
        return Decision(Verdict.ASK, f"tool '{tool}' requires human approval", skill, tool, ptuple)
    return Decision(Verdict.ALLOW, "allowed by policy", skill, tool, ptuple)


class Gate:
    """Wraps the decision with mode, fail-closed handling, and log-before-act."""

    def __init__(self, policy: Policy, log_path: str, mode: str = ENFORCE):
        if mode not in (ENFORCE, OBSERVE):
            raise ValueError(f"mode must be '{ENFORCE}' or '{OBSERVE}', got {mode!r}")
        self._policy = policy
        self._log_path = log_path
        self._mode = mode

    @property
    def mode(self) -> str:
        return self._mode

    def set_mode(self, mode: str) -> None:
        """Update mode without rebuilding policy (E2: config flip mid-process)."""
        if mode not in (ENFORCE, OBSERVE):
            raise ValueError(f"mode must be '{ENFORCE}' or '{OBSERVE}', got {mode!r}")
        self._mode = mode

    def evaluate(
        self,
        skill: str,
        tool: str,
        paths: Sequence[str] = (),
        *,
        trace: Mapping[str, str] | None = None,
        args: Mapping | None = None,
    ) -> Decision:
        norm_trace = _normalize_trace(trace)
        arg_summary = summarize_args(args)
        try:
            decision = _decide(self._policy, str(skill), str(tool), [str(p) for p in paths])
        except Exception as exc:  # any failure is a denial, on purpose
            decision = Decision(Verdict.DENY, f"gate error, failing closed: {exc!r}",
                                str(skill), str(tool), tuple(str(p) for p in paths))
        # observe mode records the true verdict but does not act on it
        decision = replace(decision, enforced=(self._mode == ENFORCE))
        self._log(decision, trace=norm_trace, arg_summary=arg_summary)
        return decision

    def _log(
        self,
        decision: Decision,
        *,
        trace: Mapping[str, str] | None = None,
        arg_summary: Mapping | None = None,
    ) -> None:
        record = {"ts": time.time(), "mode": self._mode, **decision.as_dict()}
        if trace:
            for field in _TRACE_FIELDS:
                if field in trace:
                    record[field] = trace[field]
        if arg_summary:
            record["arg_summary"] = dict(arg_summary)
        line = json.dumps(record, sort_keys=True) + "\n"
        try:
            os.makedirs(os.path.dirname(self._log_path) or ".", exist_ok=True)
            fd = os.open(self._log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, line.encode("utf-8"))
                os.fsync(fd)  # durable before the action runs
            finally:
                os.close(fd)
        except Exception:
            # A gate that cannot record its own decisions is not trustworthy.
            # Re-raise so the adapter treats that as a denial in enforce mode.
            raise
