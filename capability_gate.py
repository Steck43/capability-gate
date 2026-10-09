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

import hashlib
import json
import os
import re
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import Enum

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

_GENESIS = "0" * 64


class _StrictLoader(yaml.SafeLoader):
    """Refuse duplicate keys and YAML merge keys (``<<``)."""


def _construct_mapping_strict(loader: yaml.SafeLoader, node: MappingNode, deep=False):
    if not isinstance(node, MappingNode):
        raise ConstructorError(
            None,
            None,
            f"expected a mapping node, got {node.id}",
            node.start_mark,
        )
    mapping: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key == "<<":
            raise ConstructorError(
                None,
                None,
                "YAML merge keys are refused",
                key_node.start_mark,
            )
        if key in mapping:
            raise ConstructorError(
                None,
                None,
                f"duplicate YAML key: {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


def _refuse_merge(loader: yaml.SafeLoader, node) -> None:
    raise ConstructorError(
        None,
        None,
        "YAML merge keys are refused",
        node.start_mark,
    )


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping_strict,
)
_StrictLoader.add_constructor("tag:yaml.org,2002:merge", _refuse_merge)


def load_yaml_mapping(text: str) -> dict:
    """Parse YAML that must be a mapping, without duplicate or merge keys."""
    data = yaml.load(text, Loader=_StrictLoader)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"YAML root must be a mapping, got {type(data).__name__}")
    return data

_TRACE_FIELDS = ("session_id", "turn_id", "task_id", "tool_call_id")
_LOG_ALLOWED = frozenset(
    {
        "ts",
        "mode",
        "verdict",
        "reason",
        "skill",
        "tool",
        "paths",
        "enforced",
        "session_id",
        "turn_id",
        "task_id",
        "tool_call_id",
        "arg_summary",
        "trace_id",
        "span_id",
        "parent",
        "start",
        "end",
        "input",
        "output",
        "score",
        "run_id",
    }
)


def checked_log_record(record: Mapping) -> dict:
    """Unknown JSONL keys fail closed. Sitting run_id is optional."""
    out = dict(record)
    extra = sorted(k for k in out if k not in _LOG_ALLOWED)
    if extra:
        raise ValueError("unknown jsonl keys: " + ", ".join(extra))
    return out


def _hash_log_line(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def _witness_path(log_path: str) -> str:
    return f"{log_path}.witness"


def _read_witness(witness_path: str) -> dict:
    with open(witness_path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("audit log witness malformed")
    head = data.get("head")
    count = data.get("count")
    if not isinstance(head, str) or not isinstance(count, int) or count < 0:
        raise ValueError("audit log witness malformed")
    return {"head": head, "count": count}


def _write_witness(witness_path: str, head: str, count: int) -> None:
    payload = json.dumps({"head": head, "count": count}, sort_keys=True) + "\n"
    directory = os.path.dirname(witness_path) or "."
    os.makedirs(directory, exist_ok=True)
    fd = os.open(witness_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, payload.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


def _verify_log(log_path: str) -> tuple[str, int]:
    """Return (head hash, record count). Check parent links and the witness."""
    witness_path = _witness_path(log_path)
    witness = _read_witness(witness_path) if os.path.exists(witness_path) else None

    prev = _GENESIS
    count = 0
    if not os.path.exists(log_path):
        if witness is not None and (witness["count"] != 0 or witness["head"] != _GENESIS):
            raise ValueError("audit log missing but witness present")
        return _GENESIS, 0

    with open(log_path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line:
                continue
            rec = json.loads(line)
            if rec.get("parent") != prev:
                raise ValueError("audit log hash chain broken")
            prev = _hash_log_line(line)
            count += 1

    if witness is not None and (
        witness["count"] != count or witness["head"] != prev
    ):
        raise ValueError("audit log witness mismatch")
    return prev, count


def verify_hash_chain(log_path: str) -> str:
    """Return the hash of the last JSONL line, or genesis if none exist.

    Each record's parent is the hash of the previous line. A sibling witness
    file stores the head hash and record count so truncation and whole-log
    deletion fail closed the same way a rewrite does. Fail closed instead of
    appending onto a broken chain.
    """
    head, _count = _verify_log(log_path)
    return head


_PATH_LIKE_KEYS = frozenset(
    {
        "path",
        "target",
        "workdir",
        "output_path",
        "workspace_path",
        "file_path",
        "directory",
        "cwd",
    }
)
_CONTENT_KEYS = frozenset(
    {
        "content",
        "file_content",
        "patch",
        "code",
        "command",
        "text",
        "body",
        "message",
        "data",
        "stdout",
        "stderr",
        "output",
    }
)


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
                content_lengths[ks] = len(
                    val.encode("utf-8", errors="surrogatepass")
                )
            elif val is not None and not isinstance(val, (bool, int, float)):
                content_lengths[ks] = len(
                    str(val).encode("utf-8", errors="surrogatepass")
                )
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
                out.append(".*")  # ** crosses separators
                i += 2
                if i < n and glob[i] == "/":
                    i += 1  # collapse the slash after **
                continue
            out.append("[^/]*")  # * stays within a segment
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    out.append("$")
    return re.compile("".join(out))


def _real_glob(glob: str) -> str:
    # Resolve the literal prefix of a grant, so a grant rooted at a symlink
    # still matches its own files once request paths are resolved.
    # Split on both separators: a Windows grant is spelled with backslashes.
    parts = re.split(r"[\\/]", glob)
    i = next((k for k, seg in enumerate(parts) if "*" in seg or "?" in seg), len(parts))
    prefix = os.path.realpath(os.sep.join(parts[:i]) or os.sep)
    rest = parts[i:]
    return os.path.join(prefix, *rest) if rest else prefix


def _path_allowed(path: str, globs: Iterable[str]) -> bool:
    # Request paths are not expanded. The tool may expand "~" or "$VAR"
    # differently, or not at all, so the gate refuses to guess.
    if "$" in path or path.startswith("~"):
        return False
    # Match the file the name resolves to, not the string. An in-grant symlink
    # to an off-grant file is denied. A swap between this check and the
    # tool's open is not closed here; that needs open-by-fd in the host.
    real = os.path.realpath(path)
    return any(
        _glob_to_regex(os.path.normpath(_real_glob(g))).match(real) for g in globs
    )


# --- the decision ---------------------------------------------------------


def _absolute(path: str, base_dir: str | None) -> str | None:
    """The absolute path a relative request names, or None with no usable base.

    A path that needs ``~`` or ``$VAR`` expansion is returned as given, so
    ``_path_allowed`` refuses it the same way it always has.
    """
    if os.path.isabs(path) or "$" in path or path.startswith("~"):
        return path
    if not base_dir or not os.path.isabs(base_dir):
        return None
    return os.path.normpath(os.path.join(base_dir, path))


def _decide(
    policy: Policy,
    skill: str,
    tool: str,
    paths: Sequence[str],
    base_dir: str | None = None,
) -> Decision:
    resolved = []
    for p in paths:
        a = _absolute(p, base_dir)
        if a is None:
            return Decision(
                Verdict.DENY,
                f"relative path '{p}' has no base folder to resolve against",
                skill,
                tool,
                tuple(paths),
            )
        resolved.append(a)
    paths = resolved
    ptuple = tuple(paths)
    rule = policy.skills.get(skill)
    if rule is None:
        return Decision(
            Verdict.DENY, f"skill '{skill}' not in allowlist", skill, tool, ptuple
        )
    if tool not in rule.tools:
        return Decision(
            Verdict.DENY, f"tool '{tool}' not granted to '{skill}'", skill, tool, ptuple
        )
    for p in paths:
        if not _path_allowed(p, rule.path_globs):
            return Decision(
                Verdict.DENY,
                f"path '{p}' outside allowlist for '{skill}'",
                skill,
                tool,
                ptuple,
            )
    if tool in policy.require_approval:
        return Decision(
            Verdict.ASK, f"tool '{tool}' requires human approval", skill, tool, ptuple
        )
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
        refuse: str | None = None,
        base_dir: str | None = None,
    ) -> Decision:
        """Decide one call. ``refuse`` is set by an adapter that could not read
        the call's files from its arguments; the call is then denied and logged
        like any other denial. ``base_dir`` is the absolute folder the tool will
        resolve a relative path against; without one a relative path is denied.
        The decision, and the log, carry the absolute paths that were checked."""
        # Everything that can throw before a recorded decision sits inside this
        # boundary (H1-1). A lone surrogate in args used to raise in
        # summarize_args before the try, so observe returned with no log line.
        try:
            norm_trace = _normalize_trace(trace)
            arg_summary = summarize_args(args)
            if refuse is not None:
                decision = Decision(
                    Verdict.DENY,
                    f"arguments refused: {refuse}",
                    str(skill),
                    str(tool),
                    tuple(str(p) for p in paths),
                )
            else:
                decision = _decide(
                    self._policy,
                    str(skill),
                    str(tool),
                    [str(p) for p in paths],
                    base_dir,
                )
            # observe mode records the true verdict but does not act on it
            decision = replace(decision, enforced=(self._mode == ENFORCE))
            self._log(decision, trace=norm_trace, arg_summary=arg_summary)
            return decision
        except Exception as exc:  # any failure is a denial, on purpose
            decision = Decision(
                Verdict.DENY,
                f"gate error, failing closed: {exc!r}",
                str(skill),
                str(tool),
                tuple(str(p) for p in paths),
            )
            decision = replace(decision, enforced=(self._mode == ENFORCE))
            try:
                self._log(decision, trace=None, arg_summary=None)
            except Exception:
                # Still return the denial. Enforce callers that need the raise
                # see it from _log only when the outer path did not already
                # catch; here the record attempt failed after a prior error.
                if self._mode == ENFORCE:
                    raise
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
        run_id = os.environ.get("SITTING_RUN_ID", "").strip()
        if run_id:
            record["run_id"] = run_id
        head, count = _verify_log(self._log_path)
        record["parent"] = head
        record = checked_log_record(record)
        body = json.dumps(record, sort_keys=True)
        line = body + "\n"
        try:
            os.makedirs(os.path.dirname(self._log_path) or ".", exist_ok=True)
            fd = os.open(self._log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                before = os.fstat(fd).st_size
                payload = line.encode("utf-8")
                written = os.write(fd, payload)
                if written != len(payload):
                    # F-2: roll back a torn line so the chain stays readable.
                    os.ftruncate(fd, before)
                    raise OSError(
                        f"short audit log write: {written} of {len(payload)} bytes"
                    )
                os.fsync(fd)  # durable before the action runs
            finally:
                os.close(fd)
            _write_witness(
                _witness_path(self._log_path),
                _hash_log_line(body),
                count + 1,
            )
        except Exception:
            # A gate that cannot record its own decisions is not trustworthy.
            # Re-raise so the adapter treats that as a denial in enforce mode.
            raise
