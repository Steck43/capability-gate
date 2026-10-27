"""capability-gate as a Claude Code hook.

    PreToolUse   python claude_code_hook.py          decide; exit 0 = no objection, exit 2 = block
    PostToolUse  python claude_code_hook.py --post   flag a call whose input changed after the check

Claude Code blocks a tool call only when a hook exits 2 or returns a JSON deny.
A hook that crashes, cannot start, or times out does not block: the call goes
on. So every failure inside this file ends in exit 2 with a reason on stderr,
and a watchdog denies before Claude Code's own timeout can fire.

Allow prints nothing. Claude Code reads that as "no decision" and its own
permission rules still apply, so this hook can only take access away. It never
prints JSON on PreToolUse, so it can never rewrite a call (no updatedInput).

Claude Code sends no skill label. Every call is judged as the skill
UNLABELED, which the allowlist must grant by name; a "*" grant never applies.
"""

from __future__ import annotations

import fnmatch
import math
import os
import re
import sys
import threading

DEFAULT_DEADLINE_S = 5.0
# Claude Code treats a hook timeout as allow; stay under its ~15s ceiling.
MAX_DEADLINE_S = 14.0
SKILL = "UNLABELED"

# Tool name -> the argument that names the file it touches.
# A tool missing from this map is denied (closed schema); an empty path list
# must never mean "skip the path check".
_PATH_ARG = {
    "Read": "file_path",
    "Write": "file_path",
    "Edit": "file_path",
    "MultiEdit": "file_path",
    "NotebookEdit": "notebook_path",
    "Glob": "path",
    "Grep": "path",
}
_DIR_DEFAULT_CWD = {"Glob", "Grep"}  # no path argument means the working directory


def _deny(reason: str) -> None:
    try:
        sys.stderr.write(f"capability-gate: {reason}\n")
        sys.stderr.flush()
    finally:
        os._exit(2)


def _deadline_s() -> float:
    try:
        deadline = float(os.environ.get("CG_CC_DEADLINE_S", DEFAULT_DEADLINE_S))
    except ValueError:
        return DEFAULT_DEADLINE_S
    if not math.isfinite(deadline) or deadline <= 0:
        return DEFAULT_DEADLINE_S
    return min(deadline, MAX_DEADLINE_S)


def _start_watchdog() -> None:
    deadline = _deadline_s()
    t = threading.Timer(
        deadline, _deny, args=(f"deadline of {deadline}s hit, denying",)
    )
    t.daemon = True
    t.start()


def _here() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def _allowlist_path() -> str:
    return os.environ.get("CG_CC_ALLOWLIST") or os.path.join(
        _here(), "claude_code_allowlist.yaml"
    )


def _log_path() -> str:
    return os.environ.get("CG_CC_LOG") or os.path.join(
        os.path.expanduser("~"), ".capability-gate", "claude-code.jsonl"
    )


def _canon(path: str) -> str:
    """One spelling per file: absolute, links resolved, case folded on Windows."""
    return os.path.normcase(os.path.realpath(path))


def _load_policy():
    import yaml

    from capability_gate import PolicyError, load_policy

    with open(_allowlist_path(), encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    if not isinstance(raw, dict):
        raise PolicyError("allowlist root must be a mapping")
    skills = raw.get("skills")
    if isinstance(skills, dict):
        for rule in skills.values():
            if not isinstance(rule, dict) or not isinstance(
                rule.get("paths", []), list
            ):
                continue  # load_policy raises on these
            canon_paths = []
            for g in rule.get("paths", []):
                g = os.path.expandvars(os.path.expanduser(str(g)))
                if "$" in g:
                    raise PolicyError(
                        f"grant {g!r} has an unset variable; refusing to load"
                    )
                body = g.replace("**", "")
                # A single * or ? matches within one "/" segment in the gate's glob,
                # which on Windows would cross a backslash. Only "<root>/**" is allowed.
                if "*" in body or "?" in body:
                    raise PolicyError(
                        f"grant {g!r}: only a trailing /** wildcard is supported here"
                    )
                if g.endswith(("/**", "\\**")):
                    root = _canon(g[:-3])
                    canon_paths += [
                        root,
                        root + os.sep + "**",
                    ]  # the root itself, and below it
                else:
                    canon_paths.append(_canon(g))
            rule["paths"] = canon_paths
    return load_policy(raw)


def _expand_braces(pat: str) -> list[str]:
    """Expand nested `{a,{b,c}}` style alternatives (innermost first)."""
    m = re.search(r"\{([^{}]*)\}", pat)
    if not m:
        return [pat]
    out: list[str] = []
    for alt in m.group(1).split(","):
        out.extend(_expand_braces(pat[: m.start()] + alt + pat[m.end() :]))
    return out


def _collapse_dot_classes(pat: str) -> str:
    """Turn `[.]` / `[\\.]` / `[..]` into literal dots before separator normalize."""
    t = re.sub(r"\[\\?\.\]", ".", pat)
    return t.replace("[..]", "..")


def _segment_climbs(seg: str) -> bool:
    """True when one path segment can name a parent after glob obfuscation."""
    if not seg:
        return False
    if ":" in seg:
        return True
    t = _collapse_dot_classes(seg)
    if t == ".." or t.startswith(".."):
        return True
    if "*" not in t and fnmatch.fnmatchcase("..", t):
        return True
    core = re.sub(r"[?*]", "", t)
    return core == ".."


def _glob_climbs(pat: str) -> bool:
    """True when a Glob pattern can reach a parent directory (including obfuscations)."""
    if os.path.isabs(pat) or pat.startswith(("~", "\\", "/")):
        return True
    # Windows drive-qualified even when os.path.isabs is false (e.g. C:foo).
    if len(pat) >= 2 and pat[1] == ":":
        return True
    # Collapse dot classes before turning remaining backslashes into separators,
    # so `[\.][\.]/*` does not become `[/.][/.]/*`.
    collapsed = _collapse_dot_classes(pat)
    s = collapsed.replace("\\", "/")
    for expanded in _expand_braces(s):
        if os.path.isabs(expanded) or (len(expanded) >= 2 and expanded[1] == ":"):
            return True
        for seg in expanded.split("/"):
            if _segment_climbs(seg):
                return True
    return False


def _paths(tool: str, ti: dict, cwd: str) -> list[str]:
    if tool not in _PATH_ARG:
        raise ValueError(f"{tool} has no path schema in the Claude Code adapter")
    if tool == "Glob":
        pat = str(ti.get("pattern", ""))
        if _glob_climbs(pat):
            raise ValueError(
                f"Glob pattern {pat!r} is absolute or climbs out of its path"
            )
    key = _PATH_ARG[tool]
    raw = ti.get(key)
    if raw in (None, "") and tool in _DIR_DEFAULT_CWD:
        raw = cwd
    if not isinstance(raw, str) or not raw:
        raise ValueError(f"{tool} call has no usable {key}")
    if "$" in raw or raw.startswith("~"):
        raise ValueError(f"{key} {raw!r} has an unexpanded $ or ~")
    full = raw if os.path.isabs(raw) else os.path.join(cwd, raw)
    return [_canon(full)]


def _input_digest(ti) -> str:
    import hashlib
    import json

    return hashlib.sha256(
        json.dumps(ti, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _inputs_log() -> str:
    return _log_path() + ".inputs"


def _record_input(tool_use_id: str, ti) -> None:
    import json

    line = json.dumps({"tool_use_id": tool_use_id, "sha256": _input_digest(ti)}) + "\n"
    fd = os.open(_inputs_log(), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


_WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})


def _own_files() -> list[str]:
    """The files that decide or record this hook, in canonical form."""
    import capability_gate

    log = _log_path()
    names = [
        _allowlist_path(),
        log,
        log + ".inputs",
        log + ".witness",
        log + ".lock",
        log + ".halt",
        log + ".anchor",
        capability_gate.__file__,
    ]
    return [_canon(p) for p in names]


def _own_file_hit(paths: list[str]) -> str | None:
    """Why a write target is one of the hook's own files, or None."""
    own = set(_own_files())
    hook_dir = _canon(_here()) + os.sep
    for p in paths:
        if p in own or p.startswith(hook_dir):
            return f"path '{p}' is one of the adapter's own policy, log, or code files"
    return None


def _grant_reaches_own_files(policy) -> str | None:
    """A write grant that covers the hook's own files lets the agent widen it.

    Checked on every start, before any call is decided: such a policy is
    refused outright rather than trusted call by call.
    """
    from capability_gate import Verdict, _decide

    targets = [*_own_files(), _canon(os.path.join(_here(), "claude_code_hook.py"))]
    for tool in sorted(_WRITE_TOOLS):
        for target in targets:
            if _decide(policy, SKILL, tool, [target]).verdict is Verdict.ALLOW:
                return (
                    f"refusing to start: the {tool} grant covers the adapter's own "
                    f"file '{target}'"
                )
    return None


def _isolate_route():
    """adapters/isolate_route.py, loaded by its path beside this file."""
    import importlib.util

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "isolate_route.py")
    spec = importlib.util.spec_from_file_location("capability_gate_isolate_route", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look the module up while it runs
    spec.loader.exec_module(module)
    return module


def _cc_grant_config_path() -> str | None:
    return os.environ.get("CG_CC_GRANT_CONFIG") or None


def _cc_grant_session_path() -> str | None:
    return os.environ.get("CG_CC_GRANT_SESSION") or None


def _pre(event: dict) -> None:
    from capability_gate import Decision, Gate, Verdict, record_decision

    tool = str(event.get("tool_name", ""))
    ti = event.get("tool_input") or {}
    if not isinstance(ti, dict):
        raise ValueError("tool_input is not an object")
    cwd = str(event.get("cwd") or os.getcwd())
    policy = _load_policy()
    paths = _paths(tool, ti, cwd)
    os.makedirs(os.path.dirname(_log_path()) or ".", exist_ok=True)
    grants = None
    grant_kwargs = {}
    try:
        from adapters.grant_forward import (
            GrantForwardError,
            load_call_kwargs,
            load_grant_config,
        )

        cfg_path = _cc_grant_config_path()
        sess_path = _cc_grant_session_path()
        # GF-L1: env set means the host opted into grants; missing file denies.
        grants = load_grant_config(cfg_path, required=bool(cfg_path))
        grant_kwargs = load_call_kwargs(sess_path, required=bool(sess_path))
    except GrantForwardError as exc:
        raise ValueError(f"grant forward refused: {exc}") from exc
    gate = Gate(policy, log_path=_log_path(), mode="enforce", grants=grants)
    trace = {k: str(event[k]) for k in ("session_id",) if event.get(k)}
    if event.get("tool_use_id"):
        trace["tool_call_id"] = str(event["tool_use_id"])
    refused = _grant_reaches_own_files(policy)
    if refused is None and tool in _WRITE_TOOLS:
        refused = _own_file_hit(paths)
    # Host session only; ignore any grant fields on the event (model-controlled).
    decision = gate.evaluate(
        SKILL, tool, paths, trace=trace, args=ti, refuse=refused, **grant_kwargs
    )
    if decision.verdict is Verdict.ISOLATE:
        # D8: a VM boot does not fit inside the hook deadline, so the task is
        # queued for the box and this call is denied on the host.
        router = _isolate_route()
        outcome = router.route_isolate(
            decision,
            tool_call_id=str(event.get("tool_use_id") or ""),
            args=ti,
            log_path=_log_path(),
            queue_only=True,
            spool=os.environ.get("CG_CC_ISOLATE_SPOOL"),
        )
        record_decision(
            _log_path(),
            "enforce",
            Decision(
                Verdict.DENY,
                outcome.message,
                SKILL,
                tool,
                tuple(paths),
                route_ticket=outcome.ticket or decision.route_ticket,
            ),
            trace=trace,
        )
        _deny(outcome.message)
    if decision.verdict is not Verdict.ALLOW:
        _deny(f"{decision.verdict.value}: {decision.reason}")
    if event.get("tool_use_id"):
        _record_input(str(event["tool_use_id"]), ti)
    os._exit(0)  # allow: no output, Claude Code's own permissions still apply


def _post(event: dict) -> None:
    """Detect, not prevent: the call already ran. Tell Claude and stop it."""
    import json

    tid = str(event.get("tool_use_id", ""))
    want = None
    try:
        with open(_inputs_log(), encoding="utf-8") as f:
            for line in f:
                rec = json.loads(line)
                if rec.get("tool_use_id") == tid:
                    want = rec.get("sha256")
    except FileNotFoundError:
        pass
    got = _input_digest(event.get("tool_input") or {})
    if want == got:
        os._exit(0)
    reason = (
        "capability-gate: no PreToolUse check is on record for this call"
        if want is None
        else "capability-gate: this call's input changed after the check; the run did not match what was allowed"
    )
    sys.stdout.write(json.dumps({"decision": "block", "reason": reason}) + "\n")
    sys.stdout.flush()
    os._exit(0)


def main() -> None:
    _start_watchdog()
    try:
        import json

        sys.path.insert(0, os.path.dirname(_here()))
        event = json.loads(sys.stdin.read())
        if not isinstance(event, dict):
            raise ValueError("hook input is not an object")
        if "--post" in sys.argv[1:]:
            _post(event)
        else:
            _pre(event)
    except BaseException as exc:  # every failure is a block, on purpose
        _deny(f"error, denying: {exc.__class__.__name__}: {exc}")


if __name__ == "__main__":
    main()
