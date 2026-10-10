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
        for name, rule in skills.items():
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
                if g.endswith("/**") or g.endswith("\\**"):
                    root = _canon(g[:-3])
                    canon_paths += [
                        root,
                        root + os.sep + "**",
                    ]  # the root itself, and below it
                else:
                    canon_paths.append(_canon(g))
            rule["paths"] = canon_paths
    return load_policy(raw)


def _glob_climbs(pat: str) -> bool:
    """True when a Glob pattern can reach a parent directory (including obfuscations)."""
    s = pat.replace("\\", "/")
    if os.path.isabs(pat) or pat.startswith(("~", "\\", "/")):
        return True
    if ".." in s.split("/"):
        return True
    if "[.][.]" in s or "[..]" in s:
        return True
    for m in re.finditer(r"\{([^}]*)\}", s):
        for alt in m.group(1).split(","):
            a = alt.strip().replace("\\", "/")
            if (
                a == ".."
                or a.startswith("../")
                or a.startswith("..\\")
                or "/../" in f"/{a}/"
            ):
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


def _pre(event: dict) -> None:
    from capability_gate import Gate, Verdict

    tool = str(event.get("tool_name", ""))
    ti = event.get("tool_input") or {}
    if not isinstance(ti, dict):
        raise ValueError("tool_input is not an object")
    cwd = str(event.get("cwd") or os.getcwd())
    policy = _load_policy()
    paths = _paths(tool, ti, cwd)
    os.makedirs(os.path.dirname(_log_path()) or ".", exist_ok=True)
    gate = Gate(policy, log_path=_log_path(), mode="enforce")
    trace = {k: str(event[k]) for k in ("session_id",) if event.get(k)}
    if event.get("tool_use_id"):
        trace["tool_call_id"] = str(event["tool_use_id"])
    decision = gate.evaluate(SKILL, tool, paths, trace=trace, args=ti)
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
