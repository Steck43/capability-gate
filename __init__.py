"""Hermes plugin adapter for capability-gate (Stage 1, Branch B).

Hermes 0.18.0 ``get_pre_tool_call_block_message`` still has no skill argument
(dest-read 2026-09-13). ``_resolve_skill`` uses a real field when one is
present. Otherwise it stays ``*``. Do not invent a skill for the lab.
"""

from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

import yaml

try:
    from .capability_gate import Gate, load_policy, load_yaml_mapping
except ImportError:
    from capability_gate import Gate, load_policy, load_yaml_mapping

_HERE = os.path.dirname(__file__)


def _BLOCK(msg: str) -> dict[str, str]:
    return {"action": "block", "message": msg}


class ArgsRefused(Exception):
    """The call's arguments do not fit its tool's schema, so it is denied."""


# Closed argument schemas. The gate can only check the files it can see, so
# each tool lists every argument it accepts and which of them name a file. A
# tool with no entry, an argument not listed, args that are not a plain dict,
# or a path argument that is not a string is refused rather than read as "no
# paths". Keys are taken from the Hermes runtime at ccd8deaa67:
#   read_file, write_file, patch, search_files  tools/file_tools.py:2013-2110
#   skills_list                                  tools/skills_tool.py:1605-1617
#   execute_code                                 tools/code_execution_tool.py:1871-1886
#   web_search                                   tools/web_tools.py:1114-1134
#   terminal                                     tools/terminal_tool.py:2962-3004
# When Hermes adds an argument to one of these tools, calls that use it are
# denied until the key is added here.
_SCHEMAS: dict[str, dict[str, Any]] = {
    "read_file": {
        "keys": {"path", "offset", "limit"},
        "paths": ("path",),
        "required": ("path",),
    },
    "write_file": {
        "keys": {"path", "content", "cross_profile"},
        "paths": ("path",),
        "required": ("path",),
    },
    "patch": {
        "keys": {
            "mode",
            "path",
            "old_string",
            "new_string",
            "replace_all",
            "patch",
            "cross_profile",
        },
        "paths": ("path",),
    },
    "search_files": {
        "keys": {
            "pattern",
            "target",
            "path",
            "file_glob",
            "limit",
            "offset",
            "output_mode",
            "context",
        },
        "paths": ("path",),
        # Hermes searches the working directory when no path is given.
        "default_path": ".",
    },
    "skills_list": {"keys": {"category"}, "paths": ()},
    "execute_code": {"keys": {"code"}, "paths": ()},
    "web_search": {"keys": {"query", "limit"}, "paths": ()},
    "terminal": {
        "keys": {
            "command",
            "background",
            "timeout",
            "workdir",
            "pty",
            "notify_on_complete",
            "watch_patterns",
        },
        "paths": ("workdir",),
    },
}

_PATCH_MODES = ("replace", "patch")

# V4A patch bodies name their files in header lines. Hermes reads them with
# re.match at column 0 (tools/patch_parser.py:111-114); this reader accepts a
# superset (any case, optional space before the colon, OpenAI "Move to:") so a
# header Hermes would apply is never missed. Any other line starting with "***"
# is refused rather than guessed at.
_V4A_FILE = re.compile(r"^\*\*\*\s*(?:Update|Add|Delete)\s+File\s*:\s*(.*)$", re.I)
_V4A_MOVE = re.compile(r"^\*\*\*\s*Move\s+File\s*:\s*(.*?)\s*->\s*(.*)$", re.I)
_V4A_MOVE_TO = re.compile(r"^\*\*\*\s*Move\s+to\s*:\s*(.*)$", re.I)
_V4A_MARKER = re.compile(
    r"^\*\*\*\s*(?:Begin\s+Patch|End\s+Patch|End\s+of\s+File)\s*$", re.I
)


def _v4a_paths(body: str) -> list[str]:
    """Every file a V4A patch body names, or ArgsRefused."""
    out: list[str] = []
    for raw in body.split("\n"):
        line = raw.rstrip("\r")
        if not line.startswith("***"):
            continue
        if _V4A_MARKER.match(line):
            continue
        m = _V4A_FILE.match(line) or _V4A_MOVE_TO.match(line)
        found = [m.group(1)] if m else []
        if not m:
            mv = _V4A_MOVE.match(line)
            if mv is None:
                raise ArgsRefused(f"unrecognised patch control line: {line[:80]!r}")
            found = [mv.group(1), mv.group(2)]
        for name in found:
            name = name.strip()
            if not name:
                raise ArgsRefused(f"patch header names no file: {line[:80]!r}")
            out.append(name)
    if not out:
        raise ArgsRefused("patch body names no file header")
    return out


def _hermes_home() -> str:
    return os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")


class UntrustedFile(Exception):
    """A gate file is not the plain, privately owned file it should be."""


def _read_trusted(path: str | os.PathLike) -> str:
    """Read one of the gate's own files only if it is what it claims to be.

    POSIX: the last path part must not be a symlink (``O_NOFOLLOW``), the
    opened file must be the same inode the name pointed at, a regular file,
    owned by the current user, and not writable by group or others. Windows:
    a symlink or other reparse point is refused; owner and ACL are not checked
    there yet. A symlink in a parent folder and a hardlink are not detected.
    """
    path = os.fspath(path)
    named = os.lstat(path)
    if stat.S_ISLNK(named.st_mode):
        raise UntrustedFile(f"{path} is a symlink")
    if os.name == "nt":
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if getattr(named, "st_file_attributes", 0) & reparse:
            raise UntrustedFile(f"{path} is a reparse point")
        with open(path, encoding="utf-8") as f:
            return f.read()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            raise UntrustedFile(f"{path} changed while it was opened")
        if not stat.S_ISREG(opened.st_mode):
            raise UntrustedFile(f"{path} is not a regular file")
        if opened.st_uid != os.geteuid():
            raise UntrustedFile(f"{path} is not owned by the current user")
        if opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise UntrustedFile(f"{path} is writable by group or others")
        with os.fdopen(fd, encoding="utf-8") as f:
            fd = -1
            return f.read()
    finally:
        if fd >= 0:
            os.close(fd)


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
        raw = _read_trusted(cfg_path)
    except UntrustedFile as exc:
        return "enforce", f"{MODE_UNRESOLVED_PREFIX}:untrusted:{exc}"
    except (OSError, UnicodeError):
        return "enforce", f"{MODE_UNRESOLVED_PREFIX}:unreadable"
    if not raw.strip():
        return "enforce", f"{MODE_UNRESOLVED_PREFIX}:empty"
    try:
        data = load_yaml_mapping(raw)
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


_SKILL_KEYS = ("skill", "skill_name", "active_skill")
# A call with no skill is judged as this name, never as the "*" grant. The
# policy grants it by name or the call is denied.
UNLABELED = "UNLABELED"


def _resolve_skill(kwargs: dict) -> str:
    """Use a skill field Hermes actually passed. Missing field is ``UNLABELED``."""
    if not isinstance(kwargs, dict):
        return UNLABELED
    for key in _SKILL_KEYS:
        val = kwargs.get(key)
        if isinstance(val, str):
            name = val.strip()
            if name and name != "*":
                return name
    return UNLABELED


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
    """Every file the call names, read from the tool's closed schema.

    Raises ArgsRefused when the call does not fit the schema. The caller turns
    that into a logged denial; it never means "no paths to check".
    """
    schema = _SCHEMAS.get(tool_name)
    if schema is None:
        raise ArgsRefused(f"no argument schema for tool '{tool_name}'")
    if type(args) is not dict:
        raise ArgsRefused(f"arguments are a {type(args).__name__}, not a dict")
    unknown = sorted(str(k) for k in args if k not in schema["keys"])
    if unknown:
        raise ArgsRefused(
            f"argument(s) not in the '{tool_name}' schema: {', '.join(unknown)}"
        )
    out: list[str] = []
    for key in schema["paths"]:
        val = args.get(key)
        if val is None or val == "":
            val = schema.get("default_path")
            if val is None:
                if key in schema.get("required", ()):
                    raise ArgsRefused(f"'{tool_name}' call has no '{key}'")
                continue
        if not isinstance(val, str):
            raise ArgsRefused(f"'{key}' is a {type(val).__name__}, not a string")
        out.append(val)
    if tool_name == "patch":
        mode = args.get("mode", "replace")
        if mode not in _PATCH_MODES:
            raise ArgsRefused(f"patch mode {mode!r} is not one of {_PATCH_MODES}")
        body = args.get("patch")
        if body is not None and not isinstance(body, str):
            raise ArgsRefused(f"'patch' is a {type(body).__name__}, not a string")
        if body:
            # Read headers whatever the mode says: a body Hermes would not
            # apply today must not become a write path tomorrow.
            out.extend(_v4a_paths(body))
        if not out:
            raise ArgsRefused("patch call names no file")
    return list(dict.fromkeys(out))


_HERMES_FILE_TOOLS = "tools.file_tools"


def _base_dir(task_id: str) -> str | None:
    """The folder Hermes resolves this task's relative paths against.

    Read from Hermes's own resolver (``tools/file_tools.py``
    ``_resolve_base_dir``: live terminal cwd, then a registered session cwd,
    then an absolute ``$TERMINAL_CWD``, then the process cwd), through the
    module Hermes has already loaded. Nothing is imported here. None when that
    module is not loaded, the call fails, or the answer is not absolute; the
    gate then denies a relative path rather than guess.
    """
    mod = sys.modules.get(_HERMES_FILE_TOOLS)
    resolver = getattr(mod, "_resolve_base_dir", None)
    if not callable(resolver):
        return None
    try:
        base = str(resolver(str(task_id or "default")))
    except Exception:
        return None
    return base if os.path.isabs(base) else None


def _load_allowlist(path: str):
    return load_policy(load_yaml_mapping(_read_trusted(path)))


def _log_path() -> str:
    return os.path.join(_hermes_home(), "logs", "capability-gate.jsonl")


def _build_gate(mode: str) -> Gate:
    # Guarantee HERMES_HOME before policy expansion so grants resolve the same
    # way the log path does. Without this, an unset var makes every grant match
    # nothing and the gate denies silently.
    os.environ.setdefault("HERMES_HOME", _hermes_home())
    policy = _load_allowlist(os.path.join(_HERE, "allowlist.yaml"))
    return Gate(policy, log_path=_log_path(), mode=mode)


# Tools that write the files they name. A write aimed at the gate's own files
# is denied whatever the grant says, so no grant can reconfigure the gate.
_WRITE_TOOLS = frozenset({"write_file", "patch"})


def _gate_file_hit(paths: list[str], base_dir: str | None, gate: Gate) -> str | None:
    """The first path that resolves to a gate file or the plugin folder."""

    def real(p: str) -> str:
        return os.path.normcase(os.path.realpath(p))

    files = {
        real(os.path.join(_hermes_home(), "config.yaml")),
        real(os.path.join(_HERE, "allowlist.yaml")),
        real(_log_path()),
        real(_log_path() + ".witness"),
    }
    live_log = getattr(gate, "_log_path", None)
    if live_log:
        files.add(real(live_log))
        files.add(real(live_log + ".witness"))
    plugin = real(_HERE)
    for p in paths:
        if "$" in p or p.startswith("~"):
            continue  # the gate refuses these on its own
        if not os.path.isabs(p):
            if not base_dir:
                continue  # the gate denies a relative path with no base
            p = os.path.join(base_dir, p)
        r = real(p)
        if r in files or r == plugin or r.startswith(plugin + os.sep):
            return f"'{p}' is one of the gate's own files"
    return None


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
                # E3: reconfirm before observe fail-open when gate failed to load.
                mode2, unresolved2 = resolve_capability_gate_mode()
                if unresolved2:
                    return _BLOCK(unresolved2)
                if mode2 == "enforce":
                    return _BLOCK(
                        f"capability-gate failed to load, failing closed: {load_error}"
                    )
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
            refused = None
            try:
                paths = _extract_paths(tool_name, args)
            except ArgsRefused as exc:
                paths, refused = [], str(exc)
            except Exception as exc:
                paths, refused = [], f"path extraction failed: {exc!r}"
            base_dir = (
                _base_dir(task_id) if any(not os.path.isabs(p) for p in paths) else None
            )
            if refused is None and tool_name in _WRITE_TOOLS:
                refused = _gate_file_hit(paths, base_dir, gate)
            decision = gate.evaluate(
                skill,
                tool_name,
                paths,
                trace=_extract_trace(kwargs, task_id),
                args=args if isinstance(args, dict) else None,
                refuse=refused,
                base_dir=base_dir,
            )
            if decision.verdict.value == "allow":
                # E3: reconfirm before observe allow-passthrough (same TOCTOU as deny).
                if mode == "observe":
                    mode2, unresolved2 = resolve_capability_gate_mode()
                    if unresolved2:
                        return _BLOCK(unresolved2)
                    if mode2 == "enforce":
                        gate.set_mode(mode2)
                        decision2 = gate.evaluate(
                            skill,
                            tool_name,
                            paths,
                            trace=_extract_trace(kwargs, task_id),
                            args=args if isinstance(args, dict) else None,
                            refuse=refused,
                            base_dir=base_dir,
                        )
                        if decision2.verdict.value != "allow":
                            return _BLOCK(decision2.reason)
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
            # H1-1: a crashed check with no log line used to fail open in
            # observe. Block in both modes; observe still does not act on a
            # normal deny Decision, but an unrecorded exception is not that.
            mode_e, unresolved_e = resolve_capability_gate_mode()
            if unresolved_e:
                return _BLOCK(unresolved_e)
            return _BLOCK(f"capability-gate error, failing closed: {exc!r}")

    ctx.register_hook("pre_tool_call", pre_tool_call)
