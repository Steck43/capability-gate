"""Behavior: each host hook, run for real, denies an off-grant read.

The wiring check reads source and can be fooled by code that is present but
never runs. These tests run the entry points the hosts run: the Claude Code
hook script end to end through its main(), and the Hermes plugin through
register() and the pre_tool_call it registers. Each one must deny an off-grant
read, allow an in-grant read, and deny when the gate itself raises.

Every tool each hook mediates is driven the same way, so a branch that lets one
tool skip the gate (for example an early exit for Grep) fails here even when
Read is still checked.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from grind01_util import blocked, hermes_home, load_adapter, register

ROOF = Path(__file__).resolve().parents[1]
HOOK = ROOF / "adapters" / "claude_code_hook.py"

# Runs the hook script as __main__ in a fresh interpreter, optionally with
# Gate.evaluate replaced by one that raises, so the error path is the real one.
_DRIVER = """
import runpy, sys
root, hook, mode = sys.argv[1:4]
sys.path.insert(0, root)
if mode == "raise":
    import capability_gate

    def _boom(self, *a, **k):
        raise RuntimeError("evaluate failed")

    capability_gate.Gate.evaluate = _boom
sys.argv = [hook]
runpy.run_path(hook, run_name="__main__")
"""

# Every path tool the Claude Code adapter mediates, with a minimal input.
CC_TOOLS = {
    "Read": lambda p: {"file_path": p},
    "Write": lambda p: {"file_path": p, "content": "x"},
    "Edit": lambda p: {"file_path": p, "old_string": "a", "new_string": "b"},
    "MultiEdit": lambda p: {"file_path": p, "edits": []},
    "NotebookEdit": lambda p: {"notebook_path": p, "new_source": "x"},
    "Grep": lambda p: {"pattern": "x", "path": p},
    "Glob": lambda p: {"pattern": "*.txt", "path": p},
}

# Every path tool the Hermes plugin mediates, with a minimal input.
H_TOOLS = {
    "read_file": lambda p: {"path": p},
    "write_file": lambda p: {"path": p, "content": "x"},
    "patch": lambda p: {"path": p, "old_string": "a", "new_string": "b"},
    "search_files": lambda p: {"pattern": "x", "path": p},
}

_DIR_TOOLS = {"Grep", "Glob", "search_files"}


def _target(tool: str, file: Path, in_grant: bool = False) -> Path:
    # A grant of "<root>/**" covers paths below the root; the Hermes gate does
    # not treat the root folder itself as granted, so in-grant searches use a
    # folder inside it.
    if tool not in _DIR_TOOLS:
        return file
    return file.parent / "sub" if in_grant else file.parent


@pytest.fixture
def area(tmp_path: Path):
    grant = tmp_path / "grant"
    (grant / "sub").mkdir(parents=True)
    (grant / "in.txt").write_text("in", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret", encoding="utf-8")
    return tmp_path, grant / "in.txt", outside / "secret.txt"


def _cc(
    tmp_path: Path,
    grant_root: Path,
    target: Path,
    mode: str = "normal",
    tool: str = "Read",
    tool_input: dict | None = None,
    extra_env: dict | None = None,
):
    allow = tmp_path / "allowlist.yaml"
    root = grant_root.as_posix()
    tools = ", ".join(CC_TOOLS)
    allow.write_text(
        f"skills:\n  UNLABELED:\n    tools: [{tools}]\n    paths: ['{root}/**']\n",
        encoding="utf-8",
    )
    if tool_input is None:
        tool_input = CC_TOOLS[tool](str(target))
    event = {
        "session_id": "s1",
        "cwd": str(grant_root),
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": tool_input,
        "tool_use_id": "toolu_behavior",
    }
    env = {
        **os.environ,
        **(extra_env or {}),
        "CG_CC_ALLOWLIST": str(allow),
        "CG_CC_LOG": str(tmp_path / "log" / "claude-code.jsonl"),
    }
    return subprocess.run(
        [sys.executable, "-c", _DRIVER, str(ROOF), str(HOOK), mode],
        input=json.dumps(event),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def _cc_denied(r: subprocess.CompletedProcess) -> bool:
    return r.returncode == 2 and "capability-gate:" in r.stderr


def test_cc_hook_main_denies_off_grant_read(area) -> None:
    tmp, inside, outside = area
    r = _cc(tmp, inside.parent, outside)
    assert _cc_denied(r), (r.returncode, r.stderr)
    assert "outside allowlist" in r.stderr


def test_cc_hook_main_allows_in_grant_read(area) -> None:
    tmp, inside, _ = area
    r = _cc(tmp, inside.parent, inside)
    assert r.returncode == 0, (r.returncode, r.stderr)
    assert r.stdout == ""


def test_cc_hook_main_denies_when_gate_raises(area) -> None:
    tmp, inside, _ = area
    r = _cc(tmp, inside.parent, inside, mode="raise")
    assert _cc_denied(r), (r.returncode, r.stderr)
    assert "evaluate failed" in r.stderr


@pytest.mark.parametrize("tool", sorted(CC_TOOLS))
def test_cc_hook_main_denies_every_tool_off_grant(area, tool: str) -> None:
    tmp, inside, outside = area
    r = _cc(tmp, inside.parent, _target(tool, outside), tool=tool)
    assert _cc_denied(r), (tool, r.returncode, r.stderr)
    assert "outside allowlist" in r.stderr, (tool, r.stderr)


@pytest.mark.parametrize("tool", sorted(CC_TOOLS))
def test_cc_hook_main_allows_every_tool_in_grant(area, tool: str) -> None:
    tmp, inside, _ = area
    r = _cc(tmp, inside.parent, _target(tool, inside, in_grant=True), tool=tool)
    assert r.returncode == 0, (tool, r.returncode, r.stderr)


def test_cc_hook_main_denies_a_tool_with_no_path_schema(area) -> None:
    tmp, inside, _ = area
    r = _cc(tmp, inside.parent, inside, tool="Bash", tool_input={"command": "echo"})
    assert _cc_denied(r), (r.returncode, r.stderr)


@pytest.fixture
def hermes(area, monkeypatch):
    tmp, inside, outside = area
    home = hermes_home(tmp, monkeypatch)
    adapter = load_adapter("behavior")
    skills = {
        "UNLABELED": {"tools": list(H_TOOLS), "paths": [str(inside.parent / "**")]}
    }
    return register(adapter, home, skills), inside, outside


def test_hermes_registered_hook_denies_off_grant_read(hermes) -> None:
    pre, _, outside = hermes
    out = pre("read_file", {"path": str(outside)}, "t")
    assert blocked(out)
    assert "outside allowlist" in out["message"]


def test_hermes_registered_hook_allows_in_grant_read(hermes) -> None:
    pre, inside, _ = hermes
    assert pre("read_file", {"path": str(inside)}, "t") is None


def test_hermes_registered_hook_denies_when_gate_raises(hermes, monkeypatch) -> None:
    # Other tests reload capability_gate, so patch the Gate class the registered
    # hook was actually built with, not whichever module object is current.
    import grind01_util

    def _boom(self, *a, **k):
        raise RuntimeError("evaluate failed")

    monkeypatch.setattr(grind01_util.Gate, "evaluate", _boom)
    pre, inside, _ = hermes
    out = pre("read_file", {"path": str(inside)}, "t")
    assert blocked(out)
    assert "evaluate failed" in out["message"]


@pytest.mark.parametrize("tool", sorted(H_TOOLS))
def test_hermes_registered_hook_denies_every_tool_off_grant(hermes, tool) -> None:
    pre, _, outside = hermes
    out = pre(tool, H_TOOLS[tool](str(_target(tool, outside))), "t")
    assert blocked(out), tool
    assert "outside allowlist" in out["message"], (tool, out)


@pytest.mark.parametrize("tool", sorted(H_TOOLS))
def test_hermes_registered_hook_allows_every_tool_in_grant(hermes, tool) -> None:
    pre, inside, _ = hermes
    args = H_TOOLS[tool](str(_target(tool, inside, in_grant=True)))
    assert pre(tool, args, "t") is None, tool


@pytest.mark.parametrize(
    "tool, args",
    [
        ("terminal", {"command": "echo"}),
        ("execute_code", {"code": "1"}),
        ("web_search", {"query": "x"}),
    ],
)
def test_hermes_registered_hook_denies_ungranted_tools(hermes, tool, args) -> None:
    pre, _, _ = hermes
    assert blocked(pre(tool, args, "t")), tool


# Names a bypass is likely to hide behind. A hook must decide the same way
# with any of them set.
BYPASS_ENV = {
    name: "1"
    for name in (
        "CG_FAST_PATH",
        "CG_BYPASS",
        "CG_DISABLE",
        "CG_CC_BYPASS",
        "CG_CC_DISABLE",
        "CAPABILITY_GATE_DISABLE",
        "CAPABILITY_GATE_OFF",
        "GATE_OFF",
        "SKIP_GATE",
        "NO_GATE",
        "HERMES_GATE_OFF",
        "DEBUG",
        "CI",
    )
}


@pytest.mark.parametrize("tool", sorted(CC_TOOLS))
def test_cc_hook_main_denies_with_bypass_variables_set(area, tool: str) -> None:
    tmp, inside, outside = area
    r = _cc(tmp, inside.parent, _target(tool, outside), tool=tool, extra_env=BYPASS_ENV)
    assert _cc_denied(r), (tool, r.returncode, r.stderr)


def test_cc_hook_main_decides_the_same_in_a_scrubbed_environment(area) -> None:
    tmp, inside, outside = area
    keep = ("SYSTEMROOT", "PATH", "TEMP", "TMP")
    scrubbed = {k: v for k, v in os.environ.items() if k in keep}
    real = os.environ.copy()
    try:
        os.environ.clear()
        os.environ.update(scrubbed)
        denied = _cc(tmp, inside.parent, outside)
        allowed = _cc(tmp, inside.parent, inside)
    finally:
        os.environ.clear()
        os.environ.update(real)
    assert _cc_denied(denied), (denied.returncode, denied.stderr)
    assert allowed.returncode == 0, (allowed.returncode, allowed.stderr)


@pytest.mark.parametrize("tool", sorted(H_TOOLS))
def test_hermes_registered_hook_denies_with_bypass_variables_set(
    hermes, monkeypatch, tool
) -> None:
    for name, value in BYPASS_ENV.items():
        monkeypatch.setenv(name, value)
    pre, _, outside = hermes
    assert blocked(pre(tool, H_TOOLS[tool](str(_target(tool, outside))), "t")), tool
