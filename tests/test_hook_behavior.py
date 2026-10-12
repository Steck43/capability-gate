"""Behavior: each host hook, run for real, denies an off-grant read.

The wiring check reads source and can be fooled by code that is present but
never runs. These tests run the entry points the hosts run: the Claude Code
hook script end to end through its main(), and the Hermes plugin through
register() and the pre_tool_call it registers. Each one must deny an off-grant
read, allow an in-grant read, and deny when the gate itself raises.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from grind01_util import blocked, hermes_home, load_adapter, register  # noqa: E402

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


@pytest.fixture
def area(tmp_path: Path):
    grant = tmp_path / "grant"
    grant.mkdir()
    (grant / "in.txt").write_text("in", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret", encoding="utf-8")
    return tmp_path, grant / "in.txt", outside / "secret.txt"


def _cc(tmp_path: Path, grant_root: Path, target: Path, mode: str = "normal"):
    allow = tmp_path / "allowlist.yaml"
    root = str(grant_root).replace("\\", "/")
    allow.write_text(
        f"skills:\n  UNLABELED:\n    tools: [Read]\n    paths: ['{root}/**']\n",
        encoding="utf-8",
    )
    event = {
        "session_id": "s1",
        "cwd": str(grant_root),
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(target)},
        "tool_use_id": "toolu_behavior",
    }
    env = {
        **os.environ,
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


@pytest.fixture
def hermes(area, monkeypatch):
    tmp, inside, outside = area
    home = hermes_home(tmp, monkeypatch)
    adapter = load_adapter("behavior")
    skills = {
        "UNLABELED": {"tools": ["read_file"], "paths": [str(inside.parent / "**")]}
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
    import capability_gate

    def _boom(self, *a, **k):
        raise RuntimeError("evaluate failed")

    monkeypatch.setattr(capability_gate.Gate, "evaluate", _boom)
    pre, inside, _ = hermes
    assert blocked(pre("read_file", {"path": str(inside)}, "t"))
