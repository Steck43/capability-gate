"""An empty or malformed hook payload is a deny, never a pass-through.

Hook frameworks treat a crash or a non-blocking exit as "go ahead", so every
shape of bad input the host could send must end in the hook's own deny.
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


def _cc(tmp_path: Path, stdin: str) -> subprocess.CompletedProcess:
    allow = tmp_path / "allowlist.yaml"
    allow.write_text(
        "skills:\n  UNLABELED:\n    tools: [Read]\n"
        f"    paths: ['{tmp_path.as_posix()}/**']\n",
        encoding="utf-8",
    )
    env = {
        **os.environ,
        "CG_CC_ALLOWLIST": str(allow),
        "CG_CC_LOG": str(tmp_path / "log" / "claude-code.jsonl"),
    }
    return subprocess.run(
        [sys.executable, str(HOOK)],
        input=stdin,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


BAD_CC_PAYLOADS = {
    "empty": "",
    "whitespace": "   \n",
    "null": "null",
    "list": "[]",
    "string": json.dumps("Read"),
    "empty object": "{}",
    "no tool input": json.dumps({"tool_name": "Read"}),
    "tool input is a list": json.dumps({"tool_name": "Read", "tool_input": []}),
    "tool name missing": json.dumps({"tool_input": {"file_path": "x"}}),
    "truncated json": '{"tool_name": "Read", "tool_input": {"file_path": ',
}


@pytest.mark.parametrize("shape", sorted(BAD_CC_PAYLOADS))
def test_cc_hook_denies_bad_payload(tmp_path: Path, shape: str) -> None:
    r = _cc(tmp_path, BAD_CC_PAYLOADS[shape])
    assert r.returncode == 2, (shape, r.returncode, r.stderr)
    assert "capability-gate:" in r.stderr, (shape, r.stderr)


@pytest.fixture
def pre(tmp_path, monkeypatch):
    home = hermes_home(tmp_path, monkeypatch)
    skills = {"UNLABELED": {"tools": ["read_file"], "paths": [str(tmp_path / "**")]}}
    return register(load_adapter("payloads"), home, skills)


@pytest.mark.parametrize(
    "tool, args",
    [
        ("read_file", None),
        ("read_file", []),
        ("read_file", "path=x"),
        ("read_file", {}),
        ("read_file", {"path": None}),
        ("read_file", {"path": 7}),
        ("", {"path": "x"}),
        (None, {"path": "x"}),
    ],
    ids=[
        "args none",
        "args list",
        "args string",
        "args empty",
        "path none",
        "path not a string",
        "tool empty",
        "tool none",
    ],
)
def test_hermes_hook_blocks_bad_payload(pre, tool, args) -> None:
    assert blocked(pre(tool, args, "t")), (tool, args)
