"""Every path argument is mediated. A second path cannot hide behind the first."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

from capability_gate import Gate, Verdict, load_policy

ROOF = Path(__file__).resolve().parents[1]


def _adapter():
    spec = importlib.util.spec_from_file_location(
        "capability_gate_adapter_paths", ROOF / "__init__.py"
    )
    if "capability_gate" not in sys.modules:
        cg_spec = importlib.util.spec_from_file_location(
            "capability_gate", ROOF / "capability_gate.py"
        )
        cg = importlib.util.module_from_spec(cg_spec)
        sys.modules["capability_gate"] = cg
        cg_spec.loader.exec_module(cg)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_notes_path_and_passwd_target_fail_closed(tmp_path) -> None:
    # Outcome change, grind01 P1: read_file's schema has no "target" key, so
    # this call is now refused outright instead of having both paths read and
    # the second one denied. Either way the call cannot reach /etc/passwd.
    adapter = _adapter()
    notes = os.path.join(os.path.expanduser("~"), ".hermes", "notes", "a.md")
    with pytest.raises(adapter.ArgsRefused, match="target"):
        adapter._extract_paths("read_file", {"path": notes, "target": "/etc/passwd"})


def test_every_path_argument_is_checked(tmp_path) -> None:
    # The original intent, on a tool whose schema has two path arguments.
    adapter = _adapter()
    body = "*** Begin Patch\n*** Update File: /etc/passwd\n+x\n*** End Patch"
    notes = os.path.join(os.path.expanduser("~"), ".hermes", "notes", "a.md")
    paths = adapter._extract_paths(
        "patch", {"mode": "patch", "path": notes, "patch": body}
    )
    assert notes in paths
    assert "/etc/passwd" in paths
    policy = load_policy(
        {
            "skills": {
                "note-taker": {"tools": ["patch"], "paths": ["~/.hermes/notes/**"]}
            }
        }
    )
    gate = Gate(policy, log_path=str(tmp_path / "d.jsonl"))
    decision = gate.evaluate("note-taker", "patch", paths)
    assert decision.verdict is Verdict.DENY
    assert "outside allowlist" in decision.reason
