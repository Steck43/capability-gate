"""Every path argument is mediated. A second path cannot hide behind the first."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

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
    adapter = _adapter()
    notes = os.path.join(os.path.expanduser("~"), ".hermes", "notes", "a.md")
    paths = adapter._extract_paths(
        "read_file",
        {"path": notes, "target": "/etc/passwd"},
    )
    assert notes in paths
    assert "/etc/passwd" in paths
    policy = load_policy(
        {
            "skills": {
                "note-taker": {
                    "tools": ["read_file", "write_file"],
                    "paths": ["~/.hermes/notes/**"],
                }
            },
        }
    )
    gate = Gate(policy, log_path=str(tmp_path / "d.jsonl"))
    decision = gate.evaluate("note-taker", "read_file", paths)
    assert decision.verdict is Verdict.DENY
    assert "outside allowlist" in decision.reason
