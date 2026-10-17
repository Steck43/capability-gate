"""Kill switch marker and log behavior that asks the gate for no verdict.

These tests pin what throwing the switch writes (one THROWN row, one marker),
not a decision, so a swapped gate cannot change their answer and they are not
known-answer tests of the gate. The decisions after a throw are pinned in
tests/test_kill_switch.py.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOF = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOF))

from capability_gate import Gate, load_policy, verify_hash_chain  # noqa: E402


def _policy(root: Path):
    return load_policy(
        {
            "skills": {
                "writer": {
                    "tools": ["read_file", "write_file"],
                    "paths": [str(root) + "/**"],
                }
            }
        }
    )


def _thrown_rows(log: Path) -> list[dict]:
    rows = [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines() if x]
    return [r for r in rows if r.get("verdict") == "thrown"]


@pytest.fixture()
def log(tmp_path):
    return tmp_path / "decisions.jsonl"


@pytest.fixture()
def gate(tmp_path, log):
    return Gate(_policy(tmp_path), log_path=str(log))


def test_ks_double_throw_one_row(gate, log):
    # KS-DOUBLE-THROW: a second throw is a no-op. Still one row, still thrown.
    assert gate.throw("first") is True
    assert gate.throw("second") is False
    assert len(_thrown_rows(log)) == 1
    assert os.path.exists(gate.halt_path)
    verify_hash_chain(str(log))
