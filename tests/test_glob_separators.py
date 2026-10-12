"""Known-answer tests: single-star and ? globs stay inside one path segment.

# KAT

On Windows a path's separator is a backslash. A grant like ``ws\\*`` must
cover files directly in ``ws`` and nothing deeper; only ``**`` crosses
separators. These run through Gate.evaluate on Windows, where the paths are
real. tests/test_glob_regex.py checks the same rule on the matcher on any OS.
"""

# KAT

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOF = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOF))

from capability_gate import Gate, Verdict, load_policy  # noqa: E402

pytestmark = pytest.mark.skipif(
    os.name != "nt", reason="backslash separators are only real paths on Windows"
)


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    root = tmp_path.resolve() / "ws"
    (root / "sub").mkdir(parents=True)
    (root / "a").mkdir()
    for p in (root / "top.txt", root / "sub" / "x", root / "a" / "b"):
        p.write_text("x", encoding="utf-8")
    return root


def _gate(ws: Path, glob: str):
    policy = load_policy({"skills": {"s": {"tools": ["read_file"], "paths": [glob]}}})
    return Gate(policy, log_path=str(ws.parent / "logs" / "d.jsonl"))


def test_single_star_does_not_cross_a_backslash(ws) -> None:
    gate = _gate(ws, str(ws) + "\\*")
    assert (
        gate.evaluate("s", "read_file", [str(ws / "top.txt")]).verdict is Verdict.ALLOW
    )
    d = gate.evaluate("s", "read_file", [str(ws / "sub" / "x")])
    assert d.verdict is Verdict.DENY, d.reason


def test_question_mark_does_not_match_a_backslash(ws) -> None:
    gate = _gate(ws, str(ws) + "\\a?b")
    d = gate.evaluate("s", "read_file", [str(ws / "a" / "b")])
    assert d.verdict is Verdict.DENY, d.reason


def test_double_star_still_crosses_separators(ws) -> None:
    gate = _gate(ws, str(ws) + "\\**")
    d = gate.evaluate("s", "read_file", [str(ws / "sub" / "x")])
    assert d.verdict is Verdict.ALLOW, d.reason
