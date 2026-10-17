"""The grant matcher keeps * and ? inside one segment for both separators.

Runs on any OS by giving the matcher Windows-form and POSIX-form strings
directly; tests/test_glob_separators.py drives the same rule through the gate
on Windows.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOF = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOF))

from capability_gate import Gate, Verdict, _glob_to_regex, load_policy  # noqa: E402

BS = chr(92)


def _w(*parts: str) -> str:
    return BS.join(parts)


@pytest.mark.parametrize(
    "glob, path, matches",
    [
        (_w("C:", "ws", "*"), _w("C:", "ws", "top.txt"), True),
        (_w("C:", "ws", "*"), _w("C:", "ws", "sub", "x"), False),
        (_w("C:", "ws", "a?b"), _w("C:", "ws", "a", "b"), False),
        (_w("C:", "ws", "a?b"), _w("C:", "ws", "axb"), True),
        (_w("C:", "ws", "**"), _w("C:", "ws", "sub", "x"), True),
        (_w("C:", "ws", "**", "x"), _w("C:", "ws", "sub", "x"), True),
        ("/ws/*", "/ws/top.txt", True),
        ("/ws/*", "/ws/sub/x", False),
        ("/ws/a?b", "/ws/a/b", False),
        ("/ws/**", "/ws/sub/x", True),
    ],
)
def test_star_and_question_mark_stay_in_one_segment(glob, path, matches) -> None:
    assert bool(_glob_to_regex(glob).match(path)) is matches


NL = chr(10)


@pytest.mark.parametrize(
    "glob, path, matches",
    [
        ("/ws/ok.txt", "/ws/ok.txt" + NL, False),
        ("/ws/*.txt", "/ws/a.txt" + NL, False),
        ("/ws/**", "/ws/a" + NL + "b", True),
        ("/ws/**", "/ws/a" + NL, True),
    ],
)
def test_a_newline_is_part_of_the_name(glob, path, matches) -> None:
    # A regex $ also matches before a final newline, so a grant for ok.txt
    # matched "ok.txt\n", a different file on POSIX.
    assert bool(_glob_to_regex(glob).match(path)) is matches


@pytest.mark.skipif(os.name == "nt", reason="a Windows file name cannot hold a newline")
def test_grant_for_one_file_denies_its_name_with_a_newline(tmp_path) -> None:
    root = tmp_path.resolve()
    ok, other = root / "ok.txt", root / ("ok.txt" + NL)
    ok.write_text("IN", encoding="utf-8")
    other.write_text("OTHER", encoding="utf-8")
    policy = load_policy(
        {"skills": {"s": {"tools": ["read_file"], "paths": [str(ok)]}}}
    )
    gate = Gate(policy, log_path=str(root / "logs" / "decisions.jsonl"))
    assert gate.evaluate("s", "read_file", [str(ok)]).verdict is Verdict.ALLOW
    d = gate.evaluate("s", "read_file", [str(other)])
    assert d.verdict is Verdict.DENY, d.reason
