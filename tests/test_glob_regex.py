"""The grant matcher keeps * and ? inside one segment for both separators.

Runs on any OS by giving the matcher Windows-form and POSIX-form strings
directly; tests/test_glob_separators.py drives the same rule through the gate
on Windows.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOF = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOF))

from capability_gate import _glob_to_regex  # noqa: E402

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
