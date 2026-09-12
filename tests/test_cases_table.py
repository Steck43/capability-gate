"""CASES.md matches the derived harness sets."""

from __future__ import annotations

import sys
from pathlib import Path

ROOF = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOF / "harness"))

from cases_table import CASES_PATH, cases_markdown  # noqa: E402
from lab_insufficiency_harness import CAUGHT, CORRECT_ALLOW, FALSE_ALLOW  # noqa: E402


def test_cases_markdown_matches_disk() -> None:
    assert CASES_PATH.read_text(encoding="utf-8") == cases_markdown()


def test_cases_counts_match_sets() -> None:
    text = CASES_PATH.read_text(encoding="utf-8")
    assert f"- CAUGHT-NAIVE: {len(CAUGHT)}" in text
    assert f"- FALSE-ALLOW: {len(FALSE_ALLOW)}" in text
    assert f"- CORRECT-ALLOW: {len(CORRECT_ALLOW)}" in text
    assert "- FALSE-DENY: 0" in text
    assert (len(CAUGHT), len(FALSE_ALLOW), len(CORRECT_ALLOW)) == (7, 8, 4)
