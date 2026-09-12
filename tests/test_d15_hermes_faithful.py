"""D15 receipt: Stage-1 through pre_tool_call. Does not require Hermes install."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOF = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOF / "harness"))

from d15_hermes_faithful import run_d15  # noqa: E402


def test_d15_grades_non_transfer_because_skill_is_star(tmp_path: Path) -> None:
    receipt = run_d15(tmp_path)
    assert receipt["hook_skill"] == "*"
    assert receipt["n"] == 19
    assert receipt["grade"] == "NON-TRANSFER"
    assert receipt["transfer"] < receipt["n"]
    dest = tmp_path / "D15-RECEIPT.json"
    dest.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    assert dest.is_file()
