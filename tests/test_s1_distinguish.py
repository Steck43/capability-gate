"""§8.2 distinguish: resolve-then-reopen by the original name still ALLOWs.

This is not a decide-path fix. It measures why publishing realpath as the
remedy would be the wrong claim: the hook re-opens the path it was given.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOF = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOF))
sys.path.insert(0, str(ROOF / "harness"))

from capability_gate import ENFORCE, Gate, Verdict, load_policy  # noqa: E402
from lab_insufficiency_harness import POLICY, _s1_symlink  # noqa: E402


def test_resolve_then_reopen_by_name_still_allows(tmp_path: Path) -> None:
    link, notes, created = _s1_symlink(tmp_path)
    if not created:
        pytest.skip(notes)
    grant_glob = str((tmp_path / "s1-in-grant").resolve() / "**")
    policy = load_policy(
        {
            **POLICY,
            "skills": {
                **POLICY["skills"],
                "lab-helper": {
                    **POLICY["skills"]["lab-helper"],
                    "paths": list(POLICY["skills"]["lab-helper"]["paths"]) + [grant_glob],
                },
            },
        }
    )
    gate = Gate(policy, log_path=str(tmp_path / "decisions.jsonl"), mode=ENFORCE)
    by_name = gate.evaluate("lab-helper", "write_file", [link])
    resolved = os.path.realpath(link)
    by_target = gate.evaluate("lab-helper", "write_file", [resolved])
    again_by_name = gate.evaluate("lab-helper", "write_file", [link])
    assert by_name.verdict is Verdict.ALLOW
    assert by_target.verdict is Verdict.DENY
    assert again_by_name.verdict is Verdict.ALLOW
