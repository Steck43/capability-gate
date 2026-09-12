"""Stage-1 insufficiency tally is asserted by case id. Print is not the prove.

Counts are derived from CAUGHT / FALSE_ALLOW / CORRECT_ALLOW. Do not hand-type
the 7/8/4/0 permutation. README order is caught / false-allow / correct / false-deny.
The tuple below is (caught, correct, false_allow, false_deny).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOF = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOF))
sys.path.insert(0, str(ROOF / "harness"))

from lab_insufficiency_harness import (  # noqa: E402
    CAUGHT,
    CORRECT_ALLOW,
    FALSE_ALLOW,
    _s1_symlink,
    run_cases,
)

EXPECTED = {
    **{cid: "CAUGHT-NAIVE" for cid in CAUGHT},
    **{cid: "FALSE-ALLOW" for cid in FALSE_ALLOW},
    **{cid: "CORRECT-ALLOW" for cid in CORRECT_ALLOW},
}

DERIVED_CAUGHT = len(CAUGHT)
DERIVED_FALSE_ALLOW = len(FALSE_ALLOW)
DERIVED_CORRECT = len(CORRECT_ALLOW)


@pytest.fixture()
def results(tmp_path):
    return {
        r.case_id: r
        for r in run_cases(tmp_path / "decisions.jsonl", work=tmp_path)
    }


def test_case_set_matches_expected(results):
    assert set(results) == set(EXPECTED)


@pytest.mark.parametrize("case_id,matrix", sorted(EXPECTED.items()))
def test_case_id_matrix(results, case_id, matrix):
    assert results[case_id].matrix_verdict == matrix, (
        case_id,
        results[case_id].matrix_verdict,
        results[case_id].gate_verdict,
        results[case_id].notes,
    )


def test_false_deny_zero(results):
    assert sum(1 for r in results.values() if r.matrix_verdict == "FALSE-DENY") == 0


def test_tally_shape_derived(results):
    caught = sum(1 for r in results.values() if r.matrix_verdict == "CAUGHT-NAIVE")
    false_allow = sum(1 for r in results.values() if r.matrix_verdict == "FALSE-ALLOW")
    correct = sum(1 for r in results.values() if r.matrix_verdict == "CORRECT-ALLOW")
    assert (caught, correct, false_allow, 0) == (
        DERIVED_CAUGHT,
        DERIVED_CORRECT,
        DERIVED_FALSE_ALLOW,
        0,
    )
    assert (caught, false_allow, correct, 0) == (7, 8, 4, 0)


def test_s1_symlink_created_or_os_refused(tmp_path):
    _path, notes, created = _s1_symlink(tmp_path)
    if not created:
        pytest.skip(notes)
    assert os.path.islink(tmp_path / "s1-in-grant" / "s1-link")
