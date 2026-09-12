"""TDD for scheduled empty-range skip."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".floor" / "craft"))

from empty_range import blocked_exit


def test_schedule_same_sha_skips():
    assert (
        blocked_exit(
            base_resolves=True,
            base_sha="abc",
            head_sha="abc",
            event_name="schedule",
        )
        == 0
    )


def test_dispatch_same_sha_skips():
    assert (
        blocked_exit(
            base_resolves=True,
            base_sha="abc",
            head_sha="abc",
            event_name="workflow_dispatch",
        )
        == 0
    )


def test_unresolvable_stays_3():
    assert (
        blocked_exit(
            base_resolves=False,
            base_sha=None,
            head_sha="abc",
            event_name="schedule",
        )
        == 3
    )


def test_push_empty_still_3():
    assert (
        blocked_exit(
            base_resolves=True,
            base_sha="abc",
            head_sha="abc",
            event_name="push",
        )
        == 3
    )


def test_real_range_ok():
    assert (
        blocked_exit(
            base_resolves=True,
            base_sha="aaa",
            head_sha="bbb",
            event_name="pull_request",
        )
        == 0
    )
