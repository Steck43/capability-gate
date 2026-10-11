"""OS-1 / OS-2 — collected as strict xfail until implementation PRs land.

Checklist 1.18 / MASTER-PLAN addendum 2. Source designs under ``design/os/``.
Hermes pin ``ccd8deaa67``. Judge apply stays false. No paper claim.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.xfail(
    strict=True,
    reason="OS-1/OS-2 not implemented — collected suite pin (Track B 2026-10-11)",
)


def test_t_os_01_pin_mismatch_denies_or_escalates() -> None:
    """Approve a fixture MCP; mutate one tool description; deny/escalate + pin_mismatch."""
    pytest.fail(
        "OS-1 not implemented: fixture MCP pin must deny/escalate on description "
        "mutation and record pin_mismatch"
    )


def test_t_os_02a_taint_marks_untrusted_tool_result() -> None:
    """Tool result from an untrusted/compromised source carries taint into the next call."""
    pytest.fail("OS-2a not implemented: untrusted tool result must be tainted")


def test_t_os_02b_taint_blocks_privileged_sink() -> None:
    """Tainted data cannot authorize a privileged sink without an explicit clear."""
    pytest.fail("OS-2b not implemented: tainted value must not authorize a privileged sink")


def test_t_os_02c_taint_survives_benign_transform() -> None:
    """Taint is not cleared by a benign string/JSON transform."""
    pytest.fail("OS-2c not implemented: taint must survive benign transforms")


def test_t_os_02d_clear_requires_attested_human_origin() -> None:
    """Only an attested human-origin clear may drop taint."""
    pytest.fail("OS-2d not implemented: clear requires attested human origin")
