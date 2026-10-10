"""T-OS-01 — failing first.

Approve a fixture MCP, mutate one tool description mid-session, and assert the
next call is deny or escalate with `pin_mismatch` on the ledger. Implementation
lands in a later PR. This file is not collected by roof pytest.
"""

from __future__ import annotations

import pytest


def test_t_os_01_pin_mismatch_denies_or_escalates() -> None:
    pytest.fail(
        "OS-1 not implemented: fixture MCP pin must deny/escalate on description "
        "mutation and record pin_mismatch"
    )
