"""T-SG-04 — failing first.

An agent patch that turns a failing assert into `assert True` under tests/,
.github/, or policy/ must escalate. Implementation lands later. Not collected
by roof pytest.
"""

from __future__ import annotations

import pytest


def test_t_sg_04_test_write_escalates() -> None:
    pytest.fail(
        "SG-4 not implemented: write under tests/, .github/, or policy/ must escalate"
    )
