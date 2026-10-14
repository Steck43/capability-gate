"""K7 — check-then-open TOCTOU (failing-first; pairs C1 open-by-fd)."""

from __future__ import annotations

from pathlib import Path

import pytest


def test_k7_receipt_exists() -> None:
    receipt = (
        Path(__file__).resolve().parents[1] / "receipts" / "K7-CHECK-OPEN-TOCTOU.md"
    )
    assert receipt.is_file(), "K7 receipt missing — failing-first"


def test_k7_not_strict_xfail_forever() -> None:
    pytest.fail(
        "K7 check-open swap remains strict xfail until C1 open-by-fd lands; "
        "this KAT fails until the host path closes TOCTOU (failing-first)"
    )
