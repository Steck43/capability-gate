"""K3 — mid-path directory symlink / junction escape (failing-first)."""

from __future__ import annotations

from pathlib import Path

import pytest

# Failing-first: this module must stay red until a dedicated K3 receipt pins
# mid-path directory-symlink + Windows junction denial with LEDGER row.
# Existing floor coverage lives in test_floor_fixes / test_alias_class; this
# KAT refuses to pass on suite presence alone.


def test_k3_receipt_exists() -> None:
    receipt = (
        Path(__file__).resolve().parents[1] / "receipts" / "K3-JUNCTION-MIDPATH.md"
    )
    assert receipt.is_file(), "K3 receipt missing — failing-first until written"


def test_k3_ledger_row_names_tip() -> None:
    pytest.fail("K3 LEDGER tip row not yet recorded (failing-first)")
