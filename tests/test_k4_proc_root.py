"""K4 — /proc/self/root (and root-alias) escape KAT (failing-first)."""

from __future__ import annotations

from pathlib import Path

import pytest


def test_k4_receipt_exists() -> None:
    receipt = Path(__file__).resolve().parents[1] / "receipts" / "K4-PROC-ROOT.md"
    assert receipt.is_file(), "K4 receipt missing — failing-first"


def test_k4_dedicated_kat_not_skip_only() -> None:
    pytest.fail(
        "K4 needs a dedicated KAT that fails closed when /proc/self/root is "
        "present; skip-only coverage is not enough (failing-first)"
    )
