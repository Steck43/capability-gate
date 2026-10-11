"""K8 — Windows grant surface (case/8.3/ADS/junction/\\?\) failing-first."""

from __future__ import annotations

from pathlib import Path

import pytest


def test_k8_receipt_exists() -> None:
    receipt = Path(__file__).resolve().parents[1] / "receipts" / "K8-WINDOWS-GRANT.md"
    assert receipt.is_file(), "K8 receipt missing — failing-first"


def test_k8_windows_acl_measured() -> None:
    pytest.fail(
        "K8 Windows grant ACL / case / 8.3 / ADS / \\?\ widening not measured "
        "(failing-first; pairs C5)"
    )
