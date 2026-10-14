"""C5 / Windows grant ownership + ACL (failing-first scaffold)."""

from __future__ import annotations

from pathlib import Path

import pytest


def test_windows_grant_acl_receipt_exists() -> None:
    receipt = Path(__file__).resolve().parents[1] / "receipts" / "WINDOWS-GRANT-ACL.md"
    assert receipt.is_file(), "Windows grant ACL receipt missing — failing-first"


def test_windows_grant_owner_acl_contract() -> None:
    pytest.fail(
        "Windows grant-file owner/ACL trust-principal check not measured "
        "(failing-first)"
    )
