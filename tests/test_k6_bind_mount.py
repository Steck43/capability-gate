"""K6 — bind-mount alias escape (failing-first)."""

from __future__ import annotations

from pathlib import Path

import pytest


def test_k6_receipt_exists() -> None:
    receipt = Path(__file__).resolve().parents[1] / "receipts" / "K6-BIND-MOUNT.md"
    assert receipt.is_file(), "K6 receipt missing — failing-first"


def test_k6_host_bind_mount_measured() -> None:
    pytest.fail(
        "K6 bind-mount alias needs a host mount measurement; in-process skip "
        "is not closed (failing-first)"
    )
