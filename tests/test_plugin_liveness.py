"""Unloaded plugin mediates nothing. Anderson row 1 needs this, not only B3."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

ROOF = Path(__file__).resolve().parents[1]


def test_import_does_not_register_a_hook() -> None:
    src = (ROOF / "__init__.py").read_text(encoding="utf-8")
    assert "ctx.register_hook" in src
    ctx = MagicMock()
    assert ctx.register_hook.call_count == 0


def test_register_is_the_only_pre_tool_install() -> None:
    src = (ROOF / "__init__.py").read_text(encoding="utf-8")
    assert src.count('register_hook("pre_tool_call"') == 2
