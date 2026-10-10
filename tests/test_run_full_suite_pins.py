"""The full-suite runner must pin the same sibling SHAs as the boundary test."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import test_gate_boundary as boundary

ROOF = Path(__file__).resolve().parents[1]


def test_runner_pins_match_boundary() -> None:
    path = ROOF / "scripts" / "run_full_suite.py"
    spec = importlib.util.spec_from_file_location("run_full_suite", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod._PINS == boundary._PINS
    assert mod._ENV == boundary._ENV
