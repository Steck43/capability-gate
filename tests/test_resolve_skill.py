"""_resolve_skill uses a real Hermes field or stays star. No lab-injected skill."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOF = Path(__file__).resolve().parents[1]


def _adapter():
    spec = importlib.util.spec_from_file_location(
        "capability_gate_adapter", ROOF / "__init__.py"
    )
    # Load capability_gate first so the adapter import path resolves.
    if "capability_gate" not in sys.modules:
        cg_spec = importlib.util.spec_from_file_location(
            "capability_gate", ROOF / "capability_gate.py"
        )
        cg = importlib.util.module_from_spec(cg_spec)
        sys.modules["capability_gate"] = cg
        cg_spec.loader.exec_module(cg)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_missing_skill_stays_star() -> None:
    adapter = _adapter()
    assert adapter._resolve_skill({}) == "*"
    assert adapter._resolve_skill({"session_id": "s", "turn_id": "t"}) == "*"
    assert adapter._resolve_skill({"skill": "*"}) == "*"
    assert adapter._resolve_skill({"skill": "  "}) == "*"


def test_real_field_is_used() -> None:
    adapter = _adapter()
    assert adapter._resolve_skill({"skill": "lab-helper"}) == "lab-helper"
    assert adapter._resolve_skill({"skill_name": "note-taker"}) == "note-taker"
    assert (
        adapter._resolve_skill({"active_skill": "web-researcher"}) == "web-researcher"
    )
