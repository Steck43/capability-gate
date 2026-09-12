"""FIG-1: the floor decide path does not call the box."""

from __future__ import annotations

from pathlib import Path

ROOF = Path(__file__).resolve().parents[1]
DECIDER = (ROOF / "capability_gate.py").read_text(encoding="utf-8")
ADAPTER = (ROOF / "__init__.py").read_text(encoding="utf-8")
FORBIDDEN = (
    "firecracker",
    "jailer",
    "isolation_layer",
    "isolation-layer",
    "b1-prove",
    "microvm",
    "vsock",
)


def test_evaluate_does_not_import_the_box() -> None:
    blob = DECIDER.lower() + "\n" + ADAPTER.lower()
    hits = [w for w in FORBIDDEN if w in blob]
    assert hits == []
