"""Three receipts in order: gate into atoms, atoms into a jailer prove receipt."""

from __future__ import annotations

import inspect
import json
import os
import sys
from collections.abc import Mapping
from contextlib import contextmanager
from pathlib import Path

ROOF = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOF))

from capability_gate import ENFORCE, Gate, load_policy  # noqa: E402

_ATOMS = "aegis-atoms"
_ISOLATION = "isolation-layer"
_ENV = {
    _ATOMS: "AEGIS_ATOMS_ROOT",
    _ISOLATION: "ISOLATION_LAYER_ROOT",
}
_DECISION_PARAMS = (
    "decision",
    "gate_decision",
    "gate",
    "capability_decision",
)
_PROVE_ATTRS = (
    "prove_receipt",
    "box_receipt",
    "jailer_receipt",
    "isolation_receipt",
)
_REFUSED_BOX_SCRIPTS = frozenset({"conflicting_handoff.py", "b1-prove.py"})


def _require_sibling(name: str, rel: str) -> Path:
    raw = os.environ.get(_ENV[name], "").strip()
    candidates = [Path(raw)] if raw else []
    candidates.append(ROOF.parent / name)
    for root in candidates:
        if (root / rel).is_file():
            return root
    raise AssertionError(f"missing sibling checkout: {name} ({rel})")


@contextmanager
def _watch(owner, name: str):
    hits: list[tuple[tuple, dict, object]] = []
    real = getattr(owner, name)

    def wrapped(*args, **kwargs):
        out = real(*args, **kwargs)
        hits.append((args, kwargs, out))
        return out

    setattr(owner, name, wrapped)
    try:
        yield hits, real
    finally:
        setattr(owner, name, real)


def _decision_kwargs(fn, decision) -> dict:
    params = inspect.signature(fn).parameters
    for name in _DECISION_PARAMS:
        if name in params:
            return {name: decision}
    return {}


def _decision_was_input(fn, decision, args, kwargs) -> bool:
    if decision is None:
        return False
    try:
        bound = inspect.signature(fn).bind(*args, **kwargs)
    except TypeError:
        return False
    bound.apply_defaults()
    return any(value is decision for value in bound.arguments.values())


def _receipt_text(receipt) -> str:
    if receipt is None:
        return ""
    if isinstance(receipt, str):
        return receipt
    stdout = getattr(receipt, "stdout", None)
    if stdout:
        return str(stdout)
    if isinstance(receipt, Mapping):
        return json.dumps(receipt, default=str)
    return str(receipt)


def _flag(receipt, *keys: str) -> bool:
    if isinstance(receipt, Mapping):
        return any(receipt.get(key) is True for key in keys)
    return any(getattr(receipt, key, None) is True for key in keys)


def _box_receipt(atoms_result, isolation_root: Path):
    for attr in _PROVE_ATTRS:
        rec = getattr(atoms_result, attr, None)
        if rec is not None:
            return rec
    consumer = _box_consumer(isolation_root)
    if consumer is None:
        return None
    return consumer(atoms_result)


def _box_consumer(isolation_root: Path):
    # Named door for later wiring. Do not run prove. Do not treat the dry print as this door.
    for rel, fn_name in (
        ("box_boundary.py", "prove_receipt_for"),
        ("scripts/box_boundary.py", "prove_receipt_for"),
    ):
        path = isolation_root / rel
        if not path.is_file() or path.name in _REFUSED_BOX_SCRIPTS:
            continue
        sys.path.insert(0, str(path.parent))
        # Isolation stays a sibling roof. Load only a named consumer.
        module = __import__(path.stem)
        fn = getattr(module, fn_name, None)
        if callable(fn):
            return fn
    return None


def _atoms_result_was_input(atoms_result, receipt) -> bool:
    if receipt is None or atoms_result is None:
        return False
    if getattr(receipt, "atoms_result", None) is atoms_result:
        return True
    return isinstance(receipt, Mapping) and receipt.get("atoms_result") is atoms_result


def _is_jailer_prove_receipt(receipt) -> bool:
    if receipt is None:
        return False
    if "HANDOFF_OK" in _receipt_text(receipt):
        return False
    if _flag(receipt, "tool_body_ran_under_jailer"):
        return True
    return _flag(receipt, "jailer") and _flag(receipt, "tool_body_ran")


def test_one_write_needs_three_receipts(tmp_path: Path) -> None:
    atoms_root = _require_sibling(_ATOMS, "engine.py")
    if not (atoms_root / "catalog" / "Aegis-Atoms-v0.yaml").is_file():
        raise AssertionError(
            "missing sibling checkout: aegis-atoms (catalog/Aegis-Atoms-v0.yaml)"
        )
    isolation_root = _require_sibling(_ISOLATION, "scripts/conflicting_handoff.py")

    if str(atoms_root) not in sys.path:
        sys.path.insert(0, str(atoms_root))
    # Sibling roof: import after the checkout assert so a miss fails that pin.
    import engine
    from engine import load_catalog

    path = str(tmp_path / "SOUL.md")
    policy = load_policy(
        {
            "skills": {
                "note-taker": {
                    "tools": ["write_file"],
                    "paths": [str(tmp_path / "**")],
                }
            }
        }
    )
    gate = Gate(policy, log_path=str(tmp_path / "decisions.jsonl"), mode=ENFORCE)

    decision = None
    with _watch(Gate, "evaluate") as (gate_hits, _real_gate):
        decision = gate.evaluate("note-taker", "write_file", [path])
    if not gate_hits:
        raise AssertionError("Gate.evaluate was skipped")
    if decision is None:
        raise AssertionError("Gate.evaluate returned None")

    env = {
        "HERMES_HOME": str(tmp_path),
        "OBSIDIAN_VAULT_PATH": str(tmp_path / "vault"),
    }
    catalog = load_catalog(atoms_root / "catalog" / "Aegis-Atoms-v0.yaml", env)
    extra = _decision_kwargs(engine.evaluate_tool_call, decision)

    atoms_result = None
    with _watch(engine, "evaluate_tool_call") as (atoms_hits, real_atoms):
        atoms_result = engine.evaluate_tool_call(
            catalog,
            "write_file",
            {"path": path, "content": "x"},
            env=env,
            plugin_mode="enforce",
            **extra,
        )
    if not atoms_hits:
        raise AssertionError("evaluate_tool_call was skipped")
    if atoms_result is None:
        raise AssertionError("evaluate_tool_call returned None")
    firings = getattr(atoms_result, "firings", None)
    if firings is None:
        raise AssertionError("evaluate_tool_call returned no firings")
    if len(firings) == 0:
        raise AssertionError("evaluate_tool_call returned empty firings")

    args, kwargs, _out = atoms_hits[-1]
    receipt = _box_receipt(atoms_result, isolation_root)
    misses: list[str] = []
    if not _decision_was_input(real_atoms, decision, args, kwargs):
        misses.append("gate decision was not the input to evaluate_tool_call")
    if not _atoms_result_was_input(atoms_result, receipt):
        misses.append("atoms result was not the input to the next step")
    if not _is_jailer_prove_receipt(receipt):
        misses.append("box step is not a prove receipt")
    assert misses == []
