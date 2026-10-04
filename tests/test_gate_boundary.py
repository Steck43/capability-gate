"""Three receipts in order: gate into atoms, atoms into a jailer prove receipt."""

from __future__ import annotations

import inspect
import os
import sys
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import fields, is_dataclass
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
# isolation-manager prove.rs summary. Not a flag this test invented.
_MANAGER_PROVE = "crates/isolation-manager/src/prove.rs"
_MANAGER_MODE = "jailed-via-helper"
# scripts/b1-prove.py writes b1_results.json when --mode jailed.
_B1_PROVE = "scripts/b1-prove.py"
_B1_MODE = "jailed"


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
    return str(receipt)


def _get(receipt, key: str):
    if isinstance(receipt, Mapping):
        return receipt.get(key)
    return getattr(receipt, key, None)


def _is_jailer_prove_receipt(receipt) -> bool:
    """True only for the prove summary isolation already emits. HANDOFF_OK is not it."""
    if receipt is None:
        return False
    if "HANDOFF_OK" in _receipt_text(receipt):
        return False
    jail_id = _get(receipt, "jail_id")
    workload = _get(receipt, "time_to_workload_ms")
    if not jail_id or workload is None:
        return False
    mode = _get(receipt, "mode")
    if mode == _MANAGER_MODE:
        return _get(receipt, "time_to_userspace_ms") is not None
    if mode == _B1_MODE:
        return _get(receipt, "checks") is not None
    return False


def _values_on(obj) -> list:
    out: list = []
    if obj is None:
        return out
    if isinstance(obj, Mapping):
        out.extend(obj.values())
    if is_dataclass(obj) and not isinstance(obj, type):
        out.extend(getattr(obj, f.name) for f in fields(obj))
    elif hasattr(obj, "__dict__"):
        out.extend(obj.__dict__.values())
    return out


def _box_receipt(atoms_result):
    # Do not run prove. Look only for the summary prove.rs / b1-prove.py already write.
    if _is_jailer_prove_receipt(atoms_result):
        return atoms_result
    for value in _values_on(atoms_result):
        if _is_jailer_prove_receipt(value):
            return value
    return None


def _atoms_result_was_input(atoms_result, receipt) -> bool:
    # A dict that stores the object is a shadow write. The evaluation itself
    # has to be the prove summary, or the next step had to take it as an argument.
    if receipt is None or atoms_result is None:
        return False
    return receipt is atoms_result


def test_one_write_needs_three_receipts(tmp_path: Path) -> None:
    atoms_root = _require_sibling(_ATOMS, "engine.py")
    if not (atoms_root / "catalog" / "Aegis-Atoms-v0.yaml").is_file():
        raise AssertionError(
            "missing sibling checkout: aegis-atoms (catalog/Aegis-Atoms-v0.yaml)"
        )
    isolation_root = _require_sibling(_ISOLATION, "scripts/conflicting_handoff.py")
    manager_prove = isolation_root / _MANAGER_PROVE
    b1_prove = isolation_root / _B1_PROVE
    if not manager_prove.is_file() and not b1_prove.is_file():
        raise AssertionError(
            f"missing sibling checkout: isolation-layer ({_MANAGER_PROVE} or {_B1_PROVE})"
        )

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
    receipt = _box_receipt(atoms_result)
    misses: list[str] = []
    if not _decision_was_input(real_atoms, decision, args, kwargs):
        misses.append("gate decision was not the input to evaluate_tool_call")
    if not _atoms_result_was_input(atoms_result, receipt):
        misses.append("atoms result was not the input to the next step")
    if not _is_jailer_prove_receipt(receipt):
        misses.append("box step is not a prove receipt")
    assert misses == []
