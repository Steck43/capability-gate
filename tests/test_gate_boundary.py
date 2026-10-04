"""Gate then atoms. Dry HANDOFF_OK is not a boundary."""

from __future__ import annotations

import os
import subprocess
import sys
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


def _require_sibling(name: str, rel: str) -> Path:
    raw = os.environ.get(_ENV[name], "").strip()
    candidates = [Path(raw)] if raw else []
    candidates.append(ROOF.parent / name)
    for root in candidates:
        if (root / rel).is_file():
            return root
    raise AssertionError(f"missing sibling checkout: {name} ({rel})")


def _evaluate_gate(path: str, log_path: str):
    policy = load_policy(
        {
            "skills": {
                "note-taker": {
                    "tools": ["write_file"],
                    "paths": [str(Path(path).parent / "**")],
                }
            }
        }
    )
    gate = Gate(policy, log_path=log_path, mode=ENFORCE)
    return gate.evaluate("note-taker", "write_file", [path])


def _evaluate_atoms(atoms_root: Path, path: str, tmp_path: Path):
    if str(atoms_root) not in sys.path:
        sys.path.insert(0, str(atoms_root))
    # Sibling roof: import after the checkout assert so a miss fails that pin.
    from engine import evaluate_tool_call, load_catalog

    env = {
        "HERMES_HOME": str(tmp_path),
        "OBSIDIAN_VAULT_PATH": str(tmp_path / "vault"),
    }
    catalog = load_catalog(atoms_root / "catalog" / "Aegis-Atoms-v0.yaml", env)
    return evaluate_tool_call(
        catalog,
        "write_file",
        {"path": path, "content": "x"},
        env=env,
        plugin_mode="enforce",
    )


def test_one_write_needs_a_real_boundary(tmp_path: Path) -> None:
    path = str(tmp_path / "notes" / "entry.md")
    decision = _evaluate_gate(path, str(tmp_path / "decisions.jsonl"))

    atoms_root = _require_sibling(_ATOMS, "engine.py")
    if not (atoms_root / "catalog" / "Aegis-Atoms-v0.yaml").is_file():
        raise AssertionError(
            "missing sibling checkout: aegis-atoms (catalog/Aegis-Atoms-v0.yaml)"
        )
    atoms_result = _evaluate_atoms(atoms_root, path, tmp_path)

    isolation_root = _require_sibling(_ISOLATION, "scripts/conflicting_handoff.py")
    script = isolation_root / "scripts" / "conflicting_handoff.py"
    handoff = subprocess.run(
        [sys.executable, str(script), "CONFLICTING"],
        capture_output=True,
        text=True,
        check=False,
    )

    if decision is None:
        raise AssertionError("Gate.evaluate was skipped")
    if atoms_result is None:
        raise AssertionError("evaluate_tool_call was skipped")
    if decision.verdict is None:
        raise AssertionError("Gate.evaluate was skipped")
    if getattr(atoms_result, "firings", None) is None:
        raise AssertionError("evaluate_tool_call was skipped")

    text = f"{handoff.stdout}{handoff.stderr}"
    if handoff.returncode == 0 or "HANDOFF_OK" in text:
        raise AssertionError(
            "exit 0 or HANDOFF_OK is not the boundary after "
            "Gate.evaluate and evaluate_tool_call; the path is not real"
        )
    raise AssertionError("no real boundary after Gate.evaluate and evaluate_tool_call")
