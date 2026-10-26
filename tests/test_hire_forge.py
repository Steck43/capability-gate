"""60-second forge-reject audit: every log rewrite is rejected by the real
verifier, the gate refuses to append onto it, and the audit names the first
broken row. The full-folder rewrite limit is pinned, not hidden.
"""

from __future__ import annotations

import importlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import capability_gate as cg

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "demos" / "hire"))
sys.path.insert(0, str(ROOT))

fa = importlib.import_module("forge_audit")


@pytest.fixture(scope="module")
def audit(tmp_path_factory):
    return fa.run(tmp_path_factory.mktemp("forge"))


def _by(audit, name):
    (a,) = [x for x in audit.attacks if x.attack == name]
    return a


def test_forge_baseline_verifies(audit):
    assert audit.baseline_ok
    assert audit.baseline_rows == 10


@pytest.mark.parametrize("attack", fa.ATTACKS)
def test_forge_attack_rejected(audit, attack):
    a = _by(audit, attack)
    assert a.rejected, a.error
    assert a.append_refused


def test_forge_rewrite_mid_names_row(audit):
    a = _by(audit, "rewrite-mid")
    assert a.first_bad_row is not None
    assert "hash chain broken" in a.error


def test_forge_rewrite_last_caught_by_witness(audit):
    assert "witness" in _by(audit, "rewrite-last").error


def test_forge_rechain_caught_by_witness(audit):
    assert "witness" in _by(audit, "rechain").error


def test_forge_rechain_witness_caught_by_anchor(audit):
    assert "anchor" in _by(audit, "rechain-witness").error


def test_forge_honest_limit_is_reported(audit):
    assert audit.limit_passes is True


def test_forge_external_anchor_rejects_full_rewrite(audit):
    assert audit.external_anchor_rejects is True


def test_forge_runs_inside_sixty_seconds(audit):
    assert audit.elapsed_s < 60


def _fresh(tmp_path, n_pairs: int):
    work = tmp_path / "work"
    work.mkdir(parents=True)
    policy = cg.load_policy(
        {"skills": {"w": {"tools": ["read_file"], "paths": [f"{work}/**"]}}}
    )
    log = tmp_path / "audit" / "decisions.jsonl"
    gate = cg.Gate(policy, str(log))
    for i in range(n_pairs):
        gate.evaluate("w", "read_file", [str(work / f"{i}.txt")])
        gate.evaluate("w", "shell", [])
    return log


@pytest.mark.parametrize("n_pairs", [1, 2, 3, 5, 8])
@pytest.mark.parametrize("attack", fa.ATTACKS)
def test_forge_attack_matrix_on_log_sizes(tmp_path, n_pairs, attack):
    log = _fresh(tmp_path, n_pairs)
    cg.verify_hash_chain(str(log))
    fa.apply_attack(attack, log)
    with pytest.raises(ValueError):
        cg.verify_hash_chain(str(log))


@pytest.mark.parametrize("n_pairs", [2, 4, 7])
def test_forge_every_single_row_rewrite_rejected_at_its_row(tmp_path, n_pairs):
    src = _fresh(tmp_path / "src", n_pairs)
    lines = fa._lines(src)
    for idx in range(len(lines)):
        case = tmp_path / f"case{idx}"
        shutil.copytree(src.parent, case)
        clog = case / "decisions.jsonl"
        mutated = list(lines)
        mutated[idx] = fa._flip(mutated[idx])
        fa._write(clog, mutated)
        with pytest.raises(ValueError):
            cg.verify_hash_chain(str(clog))
        expected = idx + 2 if idx + 1 < len(lines) else len(lines) + 1
        assert fa.first_bad_row(clog) == expected


@pytest.mark.parametrize("field", ["tool", "skill", "reason", "mode", "enforced", "ts"])
def test_forge_any_field_edit_rejected(tmp_path, field):
    log = _fresh(tmp_path, 3)
    lines = fa._lines(log)
    rec = json.loads(lines[1])
    rec[field] = "forged" if not isinstance(rec[field], bool) else (not rec[field])
    lines[1] = json.dumps(rec, sort_keys=True)
    fa._write(log, lines)
    with pytest.raises(ValueError):
        cg.verify_hash_chain(str(log))
    assert fa.first_bad_row(log) == 3


def test_forge_whitespace_only_edit_rejected(tmp_path):
    log = _fresh(tmp_path, 2)
    lines = fa._lines(log)
    lines[0] = lines[0].replace('": ', '":  ', 1)
    fa._write(log, lines)
    with pytest.raises(ValueError):
        cg.verify_hash_chain(str(log))


def test_forge_first_bad_row_none_on_clean_log(tmp_path):
    assert fa.first_bad_row(_fresh(tmp_path, 3)) is None


def test_forge_unknown_attack_refused(tmp_path):
    with pytest.raises(ValueError):
        fa.apply_attack("nope", _fresh(tmp_path, 1))


def test_forge_command_exits_zero(tmp_path):
    proc = subprocess.run(
        [sys.executable, "demos/hire/forge_audit.py", "--out", str(tmp_path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "RESULT: PASS" in proc.stdout
    data = json.loads((tmp_path / "forge.json").read_text(encoding="utf-8"))
    assert data["ok"] is True
    assert len(data["attacks"]) == len(fa.ATTACKS)
