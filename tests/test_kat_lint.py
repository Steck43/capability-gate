"""KAT linter: reject tests that are red by fiat or never touch the gate."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "kat_lint.py"

HARD_CODED_FAIL = '''
import pytest


def test_k9_escape_denied():
    """Failing-first until the fix lands."""
    pytest.fail("not yet measured")
'''

RECEIPT_ONLY = """
from pathlib import Path


def test_k9_receipt_exists():
    assert (Path(__file__).parent / "K9.md").is_file()
"""

REAL_GATE_CALL = """
import sys
from pathlib import Path

sys.path.insert(0, {root!r})

import pytest

from capability_gate import Gate, Verdict, load_policy


@pytest.fixture()
def gate(tmp_path):
    policy = load_policy(
        {{"skills": {{"writer": {{"tools": ["read_file"], "paths": [str(tmp_path) + "/work/**"]}}}}}}
    )
    return Gate(policy, log_path=str(tmp_path / "decisions.jsonl"))


def _attempt(gate, tmp_path):
    return gate.evaluate("writer", "read_file", [str(tmp_path / "outside.txt")])


def test_k9_off_grant_read_denied(gate, tmp_path):
    assert _attempt(gate, tmp_path).verdict is Verdict.DENY
"""


def _lint(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(path)],
        capture_output=True,
        text=True,
        check=False,
    )


def _write(tmp_path: Path, name: str, src: str) -> Path:
    tests = tmp_path / "tests"
    tests.mkdir(exist_ok=True)
    p = tests / name
    p.write_text(src, encoding="utf-8")
    return p


def test_hard_coded_fail_is_rejected(tmp_path: Path) -> None:
    r = _lint(_write(tmp_path, "test_k9_fail.py", HARD_CODED_FAIL))
    assert r.returncode == 1
    assert "first statement is an unconditional pytest.fail" in r.stdout


def test_receipt_only_is_rejected(tmp_path: Path) -> None:
    r = _lint(_write(tmp_path, "test_k9_receipt.py", RECEIPT_ONLY))
    assert r.returncode == 1
    assert "never calls the gate" in r.stdout


def test_real_gate_call_asserting_deny_is_accepted(tmp_path: Path) -> None:
    src = REAL_GATE_CALL.format(root=str(ROOT))
    path = _write(tmp_path, "test_k9_real.py", src)
    r = _lint(path)
    assert r.returncode == 0, r.stdout
    # The accepted fixture is a working test, not only a lint-shaped one.
    run = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(path)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0, run.stdout + run.stderr


def test_discovery_finds_kat_files_by_name_and_marker(tmp_path: Path) -> None:
    _write(tmp_path, "test_k9_fail.py", HARD_CODED_FAIL)
    _write(tmp_path, "test_scaffold_kat.py", RECEIPT_ONLY)
    _write(tmp_path, "test_marked.py", "# KAT\n" + RECEIPT_ONLY)
    _write(tmp_path, "test_unrelated.py", RECEIPT_ONLY)
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 1
    assert "in 3 KAT file(s)" in r.stdout
    assert "test_unrelated.py" not in r.stdout


def test_this_repo_kats_pass() -> None:
    r = subprocess.run(
        [sys.executable, str(SCRIPT)], capture_output=True, text=True, check=False
    )
    assert r.returncode == 0, r.stdout
