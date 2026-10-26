"""The one-command hire demo: allow, deny, kill switch, fail closed, verify.

Each test reads the demo's own rows and checks against the real gate, so a
mutant that deletes a control (see demos/hire/mutants.yaml) turns one of
these red. The command itself runs once as a subprocess, the way a reviewer
runs it.
"""

from __future__ import annotations

import importlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

import capability_gate as cg

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "demos" / "hire"))
sys.path.insert(0, str(ROOT))

hire_demo = importlib.import_module("hire_demo")


@pytest.fixture(scope="module")
def result(tmp_path_factory):
    return hire_demo.run(tmp_path_factory.mktemp("demo"))


def _rows(result, step):
    return [r for r in result.rows if r.step == step]


def _check(result, name):
    hits = [ok for c, ok in result.checks if c == name]
    assert len(hits) == 1, name
    return hits[0]


def test_demo_all_checks_pass(result):
    failed = [c for c, ok in result.checks if not ok]
    assert failed == []
    assert result.ok


def test_demo_allow_row_runs(result):
    (row,) = _rows(result, "1 ALLOW")
    assert row.verdict == "allow"
    assert row.executed is True
    assert _check(result, "allow: granted call is ALLOW and runs")


def test_demo_deny_tool_not_granted(result):
    row = _rows(result, "2 DENY")[0]
    assert row.verdict == "deny"
    assert row.executed is False
    assert "not granted" in row.reason


def test_demo_deny_path_outside(result):
    row = _rows(result, "2 DENY")[1]
    assert row.verdict == "deny"
    assert row.executed is False
    assert "outside allowlist" in row.reason


def test_demo_deny_canary(result):
    row = _rows(result, "2 DENY")[2]
    assert row.verdict == "deny"
    assert "canary" in row.reason


def test_demo_deny_protected_env(result):
    row = _rows(result, "2 DENY")[3]
    assert row.verdict == "deny"
    assert "protected" in row.reason


def test_demo_kill_every_tool_denied(result):
    rows = _rows(result, "3 KILL")
    expected = len(hire_demo.GRANTED_TOOLS) + len(hire_demo.UNGRANTED_TOOLS) + 1
    assert len(rows) == expected
    assert {r.verdict for r in rows} == {"deny"}
    assert result.executed_after_kill == 0
    assert all("kill switch" in r.reason for r in rows)


def test_demo_kill_rows_logged_and_thrown_row(result):
    assert _check(result, "kill: one THROWN row on the chain")
    assert _check(result, "kill: every post-throw call has its own DENY row")


def test_demo_chain_verifies_after_kill(result):
    assert _check(result, "verify: chain verifies after the kill")
    assert len(result.chain_head) == 64
    assert result.chain_head != cg._GENESIS
    assert result.chain_rows >= 13


def test_demo_fail_closed_policy(result):
    assert _check(result, "fail-closed: malformed policy refused at load")


def test_demo_fail_closed_gate_error(result):
    assert _check(result, "fail-closed: gate error is DENY and blocked")
    assert _check(result, "fail-closed: gate error DENY is on the log")


def test_demo_fail_closed_log_folder(result):
    assert _check(result, "fail-closed: removed log folder denies a granted call")
    assert _check(result, "fail-closed: removed log folder is not silently re-created")


def test_demo_observe_is_honest(result):
    (row,) = _rows(result, "6 OBSERVE")
    assert row.verdict == "deny"
    assert row.enforced is False
    assert row.executed is True


@pytest.mark.parametrize(
    "verdict,enforced,runs",
    [
        (cg.Verdict.ALLOW, True, True),
        (cg.Verdict.DENY, True, False),
        (cg.Verdict.ASK, True, False),
        (cg.Verdict.ISOLATE, True, False),
        (cg.Verdict.THROWN, True, False),
        (cg.Verdict.ALLOW, False, True),
        (cg.Verdict.DENY, False, True),
        (cg.Verdict.ASK, False, True),
    ],
)
def test_demo_host_runs_table(verdict, enforced, runs):
    d = cg.Decision(verdict, "r", "s", "t", enforced=enforced)
    assert hire_demo.host_runs(d) is runs


def test_demo_render_has_every_step(result):
    text = hire_demo.render(result)
    for step in ("1 ALLOW", "2 DENY", "3 KILL", "4 FAILCLOSED", "6 OBSERVE"):
        assert step in text
    assert "RESULT: PASS" in text
    assert "executed_after_kill = 0" in text
    assert "\u2014" not in text


def test_demo_is_deterministic_in_verdicts(tmp_path):
    a = hire_demo.run(tmp_path / "a")
    b = hire_demo.run(tmp_path / "b")
    assert [(r.step, r.verdict, r.executed) for r in a.rows] == [
        (r.step, r.verdict, r.executed) for r in b.rows
    ]
    assert a.chain_rows == b.chain_rows


def test_demo_one_command_exits_zero_and_writes_artifacts(tmp_path):
    out = tmp_path / "out"
    proc = subprocess.run(
        [sys.executable, "demos/hire/hire_demo.py", "--out", str(out)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "RESULT: PASS" in proc.stdout
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["ok"] is True
    assert summary["executed_after_kill"] == 0
    assert (out / "demo-output.txt").read_text(encoding="utf-8") == proc.stdout


def test_demo_json_mode(tmp_path):
    proc = subprocess.run(
        [sys.executable, "demos/hire/hire_demo.py", "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert data["ok"] is True
    assert {c["ok"] for c in data["checks"]} == {True}


def test_demo_leaves_no_sandbox(tmp_path, monkeypatch):
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    import tempfile

    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    assert hire_demo.main([]) == 0
    assert list(tmp_path.iterdir()) == []
