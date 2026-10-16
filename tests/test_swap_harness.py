"""The behavioral known-answer test check (scripts/kat_swap.py), run on small
known inputs.

Each input is a one-test file run under the real gate, allow-all, deny-all,
the inverted gate and, for the honest case, every per-branch mutant of the
decision. The check must call a test real only when its answer follows the
gate, and must say why every other test is not.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

ROOF = Path(__file__).resolve().parents[1]
SCRIPT = ROOF / "scripts" / "kat_swap.py"

HEAD = """
import pytest

from capability_gate import Gate, Verdict, load_policy


@pytest.fixture()
def gate(tmp_path):
    return Gate(load_policy({"skills": {}}), log_path=str(tmp_path / "d.jsonl"))

"""

HONEST = (
    HEAD
    + """
def test_unknown_skill_denied(gate):
    d = gate.evaluate("s", "write_file", ["x"])
    assert d.verdict is Verdict.DENY
"""
)

# Calls the gate but asserts nothing that depends on the answer.
WEAK = (
    HEAD
    + """
def test_answer_not_read(gate):
    d = gate.evaluate("s", "write_file", ["x"])
    assert d is not None
"""
)

NO_CALL = (
    HEAD
    + """
def test_gate_never_asked(gate):
    assert gate is not None
"""
)

SKIPPED = (
    HEAD
    + """
@pytest.mark.skip(reason="never runs")
def test_skipped(gate):
    d = gate.evaluate("s", "write_file", ["x"])
    assert d.verdict is Verdict.DENY
"""
)

# Changes the gate module in the copy it runs in.
TAMPER = (
    HEAD
    + """
from pathlib import Path

import capability_gate


def test_edits_the_gate_module(gate):
    with Path(capability_gate.__file__).open("a", encoding="utf-8") as fh:
        fh.write("\\n")
    d = gate.evaluate("s", "write_file", ["x"])
    assert d.verdict is Verdict.DENY
"""
)


@pytest.fixture(scope="module")
def swap():
    spec = importlib.util.spec_from_file_location("kat_swap", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["kat_swap"] = mod
    spec.loader.exec_module(mod)
    return mod


def _copies(swap, request, **kw):
    copies, modes = swap.make_copies(**kw)
    request.addfinalizer(
        lambda: shutil.rmtree(next(iter(copies.values())).parent, ignore_errors=True)
    )
    return copies, modes


@pytest.fixture(scope="module")
def fixed(swap, request):
    return _copies(swap, request, strip=set(), mutants=False)


@pytest.fixture(scope="module")
def full(swap, request):
    return _copies(swap, request, strip=set(), mutants=True)


def _one(swap, copies_modes, tmp_path, name, src):
    kat = tmp_path / name
    kat.write_text(src, encoding="utf-8")
    copies, modes = copies_modes
    (row,) = swap.judge(kat, copies, modes)["tests"]
    return row


def test_an_honest_kat_is_real_and_kills_a_mutant(swap, full, tmp_path):
    row = _one(swap, full, tmp_path, "test_k_honest.py", HONEST)
    assert row["verdict"] == "real", row
    assert row["kills"], row


def test_a_kat_that_never_reads_the_answer_is_hollow(swap, fixed, tmp_path):
    row = _one(swap, fixed, tmp_path, "test_k_weak.py", WEAK)
    assert row["verdict"] == "hollow", row
    assert "inverted" in row["why"], row


def test_a_kat_that_never_asks_the_gate_is_hollow(swap, fixed, tmp_path):
    row = _one(swap, fixed, tmp_path, "test_k_no_call.py", NO_CALL)
    assert row["verdict"] == "hollow", row
    assert "never reached" in row["why"], row


def test_a_skipped_kat_is_not_run(swap, fixed, tmp_path):
    row = _one(swap, fixed, tmp_path, "test_k_skipped.py", SKIPPED)
    assert row["verdict"] == "not-run", row


def test_a_kat_that_edits_the_gate_module_is_tamper(swap, fixed, tmp_path):
    row = _one(swap, fixed, tmp_path, "test_k_tamper.py", TAMPER)
    assert row["verdict"] == "tamper", row


def test_a_tamper_does_not_reach_the_next_file(swap, fixed, tmp_path):
    _one(swap, fixed, tmp_path, "test_k_tamper.py", TAMPER)
    row = _one(swap, fixed, tmp_path, "test_k_after.py", WEAK)
    assert row["verdict"] == "hollow", row
    assert "inverted" in row["why"], row


def test_stripping_the_substitutes_turns_an_honest_kat_hollow(swap, request, tmp_path):
    stripped = _copies(swap, request, strip={"all"}, mutants=False)
    row = _one(swap, stripped, tmp_path, "test_k_honest.py", HONEST)
    assert row["verdict"] == "hollow", row


def test_every_constant_verdict_in_the_decision_is_a_mutant_site(swap):
    src = (ROOF / "capability_gate.py").read_text(encoding="utf-8")
    sites = swap.mutant_sites(src)
    labels = [s[0] for s in sites]
    assert len(labels) >= 10, labels
    assert len(set(labels)) == len(labels), labels
    for site in sites:
        changed = [
            (a, b)
            for a, b in zip(src.splitlines(), swap.mutate(src, site).splitlines())
            if a != b
        ]
        assert len(changed) == 1, (site, changed)


def test_discovery_finds_the_kill_switch_kats_and_not_this_file(swap):
    found = {p.relative_to(ROOF).as_posix() for p in swap.kat_files(ROOF)}
    assert "tests/test_kill_switch.py" in found
    assert "tests/test_swap_harness.py" not in found


def test_children_get_a_clean_environment(swap, tmp_path, monkeypatch):
    monkeypatch.setenv("PYTEST_ADDOPTS", "-p no_such_plugin")
    monkeypatch.setenv("KAT_SWAP_UNRELATED", "1")
    env = swap.clean_env(tmp_path / "beacon.tsv")
    assert "PYTEST_ADDOPTS" not in env
    assert "KAT_SWAP_UNRELATED" not in env
    assert env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert env["KAT_SWAP_BEACON"] == str(tmp_path / "beacon.tsv")
    assert Path(env["TMPDIR"]).is_relative_to(tmp_path)


DUP_CLASS = (
    HEAD
    + """
class TestA:
    def test_same(self, gate):
        d = gate.evaluate("s", "write_file", ["x"])
        assert d.verdict is Verdict.DENY


class TestB:
    def test_same(self, gate):
        assert gate is not None
"""
)

NO_REPORT = (
    HEAD
    + """
import os


def test_exits_before_report(gate):
    d = gate.evaluate("s", "write_file", ["x"])
    assert d.verdict is Verdict.DENY
    os._exit(0)
"""
)


def _all(swap, copies_modes, tmp_path, name, src):
    kat = tmp_path / name
    kat.write_text(src, encoding="utf-8")
    copies, modes = copies_modes
    return {t["id"]: t for t in swap.judge(kat, copies, modes)["tests"]}


def test_same_named_tests_in_two_classes_get_two_rows(swap, fixed, tmp_path):
    rows = _all(swap, fixed, tmp_path, "test_k_dup.py", DUP_CLASS)
    assert len(rows) == 2, rows
    assert {r["verdict"] for r in rows.values()} == {"real", "hollow"}, rows
    assert all(i.split("::")[0] for i in rows), rows


def test_a_child_with_no_junit_report_is_broken(swap, fixed, tmp_path):
    rows = _all(swap, fixed, tmp_path, "test_k_noreport.py", NO_REPORT)
    assert rows["<module>"]["verdict"] == "broken", rows
    assert "no junit report" in rows["<module>"]["why"], rows
    assert list(rows) == ["<module>"], rows


def test_the_real_column_beacons(swap, fixed, tmp_path):
    kat = tmp_path / "test_k_honest.py"
    kat.write_text(HONEST, encoding="utf-8")
    copies, modes = fixed
    assert swap.judge(kat, copies, modes)["reach"]["real"]["lines"] >= 1


def test_duplicate_ids_are_broken(swap):
    o = {m: "failed" for m in swap.FIXED}
    o["real"] = "passed"
    o[swap.FIXED[-1]] = "duplicate"
    reach = {m: {"lines": 1} for m in swap.FIXED}
    verdict, why = swap._verdict(o, [], reach, [])
    assert verdict == "broken"
    assert why == "duplicate test id in the junit report"
