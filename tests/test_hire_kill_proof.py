"""Kill-switch proof for the hire demo: throw, then every tool is denied,
every denial is logged, nothing runs, and the chain still verifies.

Covers the default anchor beside the log and an operator anchor outside the
log folder. A switch thrown from another process stops a gate that is already
running, with no restart. Observe mode is pinned as the honest limit: the
deny is logged and the host would still run the call.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import capability_gate as cg

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


GRANTED = ("read_file", "write_file", "list_dir", "search")
UNGRANTED = ("shell", "http_post", "delete_file", "spawn_agent", "mcp_call")
UNKNOWN = ("", "tool_nobody_named", "READ_FILE", "read_file ", "../shell")
ALL_TOOLS = GRANTED + UNGRANTED + UNKNOWN
SKILLS = ("writer", "UNLABELED", "")
ANCHORS = ("beside", "external")


def _rows(log: Path) -> list[dict]:
    return [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines() if x]


def _setup(tmp_path: Path, anchor: str, mode: str = cg.ENFORCE):
    work = tmp_path / "work"
    work.mkdir()
    (work / "a.txt").write_text("a", encoding="utf-8")
    policy = cg.load_policy(
        {"skills": {"writer": {"tools": list(GRANTED), "paths": [f"{work}/**"]}}}
    )
    log = tmp_path / "audit" / "decisions.jsonl"
    anchor_path = None
    if anchor == "external":
        (tmp_path / "operator").mkdir()
        anchor_path = str(tmp_path / "operator" / "decisions.anchor")
    gate = cg.Gate(policy, str(log), mode=mode, anchor_path=anchor_path)
    return gate, log, work, anchor_path


def _host_runs(d: cg.Decision) -> bool:
    return (not d.enforced) or d.verdict is cg.Verdict.ALLOW


@pytest.mark.parametrize("anchor", ANCHORS)
@pytest.mark.parametrize("skill", SKILLS)
@pytest.mark.parametrize("tool", ALL_TOOLS)
def test_after_throw_every_tool_denied_logged_and_chain_verifies(
    tmp_path, anchor, skill, tool
):
    gate, log, work, anchor_path = _setup(tmp_path, anchor)
    before = gate.evaluate("writer", "read_file", [str(work / "a.txt")])
    assert before.verdict is cg.Verdict.ALLOW
    assert gate.throw("proof") is True
    n_before = len(_rows(log))
    d = gate.evaluate(skill, tool, [str(work / "a.txt")])
    assert d.verdict is cg.Verdict.DENY
    assert d.enforced is True
    assert "kill switch" in d.reason
    assert not _host_runs(d)
    rows = _rows(log)
    assert len(rows) == n_before + 1
    assert rows[-1]["verdict"] == "deny"
    assert rows[-1]["tool"] == tool
    assert cg.verify_hash_chain(str(log), anchor_path=anchor_path)


@pytest.mark.parametrize("anchor", ANCHORS)
def test_throw_row_keeps_operator_anchor_in_step(tmp_path, anchor):
    gate, log, work, anchor_path = _setup(tmp_path, anchor)
    gate.evaluate("writer", "read_file", [str(work / "a.txt")])
    gate.throw("anchor step")
    head = cg.verify_hash_chain(str(log), anchor_path=anchor_path)
    rows = _rows(log)
    assert rows[-1]["verdict"] == "thrown"
    assert "anchor step" in rows[-1]["reason"]
    assert len(rows) == 2
    assert head != cg._GENESIS


def test_throw_with_external_anchor_writes_no_stray_anchor_beside_log(tmp_path):
    gate, log, work, _anchor_path = _setup(tmp_path, "external")
    gate.evaluate("writer", "read_file", [str(work / "a.txt")])
    gate.throw("stray")
    assert not Path(cg._anchor_path(str(log))).exists()


@pytest.mark.parametrize("anchor", ANCHORS)
@pytest.mark.parametrize("n_calls", [1, 2, 5, 17])
def test_every_post_throw_call_has_its_own_row(tmp_path, anchor, n_calls):
    gate, log, work, anchor_path = _setup(tmp_path, anchor)
    gate.throw("burst")
    base = len(_rows(log))
    decisions = [
        gate.evaluate("writer", ALL_TOOLS[i % len(ALL_TOOLS)], [str(work / "a.txt")])
        for i in range(n_calls)
    ]
    assert sum(_host_runs(d) for d in decisions) == 0
    rows = _rows(log)
    assert len(rows) == base + n_calls
    assert {r["verdict"] for r in rows[base:]} == {"deny"}
    assert cg.verify_hash_chain(str(log), anchor_path=anchor_path)


@pytest.mark.parametrize("anchor", ANCHORS)
def test_second_throw_is_noop_and_adds_no_row(tmp_path, anchor):
    gate, log, _work, anchor_path = _setup(tmp_path, anchor)
    assert gate.throw("one") is True
    n = len(_rows(log))
    assert gate.throw("two") is False
    assert len(_rows(log)) == n
    assert cg.verify_hash_chain(str(log), anchor_path=anchor_path)


@pytest.mark.parametrize("anchor", ANCHORS)
def test_throw_from_another_process_stops_running_gate(tmp_path, anchor):
    gate, log, work, anchor_path = _setup(tmp_path, anchor)
    assert gate.evaluate("writer", "read_file", [str(work / "a.txt")]).verdict is (
        cg.Verdict.ALLOW
    )
    code = (
        "import sys, capability_gate as cg;"
        "p = cg.load_policy({'skills': {}});"
        "g = cg.Gate(p, sys.argv[1], anchor_path=(sys.argv[2] or None));"
        "assert g.throw('other process')"
    )
    subprocess.run(
        [sys.executable, "-c", code, str(log), anchor_path or ""],
        cwd=ROOT,
        check=True,
    )
    d = gate.evaluate("writer", "read_file", [str(work / "a.txt")])
    assert d.verdict is cg.Verdict.DENY
    assert "kill switch" in d.reason
    assert cg.verify_hash_chain(str(log), anchor_path=anchor_path)


def test_second_gate_on_same_log_also_denies(tmp_path):
    gate, log, work, _a = _setup(tmp_path, "beside")
    gate.throw("fleet")
    other = cg.Gate(gate._policy, str(log))
    assert other.evaluate("writer", "read_file", [str(work / "a.txt")]).verdict is (
        cg.Verdict.DENY
    )


@pytest.mark.parametrize("tool", GRANTED)
def test_observe_mode_after_throw_logs_deny_but_does_not_enforce(tmp_path, tool):
    gate, log, work, _a = _setup(tmp_path, "beside", mode=cg.OBSERVE)
    gate.throw("observe")
    d = gate.evaluate("writer", tool, [str(work / "a.txt")])
    assert d.verdict is cg.Verdict.DENY
    assert d.enforced is False
    assert _host_runs(d)
    assert _rows(log)[-1]["enforced"] is False


def test_kill_switch_marker_cannot_be_cleared_through_a_tool_path(tmp_path):
    _gate, log, _work, _a = _setup(tmp_path, "beside")
    policy = cg.load_policy(
        {"skills": {"writer": {"tools": ["delete_file"], "paths": [f"{tmp_path}/**"]}}}
    )
    g2 = cg.Gate(policy, str(log))
    d = g2.evaluate("writer", "delete_file", [cg.halt_marker_path(str(log))])
    assert d.verdict is cg.Verdict.DENY
    assert "kill switch" in d.reason


@settings(max_examples=60, deadline=None)
@given(
    pre=st.lists(st.sampled_from(ALL_TOOLS), max_size=6),
    post=st.lists(st.sampled_from(ALL_TOOLS), min_size=1, max_size=8),
    anchor=st.sampled_from(ANCHORS),
)
def test_property_nothing_runs_after_throw(tmp_path_factory, pre, post, anchor):
    tmp = tmp_path_factory.mktemp("prop")
    gate, log, work, anchor_path = _setup(tmp, anchor)
    for t in pre:
        gate.evaluate("writer", t, [str(work / "a.txt")])
    gate.throw("prop")
    base = len(_rows(log))
    ds = [gate.evaluate("writer", t, [str(work / "a.txt")]) for t in post]
    assert [d.verdict for d in ds] == [cg.Verdict.DENY] * len(post)
    assert len(_rows(log)) == base + len(post)
    cg.verify_hash_chain(str(log), anchor_path=anchor_path)
