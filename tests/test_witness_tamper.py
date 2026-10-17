"""Audit tamper: a deleted, shortened, or recomputed witness is caught.

Once a decision log has been anchored, the gate keeps the head hash and record
count twice: in the witness beside the log, and in an anchor that can live in
an operator-owned location outside the agent's tree. Each case below damages
the log the way an agent with file access could, then asks the gate for the
next decision. None of them may be allowed, and the next call must not start a
fresh chain on its own. Only the operator's re-anchor does that.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOF = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOF))

from capability_gate import (  # noqa: E402
    Gate,
    Verdict,
    load_policy,
    reanchor_audit_log,
    verify_hash_chain,
)


def _policy(root: Path):
    return load_policy(
        {"skills": {"s": {"tools": ["write_file"], "paths": [str(root) + "/**"]}}}
    )


@pytest.fixture
def area(tmp_path: Path):
    work = tmp_path / "work"
    work.mkdir()
    logs = tmp_path / "logs"
    anchor = tmp_path / "operator" / "audit.anchor"
    return tmp_path, work, logs / "decisions.jsonl", anchor


@pytest.fixture
def gate(area):
    root, work, log, anchor = area
    g = Gate(_policy(work), log_path=str(log), anchor_path=str(anchor))
    for _ in range(4):
        assert g.evaluate("s", "write_file", [str(work / "a.md")]).verdict is (
            Verdict.ALLOW
        )
    return g


def _not_allowed(gate: Gate, target: Path) -> str:
    """The next decision is a deny or a raised error; never an allow."""
    try:
        d = gate.evaluate("s", "write_file", [str(target)])
    except ValueError as exc:
        return str(exc)
    assert d.verdict is not Verdict.ALLOW, d.reason
    return d.reason


def _lines(log: Path) -> list[str]:
    return log.read_text(encoding="utf-8").splitlines(keepends=True)


def test_a_log_and_witness_deleted(area, gate) -> None:
    _, work, log, anchor = area
    before = anchor.read_bytes()
    os.remove(log)
    os.remove(str(log) + ".witness")
    reason = _not_allowed(gate, work / "a.md")
    assert "anchor" in reason
    assert not log.exists(), "a fresh chain was started"
    assert anchor.read_bytes() == before


def test_b_log_truncated_and_witness_deleted(area, gate) -> None:
    _, work, log, anchor = area
    log.write_text("".join(_lines(log)[:2]), encoding="utf-8")
    os.remove(str(log) + ".witness")
    _not_allowed(gate, work / "a.md")
    assert len(_lines(log)) == 2


def test_c_log_truncated_and_witness_recomputed(area, gate) -> None:
    _, work, log, anchor = area
    kept = _lines(log)[:2]
    log.write_text("".join(kept), encoding="utf-8")
    import hashlib

    head = hashlib.sha256(kept[-1].rstrip("\n").encode("utf-8")).hexdigest()
    Path(str(log) + ".witness").write_text(
        json.dumps({"count": 2, "head": head}) + "\n", encoding="utf-8"
    )
    reason = _not_allowed(gate, work / "a.md")
    assert "anchor" in reason
    with pytest.raises(ValueError, match="anchor"):
        verify_hash_chain(str(log), anchor_path=str(anchor))


def test_d_log_folder_deleted_and_next_call_does_not_reanchor(area, gate) -> None:
    root, work, log, anchor = area
    before = anchor.read_bytes()
    shutil.rmtree(log.parent)
    # A new gate, as after a restart, must not re-anchor either.
    fresh = Gate(_policy(work), log_path=str(log), anchor_path=str(anchor))
    _not_allowed(fresh, work / "a.md")
    _not_allowed(fresh, work / "a.md")
    assert anchor.read_bytes() == before
    assert not log.exists()


def test_clean_first_run_anchors_and_allows(area) -> None:
    _, work, log, anchor = area
    g = Gate(_policy(work), log_path=str(log), anchor_path=str(anchor))
    assert g.evaluate("s", "write_file", [str(work / "a.md")]).verdict is Verdict.ALLOW
    stored = json.loads(anchor.read_text(encoding="utf-8"))
    assert stored["count"] == 1
    assert stored["head"] == verify_hash_chain(str(log), anchor_path=str(anchor))


def test_default_anchor_beside_the_log_catches_b(tmp_path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    log = tmp_path / "logs" / "decisions.jsonl"
    g = Gate(_policy(work), log_path=str(log))
    for _ in range(3):
        g.evaluate("s", "write_file", [str(work / "a.md")])
    assert Path(str(log) + ".anchor").exists()
    log.write_text("".join(_lines(log)[:1]), encoding="utf-8")
    os.remove(str(log) + ".witness")
    _not_allowed(g, work / "a.md")


def test_unreadable_anchor_fails_closed(area, gate) -> None:
    _, work, log, anchor = area
    anchor.write_text("not json\n", encoding="utf-8")
    _not_allowed(gate, work / "a.md")


def test_operator_reanchor_starts_a_new_chain(area, gate) -> None:
    root, work, log, anchor = area
    shutil.rmtree(log.parent)
    _not_allowed(gate, work / "a.md")
    retired = reanchor_audit_log(str(log), anchor_path=str(anchor))
    assert retired and all(Path(p).exists() for p in retired)
    d = gate.evaluate("s", "write_file", [str(work / "a.md")])
    assert d.verdict is Verdict.ALLOW, d.reason
    assert json.loads(anchor.read_text(encoding="utf-8"))["count"] == 1


def test_reanchor_command_line(area, gate) -> None:
    root, work, log, anchor = area
    os.remove(log)
    os.remove(str(log) + ".witness")
    r = subprocess.run(
        [
            sys.executable,
            str(ROOF / "capability_gate.py"),
            "reanchor",
            "--log",
            str(log),
            "--anchor",
            str(anchor),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stderr
    assert "retired" in r.stdout
    assert gate.evaluate("s", "write_file", [str(work / "a.md")]).verdict is (
        Verdict.ALLOW
    )


def test_tool_path_naming_the_anchor_is_denied(area, gate) -> None:
    _, _, _, anchor = area
    policy = load_policy(
        {
            "skills": {
                "s": {"tools": ["write_file"], "paths": [str(anchor.parent) + "/**"]}
            }
        }
    )
    g = Gate(policy, log_path=str(area[2]), anchor_path=str(anchor))
    d = g.evaluate("s", "write_file", [str(anchor)])
    assert d.verdict is Verdict.DENY
    assert "anchor" in d.reason


def _witness_only_deleted(gate: Gate, log: Path, work: Path) -> None:
    os.remove(str(log) + ".witness")
    try:
        d = gate.evaluate("s", "write_file", [str(work / "a.md")])
    except ValueError as exc:
        assert "witness missing" in str(exc)
        return
    assert d.verdict is Verdict.DENY, d.reason
    assert "witness missing" in d.reason


def test_witness_alone_deleted_is_denied(area, gate) -> None:
    _, work, log, anchor = area
    lines_before = len(_lines(log))
    _witness_only_deleted(gate, log, work)
    assert len(_lines(log)) == lines_before
    assert not Path(str(log) + ".witness").exists()


def test_witness_alone_deleted_is_denied_with_default_anchor(tmp_path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    log = tmp_path / "logs" / "decisions.jsonl"
    g = Gate(_policy(work), log_path=str(log))
    for _ in range(3):
        g.evaluate("s", "write_file", [str(work / "a.md")])
    _witness_only_deleted(g, log, work)
    assert len(_lines(log)) == 3


# Known gap. With the default anchor beside the log, whoever can write the log
# folder can also rewrite the witness and the anchor. These cases are caught
# only when the anchor lives outside the agent's writable tree, and neither
# hook sets such a location yet. Strict, so a fix turns them into failures that
# force the marker off.
_DEFAULT_ANCHOR_GAP = (
    "default anchor sits beside the log; an agent that can write the log "
    "folder can rewrite all three"
)


def _default_anchor_gate(tmp_path: Path):
    work = tmp_path / "work"
    work.mkdir()
    log = tmp_path / "logs" / "decisions.jsonl"
    g = Gate(_policy(work), log_path=str(log))
    for _ in range(4):
        g.evaluate("s", "write_file", [str(work / "a.md")])
    return g, work, log


@pytest.mark.xfail(strict=True, reason=_DEFAULT_ANCHOR_GAP)
def test_default_anchor_log_witness_and_anchor_rewritten(tmp_path) -> None:
    g, work, log = _default_anchor_gate(tmp_path)
    kept = _lines(log)[:2]
    log.write_text("".join(kept), encoding="utf-8")
    import hashlib

    head = hashlib.sha256(kept[-1].rstrip("\n").encode("utf-8")).hexdigest()
    for suffix in (".witness", ".anchor"):
        Path(str(log) + suffix).write_text(
            json.dumps({"count": 2, "head": head}) + "\n", encoding="utf-8"
        )
    _not_allowed(g, work / "a.md")


@pytest.mark.xfail(strict=True, reason=_DEFAULT_ANCHOR_GAP)
def test_default_anchor_log_folder_deleted(tmp_path) -> None:
    g, work, log = _default_anchor_gate(tmp_path)
    shutil.rmtree(log.parent)
    _not_allowed(g, work / "a.md")
