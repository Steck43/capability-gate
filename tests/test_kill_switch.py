"""Kill switch: one marker file, and every call after it is denied.

Throwing the switch creates a marker beside the decision log and appends one
THROWN row to the hash chain. ``Gate.evaluate`` reads the marker on every call,
before the policy, so a gate that was already running denies the next call
with no restart. Only a human removing the marker clears it.

Each test carries the case id it pins. Two limits are pinned as well, not
hidden: observe mode logs the deny and blocks nothing (strict xfail), and a
pass here is the gate alone. It says nothing about whether a live hook calls it.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOF = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOF))

from capability_gate import (  # noqa: E402
    OBSERVE,
    Gate,
    Verdict,
    load_policy,
    verify_hash_chain,
)


def _policy(root: Path):
    return load_policy(
        {
            "skills": {
                "writer": {
                    "tools": ["read_file", "write_file"],
                    "paths": [str(root) + "/**"],
                }
            }
        }
    )


def _rows(log: Path) -> list[dict]:
    return [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines() if x]


def _thrown_rows(log: Path) -> list[dict]:
    return [r for r in _rows(log) if r.get("verdict") == "thrown"]


@pytest.fixture()
def root(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    return tmp_path


@pytest.fixture()
def log(root):
    return root / "decisions.jsonl"


@pytest.fixture()
def gate(root, log):
    return Gate(_policy(root), log_path=str(log))


def _granted(root: Path) -> str:
    return str(root / "work" / "note.md")


def test_ks_off_no_grant_denies(gate, root):
    # KS-OFF-NO-GRANT: an untouched switch must not turn into an allow path.
    d = gate.evaluate("writer", "terminal", [_granted(root)])
    assert d.verdict is Verdict.DENY
    assert "not granted" in d.reason
    d = gate.evaluate("stranger", "read_file", [_granted(root)])
    assert d.verdict is Verdict.DENY


def test_ks_off_grant_allows(gate, root):
    # KS-OFF-GRANT: an untouched switch adds nothing to a granted call.
    d = gate.evaluate("writer", "write_file", [_granted(root)])
    assert d.verdict is Verdict.ALLOW


def test_ks_on_denies_granted_call(gate, root, log):
    # KS-ON: after the throw, the same granted call is denied and says why.
    assert gate.halt_path == str(log.resolve()) + ".halt"
    assert gate.throw("drill") is True
    assert os.path.exists(gate.halt_path)
    d = gate.evaluate("writer", "write_file", [_granted(root)])
    assert d.verdict is Verdict.DENY
    assert "kill switch" in d.reason
    assert d.enforced is True


def test_ks_no_cache_running_gate_denies_next_call(root, log):
    # KS-NO-CACHE: the gate was built and used before the throw. The throw
    # comes from a second Gate on the same log, standing in for an operator
    # process. The first gate is not rebuilt.
    running = Gate(_policy(root), log_path=str(log))
    assert running.evaluate("writer", "write_file", [_granted(root)]).verdict is (
        Verdict.ALLOW
    )
    operator = Gate(load_policy({"skills": {}}), log_path=str(log))
    assert operator.throw("operator drill") is True
    d = running.evaluate("writer", "write_file", [_granted(root)])
    assert d.verdict is Verdict.DENY
    assert "kill switch" in d.reason


def test_ks_state_error_fails_closed(root, log, monkeypatch):
    # KS-STATE-ERROR: any marker read error other than FileNotFoundError is a
    # deny. (On POSIX a file-as-parent raises NotADirectoryError; Windows often
    # raises FileNotFoundError for the same layout, so the pin is a raised
    # OSError that is not "not found".)
    g = Gate(_policy(root), log_path=str(log))

    def boom(_path):
        raise OSError("simulated marker state error")

    monkeypatch.setattr(os, "lstat", boom)
    d = g.evaluate("writer", "write_file", [_granted(root)])
    assert d.verdict is Verdict.DENY
    assert "kill switch" in d.reason
    assert "unreadable" in d.reason


def test_ks_log_one_thrown_row_chain_holds_denies_logged(gate, root, log):
    # KS-LOG: one THROWN row on the existing chain, and the denies after it
    # are logged like any other deny.
    gate.evaluate("writer", "write_file", [_granted(root)])
    assert _thrown_rows(log) == []
    gate.throw("drill")
    thrown = _thrown_rows(log)
    assert len(thrown) == 1
    assert "kill switch" in thrown[0]["reason"]
    assert thrown[0]["paths"] == [gate.halt_path]
    gate.evaluate("writer", "write_file", [_granted(root)])
    gate.evaluate("writer", "read_file", [_granted(root)])
    verify_hash_chain(str(log))
    after = _rows(log)[-2:]
    assert [r["verdict"] for r in after] == ["deny", "deny"]
    assert all("kill switch" in r["reason"] for r in after)


def test_ks_double_throw_one_row(gate, log):
    # KS-DOUBLE-THROW: a second throw is a no-op. Still one row, still thrown.
    assert gate.throw("first") is True
    assert gate.throw("second") is False
    assert len(_thrown_rows(log)) == 1
    assert os.path.exists(gate.halt_path)
    verify_hash_chain(str(log))


def test_ks_tamper_thrown_row_breaks_chain(gate, root, log):
    # KS-TAMPER: rewrite the THROWN row without rehashing. A deny follows it,
    # so its parent link no longer matches and the chain check raises. An
    # edit to the very last line is not caught by the chain; that limit is
    # older than this switch.
    gate.throw("drill")
    gate.evaluate("writer", "write_file", [_granted(root)])
    lines = log.read_text(encoding="utf-8").splitlines(keepends=True)
    idx = next(i for i, x in enumerate(lines) if '"thrown"' in x)
    rec = json.loads(lines[idx])
    rec["reason"] = "nothing happened here"
    lines[idx] = json.dumps(rec, sort_keys=True) + "\n"
    log.write_text("".join(lines), encoding="utf-8")
    with pytest.raises(ValueError, match="hash chain"):
        verify_hash_chain(str(log))


def test_ks_self_clear_marker_path_denied(gate, root, log):
    # KS-SELF-CLEAR: the marker is inside the write grant on purpose. A
    # call naming it is denied with the switch off, by absolute path, by a
    # relative path, and through a symlink. With the switch on it is denied
    # and the marker is still there afterward.
    marker = gate.halt_path
    d = gate.evaluate("writer", "write_file", [marker])
    assert d.verdict is Verdict.DENY
    assert "kill switch marker" in d.reason
    d = gate.evaluate(
        "writer", "write_file", [os.path.basename(marker)], base_dir=str(root)
    )
    assert d.verdict is Verdict.DENY
    link = root / "work" / "innocent.md"
    link.symlink_to(marker)
    d = gate.evaluate("writer", "write_file", [str(link)])
    assert d.verdict is Verdict.DENY
    gate.throw("drill")
    d = gate.evaluate("writer", "write_file", [marker])
    assert d.verdict is Verdict.DENY
    assert os.path.exists(marker)


def test_ks_paths_materialized_once_generator(gate, root):
    # R4-1: a one-shot paths iterable must not be drained before the policy
    # check. Off-grant path stays a deny (never an empty-paths allow).
    paths = (p for p in ["/etc/passwd"])
    d = gate.evaluate("writer", "write_file", paths)
    assert d.verdict is Verdict.DENY
    assert "outside allowlist" in d.reason or "passwd" in d.reason
    assert d.paths == ("/etc/passwd",)


def test_ks_path_materialization_error_fails_closed_and_logs(gate, log):
    # T-FAIL-05: coercing an adversarial path must stay inside the recorded
    # fail-closed boundary.
    class UnstringablePath:
        def __str__(self):
            raise ValueError("path refused string conversion")

    d = gate.evaluate("writer", "write_file", [UnstringablePath()])
    assert d.verdict is Verdict.DENY
    assert "gate error, failing closed" in d.reason
    assert "path refused string conversion" in d.reason
    rows = _rows(log)
    assert rows[-1]["verdict"] == "deny"
    assert rows[-1]["paths"] == []


def test_ks_eacces_marker_fails_closed(root, log, monkeypatch):
    # R5-2 / M03: PermissionError on lstat is a deny, not "not thrown".
    g = Gate(_policy(root), log_path=str(log))

    def boom(_path):
        raise PermissionError("marker locked")

    monkeypatch.setattr(os, "lstat", boom)
    d = g.evaluate("writer", "write_file", [_granted(root)])
    assert d.verdict is Verdict.DENY
    assert "unreadable" in d.reason


def test_ks_dangling_symlink_marker_fails_closed(root, log):
    # R5-2 / M04: lstat sees a dangling symlink as present; that is a deny.
    marker = Path(str(log) + ".halt")
    marker.symlink_to(root / "missing-target")
    g = Gate(_policy(root), log_path=str(log))
    d = g.evaluate("writer", "write_file", [_granted(root)])
    assert d.verdict is Verdict.DENY
    assert "kill switch" in d.reason


def test_ks_halt_checked_in_observe(root, log):
    # R5-2 / M12: observe still runs the halt check (verdict deny, logged).
    # Blocking is a separate limit pinned by the strict xfail below.
    g = Gate(_policy(root), log_path=str(log), mode=OBSERVE)
    g.throw("drill")
    d = g.evaluate("writer", "write_file", [_granted(root)])
    assert d.verdict is Verdict.DENY
    assert "kill switch" in d.reason
    assert d.enforced is False
    assert "kill switch" in _rows(log)[-1]["reason"]


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "LIMIT: observe mode logs the kill switch deny with enforced false and "
        "blocks nothing. The switch does not override observe."
    ),
)
def test_kill_switch_blocks_in_observe(root, log):
    # KS-OBSERVE: pins the honest limit. The deny is decided and logged; the
    # last assert is the one that fails, because observe does not block.
    g = Gate(_policy(root), log_path=str(log), mode=OBSERVE)
    g.throw("drill")
    d = g.evaluate("writer", "write_file", [_granted(root)])
    assert d.verdict is Verdict.DENY
    assert "kill switch" in _rows(log)[-1]["reason"]
    assert d.enforced is True
