"""CISO decision record: real receipt accepts, missing or forged rejects.

The record is checked against the gate's own decision log. action_hash is a
plain sha256 anyone can recompute, so every forgery is also tried rehashed:
the log, not the hash, is what must reject it.
"""

from __future__ import annotations

import importlib.util
import json
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "hire_decision_record", ROOT / "demos" / "hire" / "decision_record.py"
)
dr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dr)
cg = dr.cg

FUTURE = 4_102_444_800.0  # 2100-01-01


@pytest.fixture
def bound(tmp_path):
    log, idx = dr.demo_log(tmp_path)
    rec = dr.build_record(
        "keep terminal denied", dr.make_receipt(log, idx), "lead@x.invalid", FUTURE
    )
    return log, idx, rec


def _rehash(rec: dict) -> dict:
    return {**rec, "action_hash": dr.action_hash(rec["decision"], rec["receipt"])}


def _forge(rec: dict, **kw) -> dict:
    return _rehash({**rec, "receipt": {**rec["receipt"], **kw}})


def test_real_record_accepts(bound):
    log, _, rec = bound
    assert dr.validate(rec, log) == []


def test_real_record_is_bound_to_the_deny_row(bound):
    _log, idx, rec = bound
    assert rec["receipt"]["verdict"] == "deny"
    assert rec["receipt"]["tool"] == "terminal"
    assert rec["receipt"]["row_index"] == idx


def test_demo_passes_every_case():
    res = dr.run_demo()
    assert res["all_ok"], res["cases"]
    assert {c["case"] for c in res["cases"]} >= {
        "real",
        "missing-receipt",
        "log-rewritten",
    }


def test_demo_cli_exit_zero(tmp_path, capsys):
    assert dr.main(["demo", "--out", str(tmp_path)]) == 0
    assert "decision record demo: PASS" in capsys.readouterr().out
    rec = json.loads((tmp_path / "decision-record.json").read_text())
    assert rec["schema"] == dr.SCHEMA


@pytest.mark.parametrize("key", [*dr.RECORD_KEYS, "action_hash"])
def test_missing_record_key_rejects(bound, key):
    log, _, rec = bound
    rec.pop(key)
    assert any(key in e for e in dr.validate(rec, log))


@pytest.mark.parametrize("key", dr.RECEIPT_KEYS)
def test_missing_receipt_key_rejects_even_rehashed(bound, key):
    log, _, rec = bound
    rc = dict(rec["receipt"])
    rc.pop(key)
    assert dr.validate(_rehash({**rec, "receipt": rc}), log)


FORGERIES = [
    ("verdict", "allow"),
    ("verdict", "ask"),
    ("verdict", "thrown"),
    ("verdict", None),
    ("tool", "read_file"),
    ("tool", "Terminal"),
    ("tool", ""),
    ("skill", "other-agent"),
    ("skill", ""),
    ("row_sha256", "0" * 64),
    ("row_sha256", "f" * 64),
    ("row_sha256", "A" * 64),
    ("row_sha256", "abc"),
    ("log_head", "0" * 64),
    ("log_head", "e" * 64),
    ("log_head", ""),
    ("row_index", 0),
    ("row_index", 5),
    ("row_index", -1),
    ("row_index", True),
    ("row_index", "1"),
    ("row_count", 0),
    ("row_count", 1),
    ("row_count", 99),
    ("row_count", -2),
    ("row_count", 2.0),
]


@pytest.mark.parametrize(
    ("field", "value"), FORGERIES, ids=[f"{f}={v!r}" for f, v in FORGERIES]
)
def test_forged_receipt_field_rejects_unhashed(bound, field, value):
    log, _, rec = bound
    rec = {**rec, "receipt": {**rec["receipt"], field: value}}
    assert dr.validate(rec, log)


@pytest.mark.parametrize(
    ("field", "value"), FORGERIES, ids=[f"{f}={v!r}" for f, v in FORGERIES]
)
def test_forged_receipt_field_rejects_rehashed(bound, field, value):
    log, _, rec = bound
    assert dr.validate(_forge(rec, **{field: value}), log)


def test_receipt_with_an_extra_key_rejects(bound):
    log, _, rec = bound
    assert dr.validate(_forge(rec, approved=True), log)


@pytest.mark.parametrize(
    "decision", ["allow terminal", "keep terminal denied ", "", "   ", None, 7]
)
def test_changed_decision_text_rejects(bound, decision):
    log, _, rec = bound
    assert dr.validate({**rec, "decision": decision}, log)


@pytest.mark.parametrize("approver", ["", "  ", None, 3, ["a"]])
def test_bad_approver_rejects(bound, approver):
    log, _, rec = bound
    assert dr.validate({**rec, "approver": approver}, log)


@pytest.mark.parametrize(
    "nonce", ["", "abc", "Z" * 32, "A" * 32, "0" * 31, "0" * 129, None, 12]
)
def test_bad_nonce_rejects(bound, nonce):
    log, _, rec = bound
    assert dr.validate({**rec, "nonce": nonce}, log)


@pytest.mark.parametrize("nonce", ["0" * 32, "a" * 64, "f" * 128])
def test_good_nonce_shapes_accept(bound, nonce):
    log, _, rec = bound
    assert dr.validate({**rec, "nonce": nonce}, log) == []


@pytest.mark.parametrize("na", [0, 1.0, -5, "2100", None, True, [1]])
def test_bad_or_past_not_after_rejects(bound, na):
    log, _, rec = bound
    assert dr.validate({**rec, "not_after": na}, log)


def test_not_after_boundary(bound):
    log, _, rec = bound
    now = time.time()
    assert dr.validate({**rec, "not_after": now}, log, now=now)
    assert dr.validate({**rec, "not_after": now + 1}, log, now=now) == []


@pytest.mark.parametrize("schema", ["cg.decision-record/v0", "", None, "v1"])
def test_wrong_schema_rejects(bound, schema):
    log, _, rec = bound
    assert dr.validate({**rec, "schema": schema}, log)


@pytest.mark.parametrize("rec", [None, [], "x", 3])
def test_non_object_record_rejects(tmp_path, rec):
    assert dr.validate(rec, tmp_path / "none.jsonl")


@pytest.mark.parametrize("receipt", [None, [], "x", 0])
def test_non_object_receipt_rejects(bound, receipt):
    log, _, rec = bound
    assert dr.validate({**rec, "receipt": receipt}, log)


# --- the log itself ----------------------------------------------------------


def _rewrite_row(log: Path, i: int, **kw) -> None:
    lines = log.read_text(encoding="utf-8").splitlines(keepends=True)
    row = json.loads(lines[i])
    row.update(kw)
    lines[i] = json.dumps(row, sort_keys=True) + "\n"
    log.write_text("".join(lines), encoding="utf-8")


@pytest.mark.parametrize("row", [0, 1])
@pytest.mark.parametrize(
    "edit", [{"verdict": "ask"}, {"reason": "edited"}, {"ts": 1.0}]
)
def test_rewritten_log_row_rejects(bound, row, edit):
    log, _, rec = bound
    _rewrite_row(log, row, **edit)
    assert dr.validate(rec, log)


def test_rewriting_an_unbound_row_still_rejects(tmp_path):
    # Bind to row 1 of a three-row log, then edit row 0 only: the bound row and
    # the receipted head are unchanged, so only the chain check can see it.
    log, idx = dr.demo_log(tmp_path)
    rec = dr.build_record("keep", dr.make_receipt(log, idx), "lead", FUTURE)
    _rewrite_row(log, 0, reason="edited")
    errs = dr.validate(rec, log)
    assert any("does not verify" in e for e in errs), errs


def test_truncated_log_rejects(bound):
    log, _, rec = bound
    lines = log.read_text(encoding="utf-8").splitlines(keepends=True)
    log.write_text("".join(lines[:-1]), encoding="utf-8")
    assert dr.validate(rec, log)


def test_deleted_log_rejects(bound):
    log, _, rec = bound
    log.unlink()
    assert dr.validate(rec, log)


def test_log_that_grew_after_the_record_still_accepts(bound, tmp_path):
    log, _, rec = bound
    gate = cg.Gate(dr._policy(tmp_path), str(log), mode=cg.ENFORCE)
    for _ in range(3):
        gate.evaluate(dr.SKILL, "read_file", [str(tmp_path / "work" / "a")])
    assert dr.validate(rec, log) == []


def test_record_bound_to_a_different_log_rejects(bound, tmp_path):
    _, _, rec = bound
    other = tmp_path / "other"
    other_log, _ = dr.demo_log(other)
    assert dr.validate(rec, other_log)


def test_make_receipt_refuses_a_broken_log(bound):
    log, idx, _ = bound
    _rewrite_row(log, 0, reason="edited")
    with pytest.raises(ValueError):
        dr.make_receipt(log, idx)


@pytest.mark.parametrize("idx", [-1, 2, 50])
def test_make_receipt_refuses_an_out_of_range_row(bound, idx):
    log, _, _ = bound
    with pytest.raises(ValueError):
        dr.make_receipt(log, idx)


# --- CLI check ---------------------------------------------------------------


def test_cli_check_accepts_real_and_rejects_forged(bound, tmp_path, capsys):
    log, _, rec = bound
    p = tmp_path / "rec.json"
    p.write_text(json.dumps(rec))
    assert dr.main(["check", str(p), str(log)]) == 0
    assert capsys.readouterr().out.startswith("ACCEPT")
    p.write_text(json.dumps(_forge(rec, verdict="allow")))
    assert dr.main(["check", str(p), str(log)]) == 1
    assert capsys.readouterr().out.startswith("REJECT")


def test_cli_check_unreadable_record_is_reject(tmp_path, capsys):
    p = tmp_path / "rec.json"
    p.write_text("{not json")
    assert dr.main(["check", str(p), str(tmp_path / "x.jsonl")]) == 1
    assert "REJECT" in capsys.readouterr().out


# --- fail when removed (in process) ------------------------------------------


def test_removing_the_row_hash_check_lets_a_forgery_through(bound, monkeypatch):
    log, _, rec = bound
    forged = _forge(rec, row_sha256="0" * 64)
    assert dr.validate(forged, log)
    real_hash = cg._hash_log_line
    monkeypatch.setattr(
        cg,
        "_hash_log_line",
        lambda line: "0" * 64 if '"terminal"' in line else real_hash(line),
    )
    # With the row hash forced to match, only the chain still objects.
    assert dr.validate(forged, log)


def test_removing_the_chain_check_lets_an_unbound_rewrite_through(
    tmp_path, monkeypatch
):
    log, idx = dr.demo_log(tmp_path)
    rec = dr.build_record("keep", dr.make_receipt(log, idx), "lead", FUTURE)
    _rewrite_row(log, 0, reason="edited")
    assert dr.validate(rec, log)
    monkeypatch.setattr(cg, "verify_hash_chain", lambda *a, **k: "0" * 64)
    assert dr.validate(rec, log) == []


def test_record_is_not_read_by_gate_evaluate():
    # The record is after-the-fact evidence; the runtime gate never consumes it.
    src = (ROOT / "capability_gate.py").read_text(encoding="utf-8")
    assert "decision_record" not in src
    assert "decision-record" not in src
