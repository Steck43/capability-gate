import importlib
import sys
from pathlib import Path

import pytest

# The builds live one folder up. Imported by name after the path is set, mutant first.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
importlib.import_module("_mutants").apply()
training_tuesday = importlib.import_module("training_tuesday")
adversary_scoreboard = importlib.import_module("adversary_scoreboard")
token_ledger = importlib.import_module("token_ledger")
mcp_refuse_wrapper = importlib.import_module("mcp_refuse_wrapper")
sem = importlib.import_module("shadow_enforce_meter")
_cg = importlib.import_module("_cg")
sdk, make_client, SKILL = _cg.sdk, _cg.make_client, _cg.SKILL


def test_training_tuesday_grade_a():
    assert training_tuesday.main() == 0


def test_adversary_scoreboard_all_hold():
    assert adversary_scoreboard.main() == 0


def test_token_ledger_demo():
    assert token_ledger.demo() == 0


def test_mcp_refuse_before_model():
    assert mcp_refuse_wrapper.demo() == 0


def _ledger(tmp_path):
    c, _root, work = make_client(root=tmp_path)
    ok = c.check(SKILL, "read_file", [f"{work}/a"])
    led = token_ledger.Ledger(str(tmp_path / "l.jsonl"), {"a": 10}, sdk.may_run)
    return led, ok


def test_ledger_edit_detected(tmp_path):
    led, ok = _ledger(tmp_path)
    led.spend("a", 3, "r1", ok)
    led.spend("a", 2, "r2", ok)
    p = tmp_path / "l.jsonl"
    p.write_text(p.read_text().replace('"amount": 3', '"amount": 1', 1))
    with pytest.raises(token_ledger.Refused):
        led.verify()


def test_ledger_replay_keeps_caps(tmp_path):
    led, ok = _ledger(tmp_path)
    led.spend("a", 9, "r1", ok)
    again = token_ledger.Ledger(str(tmp_path / "l.jsonl"), {"a": 10}, sdk.may_run)
    with pytest.raises(token_ledger.Refused):
        again.spend("a", 2, "r2", ok)
    with pytest.raises(token_ledger.Refused):
        again.spend("a", 1, "r1", ok)  # ref reuse after restart


def test_ledger_write_failure_refuses(tmp_path):
    led, ok = _ledger(tmp_path)
    led._path = str(tmp_path / "missing-dir" / "l.jsonl")
    with pytest.raises(token_ledger.Refused):
        led.spend("a", 1, "r1", ok)
    assert led.spent("a") == 0


@pytest.mark.parametrize("amt", [0, -1, True, 1.5, "1"])
def test_ledger_bad_amounts(tmp_path, amt):
    led, ok = _ledger(tmp_path)
    with pytest.raises(token_ledger.Refused):
        led.spend("a", amt, "r", ok)


def test_meter_pass_and_schema_valid():
    assert sem.main([]) == 0


def test_meter_never_self_promotes():
    doc = sem.run_window()
    assert doc["promotion"]["decision"] == "stay_shadow"
    assert doc["promotion"]["approver"] == "pending-human-review"


def test_meter_schema_rejects_extra_field():
    jsonschema = importlib.import_module("jsonschema")
    doc = sem.run_window()
    doc["shadow"]["sneaky"] = 1
    with pytest.raises(jsonschema.ValidationError):
        sem.validate(doc)
