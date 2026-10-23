"""The demo scenarios as test assertions.

Each scenario's expect: block must hold at its own seed and at a changed seed,
two runs must give identical counts, and removing the control a scenario
targets must turn it red (one mutation check per scenario).
"""

from __future__ import annotations

import importlib
import shutil
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

# Imported by name after the path insert above, so the module-level imports stay at the top.
st = importlib.import_module("synthtraffic")
cg = st.cg

FILES = sorted((HERE / "scenarios").glob("*.yaml"))
IDS = [f.stem for f in FILES]


def _scn(stem: str) -> dict:
    return st.load_scenario(HERE / "scenarios" / f"{stem}.yaml")


def _failed(res: dict) -> list[str]:
    return [c["assert"] for c in res["checks"] if not c["ok"]]


@pytest.mark.parametrize("path", FILES, ids=IDS)
def test_scenario_expect_holds(path):
    res = st.run_scenario(st.load_scenario(path))
    assert res["status"] == "PASS", _failed(res)


@pytest.mark.parametrize("path", FILES, ids=IDS)
def test_scenario_holds_under_changed_seed(path):
    scn = st.load_scenario(path)
    res = st.run_scenario(scn, seed=int(scn["seed"]) + 1000)
    assert res["status"] == "PASS", _failed(res)


@pytest.mark.parametrize("path", FILES, ids=IDS)
def test_scenario_is_deterministic(path):
    scn = st.load_scenario(path)
    a, b = st.run_scenario(scn), st.run_scenario(scn)
    assert a["actual"] == b["actual"]
    assert a["detail"]["events_sha256"] == b["detail"]["events_sha256"]


def test_changed_seed_changes_events():
    scn = _scn("S02-gate-deny-risky-command")
    a = st.run_scenario(scn)
    b = st.run_scenario(scn, seed=int(scn["seed"]) + 1000)
    assert a["detail"]["events_sha256"] != b["detail"]["events_sha256"]


# --- mutation checks: remove the control, the scenario goes red ---------------


def _wide_policy(sb):
    return cg.load_policy(
        {
            "skills": {
                st.SKILL: {
                    "tools": [
                        "read_file",
                        "list_dir",
                        "run_tests",
                        "write_file",
                        "deploy",
                        "terminal",
                        "send_email",
                    ],
                    "paths": ["/**"],
                }
            }
        }
    )


def test_mutation_s01_no_grants_goes_red(monkeypatch):
    monkeypatch.setattr(st, "demo_policy", lambda sb: cg.load_policy({"skills": {}}))
    assert st.run_scenario(_scn("S01-baseline-benign"))["status"] == "FAIL"


def test_mutation_s02_shell_granted_goes_red(monkeypatch):
    monkeypatch.setattr(st, "demo_policy", _wide_policy)
    res = st.run_scenario(_scn("S02-gate-deny-risky-command"))
    assert res["status"] == "FAIL"
    assert res["actual"]["risky_executed"] > 0


def test_mutation_s03_no_approval_list_goes_red(monkeypatch):
    real = st.demo_policy

    def no_ask(sb):
        p = real(sb)
        return cg.Policy(skills=p.skills, require_approval=frozenset())

    monkeypatch.setattr(st, "demo_policy", no_ask)
    res = st.run_scenario(_scn("S03-policy-allow-deny-ask"))
    assert res["status"] == "FAIL"
    assert res["actual"]["ask"] == 0


def test_mutation_s04_kill_switch_ignored_goes_red(monkeypatch):
    monkeypatch.setattr(cg.Gate, "_halt_state", lambda self: None)
    res = st.run_scenario(_scn("S04-kill-switch-mid-run"))
    assert res["status"] == "FAIL"
    assert res["actual"]["executed_after_kill"] > 0


def test_mutation_s08_chain_check_skipped_goes_red(monkeypatch):
    monkeypatch.setattr(cg, "_verify_log", lambda *a, **k: (cg._GENESIS, 0))
    res = st.run_scenario(_scn("S08-receipt-chain-tamper"))
    assert res["status"] == "FAIL"


def test_mutation_s09_hook_fails_open_goes_red(tmp_path):
    # A copy of the hook whose deny path exits 0 (Claude Code reads that as
    # "no objection"), beside a link to the real gate. The repo file is untouched.
    (tmp_path / "adapters").mkdir()
    src = (st.ROOT / "adapters" / "claude_code_hook.py").read_text(encoding="utf-8")
    mutated = src.replace("        os._exit(2)\n", "        os._exit(0)\n", 1)
    assert mutated != src
    hook = tmp_path / "adapters" / "claude_code_hook.py"
    hook.write_text(mutated, encoding="utf-8")
    shutil.copy2(st.ROOT / "capability_gate.py", tmp_path / "capability_gate.py")
    scn = _scn("S09-gate-outage")
    res = st.run_scenario(
        scn, runner_override=lambda s, sb, seed: st.s_outage(s, sb, seed, hook=hook)
    )
    assert res["status"] == "FAIL"
    assert res["actual"]["executed_during_outage"] > 0


def test_mutation_s12_enforce_run_in_observe_goes_red(monkeypatch):
    real = st.run_policy_traffic

    def both_observe(scn, sb, seed, mode=cg.ENFORCE, tag="run"):
        return real(scn, sb, seed, mode=cg.OBSERVE, tag=tag)

    monkeypatch.setattr(st, "run_policy_traffic", both_observe)
    res = st.run_scenario(_scn("S12-shadow-vs-enforce"))
    assert res["status"] == "FAIL"
    assert res["actual"]["enforce_risky_executed"] > 0
