"""The demo scenarios as test assertions.

Each scenario's expect: block must hold at its own seed and at a changed seed,
two runs must give identical counts, and removing the control a scenario
targets must turn it red (one mutation check per scenario).
"""

from __future__ import annotations

import importlib
import importlib.util
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


# --- assertion strength: each count needs the right cause --------------------


def test_s02_wrong_rule_for_a_risky_kind_goes_red(monkeypatch):
    # Every risky call is still denied, but the grant deny is reported as a
    # path rule: the rule id count must not accept that.
    real = st.rule_id

    def relabel(reason):
        rid = real(reason)
        return "path-outside-allowlist" if rid == "tool-not-granted" else rid

    monkeypatch.setattr(st, "rule_id", relabel)
    res = st.run_scenario(_scn("S02-gate-deny-risky-command"))
    assert res["status"] == "FAIL"
    assert res["actual"]["risky_denied"] == res["expected"]["risky_denied"]
    assert res["actual"]["risky_with_rule_id"] < res["expected"]["risky_with_rule_id"]


def test_s02_fail_closed_deny_does_not_count_as_the_rule(monkeypatch):
    monkeypatch.setattr(st, "rule_id", lambda reason: "fail-closed")
    res = st.run_scenario(_scn("S02-gate-deny-risky-command"))
    assert res["status"] == "FAIL"
    assert res["actual"]["risky_with_rule_id"] == 0


def _broken_chain(*a, **k):
    raise RuntimeError("synthetic: audit log hash chain broken")


@pytest.mark.parametrize(
    "stem",
    ["S01-baseline-benign", "S04-kill-switch-mid-run", "S08-receipt-chain-tamper"],
)
def test_broken_chain_is_a_fail_row_not_a_traceback(monkeypatch, stem):
    monkeypatch.setattr(cg, "verify_hash_chain", _broken_chain)
    res = st.run_scenario(_scn(stem))
    assert res["status"] == "FAIL"
    if "chain_ok" in res["actual"]:
        assert res["actual"]["chain_ok"] == 0


def test_a_runner_that_raises_is_a_fail_row():
    def boom(scn, sb, seed):
        raise RuntimeError("synthetic control error")

    res = st.run_scenario(_scn("S01-baseline-benign"), runner_override=boom)
    assert res["status"] == "FAIL"
    assert "synthetic control error" in res["detail"]["error"]


def test_s09_expected_outage_count_follows_the_windows():
    scn = _scn("S09-gate-outage")
    base = st.run_scenario(scn)
    moved = dict(scn)
    moved["fault"] = {
        "outages": [
            {**w, "end": w["end"] + 2} if w["kind"] == "log_store_down" else w
            for w in scn["fault"]["outages"]
        ]
    }
    res = st.run_scenario(moved)
    assert res["status"] == "PASS", _failed(res)
    grew = (
        res["expected"]["calls_during_outage"] - base["expected"]["calls_during_outage"]
    )
    assert grew == 2
    assert (
        res["actual"]["blocked_during_outage"] == res["expected"]["calls_during_outage"]
    )


# --- README Proof check ------------------------------------------------------


_spec = importlib.util.spec_from_file_location(
    "readme_proof", HERE.parent / "scripts" / "readme_proof.py"
)
rp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rp)


def _summary(tmp_path):
    out = tmp_path / "out"
    assert st.main(["run", str(HERE / "scenarios"), "--out", str(out)]) == 0
    return out / "summary.json"


def test_readme_proof_check_goes_red_on_a_changed_number(tmp_path, capsys):
    summary = _summary(tmp_path)
    readme = tmp_path / "README.md"
    readme.write_text(f"# x\n\n{rp.START}\n{rp.END}\n", encoding="utf-8")
    assert rp.main(["write", "--readme", str(readme), "--summary", str(summary)]) == 0
    assert rp.main(["check", "--readme", str(readme), "--summary", str(summary)]) == 0
    text = readme.read_text(encoding="utf-8")
    readme.write_text(text.replace("events=200", "events=201", 1), encoding="utf-8")
    assert rp.main(["check", "--readme", str(readme), "--summary", str(summary)]) == 1
    assert "numbers: 201 != 200" in capsys.readouterr().out


def test_an_empty_expect_block_is_refused(tmp_path):
    p = tmp_path / "S99-empty.yaml"
    p.write_text(
        "name: S99-empty\ncontrol: none\nrunner: policy\nseed: 1\n"
        "actor: {agent_id: a, user_id: u}\ntraffic: {benign: 1}\nexpect: {}\n"
    )
    with pytest.raises(ValueError, match="expect must name"):
        st.load_scenario(p)


def test_zero_scenarios_is_exit_2(tmp_path):
    assert st.main(["run", str(tmp_path), "--out", str(tmp_path / "out")]) == 2
