"""The demo scenarios as test assertions.

Each scenario's expect: block must hold at its own seed and at a changed seed,
two runs must give identical counts, and removing the control a scenario
targets must turn it red (one mutation check per scenario).
"""

from __future__ import annotations

import importlib
import importlib.util
import json
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


# --- S11: alert triage replay -------------------------------------------------
# Dedup, rank and never-auto-close are local rules. A live model is not in
# this path; reasons come from the recorded fixture.


S11 = "S11-alert-triage-burst"


def _s11_res(runner_override=None, **kwargs):
    return st.run_scenario(_scn(S11), runner_override=runner_override, **kwargs)


def test_s11_expected_group_count_follows_the_burst():
    scn = _scn(S11)
    base = st.run_scenario(scn)
    assert "error" not in base["detail"]
    moved = dict(scn)
    moved["fault"] = {**scn["fault"], "duplicate_families": 10, "copies_per_family": 10}
    # 500 - 1 TP - 10*10 copies = 399 unique noise; groups = 1+10+399 = 410
    res = st.run_scenario(moved)
    assert "error" not in res["detail"]
    assert res["status"] == "PASS", _failed(res)
    assert res["expected"]["duplicates_grouped"] == 90
    assert res["actual"]["duplicates_grouped"] == 90
    assert res["actual"]["unique_groups"] == 410
    assert base["actual"]["unique_groups"] == 220


def test_s11_replay_receipt_has_no_cost_figures():
    res = _s11_res()
    assert "error" not in res["detail"]
    assert res["actual"]["replay"] == 1
    usage = res["detail"]["token_usage"]
    assert usage == {"cached": 0, "input": 0, "output": 0} or usage == {
        "input": 0,
        "output": 0,
        "cached": 0,
    }
    blob = json.dumps(res["detail"]).lower()
    assert "cost" not in blob
    assert "$" not in blob


def test_mutation_s11_no_dedup_goes_red(monkeypatch):
    monkeypatch.setattr(st, "group_alerts", lambda alerts: [[a] for a in alerts])
    res = _s11_res()
    assert "error" not in res["detail"]
    assert res["status"] == "FAIL"
    assert res["actual"]["unique_groups"] == res["actual"]["alerts"]
    assert res["actual"]["duplicates_grouped"] == 0


def test_mutation_s11_ranking_flattened_goes_red(monkeypatch):
    monkeypatch.setattr(st, "severity_score", lambda group: 0)
    res = _s11_res()
    assert "error" not in res["detail"]
    assert res["status"] == "FAIL"
    assert res["actual"]["true_positive_in_top_3"] == 0


def test_mutation_s11_auto_closes_noise_goes_red(monkeypatch):
    monkeypatch.setattr(
        st, "recommend_close", lambda group: group.get("class") == "noise"
    )
    res = _s11_res()
    assert "error" not in res["detail"]
    assert res["status"] == "FAIL"
    assert res["actual"]["auto_closed"] > 0
    assert res["actual"]["close_recommended"] > 0


def test_s11_live_mode_is_exit_2(tmp_path, capsys):
    p = tmp_path / "S11-live.yaml"
    text = (HERE / "scenarios" / f"{S11}.yaml").read_text(encoding="utf-8")
    p.write_text(text.replace("mode: replay\n", "mode: live\n", 1), encoding="utf-8")
    assert st.main(["run", str(p), "--out", str(tmp_path / "out")]) == 2
    err = capsys.readouterr().err.lower()
    assert "traceback" not in err
    assert "replay" in err


def test_s11_inconsistent_burst_is_exit_2(tmp_path, capsys):
    p = tmp_path / "S11-bad.yaml"
    text = (HERE / "scenarios" / f"{S11}.yaml").read_text(encoding="utf-8")
    p.write_text(
        text.replace("alerts: 500\n", "alerts: 10\n", 1), encoding="utf-8"
    )
    assert st.main(["run", str(p), "--out", str(tmp_path / "out")]) == 2
    err = capsys.readouterr().err.lower()
    assert "traceback" not in err
    assert "alerts" in err


def test_s11_malformed_yaml_is_exit_2(tmp_path, capsys):
    p = tmp_path / "S11-broken.yaml"
    p.write_text("name: [\n", encoding="utf-8")
    assert st.main(["run", str(p), "--out", str(tmp_path / "out")]) == 2
    err = capsys.readouterr().err.lower()
    assert "traceback" not in err


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


# --- S14: isolate route mutations (M1 to M8) ---------------------------------
# Each mutation is applied to the plugin copy the scenario installs, never to
# the repo files, and must flip the scenario to FAIL on the count it names.

S14 = "S14-isolate-route"

S14_MUTATIONS = {
    # M1 the decider has no isolate branch: the tool is allowed and runs on the host.
    "M1-isolate-branch-removed": (
        {
            "capability_gate.py": [
                ("    if tool in policy.isolate:\n", "    if False:\n")
            ]
        },
        "host_executed_isolate",
    ),
    # M2 the plugin hands an isolate call back to the host.
    "M2-adapter-passes-through": (
        {
            "__init__.py": [
                (
                    "                router = _isolate_route()\n",
                    "                return None\n                router = _isolate_route()\n",
                ),
            ]
        },
        "host_executed_isolate",
    ),
    # M3 the route call is dropped: the call is blocked but never reaches the box.
    "M3-route-call-dropped": (
        {
            "__init__.py": [
                (
                    "                    outcome = router.route_isolate(\n",
                    (
                        "                    outcome = (\n"
                        '                        router.Outcome("isolate route dropped", decision.route_ticket)\n'
                        "                        if True\n"
                        "                        else router.route_isolate(\n"
                    ),
                ),
                (
                    "                        halted=gate._halt_state,\n                    )\n",
                    "                        halted=gate._halt_state,\n                    ))\n",
                ),
            ]
        },
        "routed",
    ),
    # M4 the receipt binding check always passes: a replayed receipt advances.
    "M4-receipt-check-passes": (
        {
            "adapters/isolate_route.py": [
                (
                    "        if receipt.get(key) != task.get(key):\n",
                    "        if False:\n",
                ),
                (
                    '    if receipt.get("task_sha256") != task_sha256(task):\n',
                    "    if False:\n",
                ),
            ]
        },
        "replay_refused",
    ),
    # M5 the ticket store forgets: a ticket is accepted twice.
    "M5-ticket-store-forgets": (
        {
            "adapters/isolate_route.py": [
                (
                    "            if ticket in seen:\n                return False\n",
                    "            if ticket in seen:\n                return True\n",
                ),
            ]
        },
        "reuse_refused",
    ),
    # M6 a route error is mapped to allow: a door that is down lets the host run the call.
    "M6-route-error-allows": (
        {
            "__init__.py": [
                (
                    "                    message = outcome.message\n",
                    (
                        "                    message = outcome.message\n"
                        '                    if message.startswith("isolate route unavailable"):\n'
                        "                        return None\n"
                    ),
                ),
            ]
        },
        "door_down_blocked",
    ),
    # M7 is the lax vestibule door, below: it needs a rebuilt door, not a plugin patch.
    # M8 no kill switch check after the door: a result after the throw is delivered.
    "M8-halt-recheck-removed": (
        {
            "adapters/isolate_route.py": [
                (
                    "        stop = halted() if halted is not None else None\n",
                    "        stop = None\n",
                ),
                (
                    "        stop = halted() if halted is not None else None\n",
                    "        stop = None\n",
                ),
            ]
        },
        "kill_discarded",
    ),
    # M9 the disposition is ignored: held, dropped and rejected results all advance.
    "M9-disposition-ignored": (
        {
            "adapters/isolate_route.py": [
                ('    if disposition == "advance":\n', "    if True:\n")
            ]
        },
        "held",
    ),
}


@pytest.mark.parametrize("mid", sorted(S14_MUTATIONS))
def test_mutation_s14_goes_red(mid):
    patches, key = S14_MUTATIONS[mid]
    res = st.run_scenario(
        _scn(S14),
        runner_override=lambda s, sb, seed: st.s_isolate(s, sb, seed, patches=patches),
    )
    assert res["status"] == "FAIL", mid
    assert "error" not in res["detail"], res["detail"]
    assert res["actual"][key] != res["expected"][key], (mid, key, res["actual"])


def test_mutation_s14_m7_lax_vestibule_door_goes_red(tmp_path):
    # M7: the door built from a copy of the sandbox-demo crate whose route
    # parses the guest frame with the vestibule disabled. The checkout is untouched.
    try:
        iso = st.isolation_layer_root()
    except RuntimeError as exc:
        pytest.fail(str(exc))
    crate = tmp_path / "sandbox-demo"
    shutil.copytree(
        iso / "demos" / "sandbox-demo", crate, ignore=shutil.ignore_patterns("target")
    )
    toml = crate / "Cargo.toml"
    text = toml.read_text(encoding="utf-8").replace(
        'path = "../../crates/', f'path = "{iso}/crates/'
    )
    toml.write_text(text, encoding="utf-8")
    route = crate / "src" / "route.rs"
    src = route.read_text(encoding="utf-8")
    # The rustfmt form of the vestibule mode line, over five lines.
    old = (
        "let mode = if m.vestibule_disabled {\n"
        "        ParseMode::Disabled\n"
        "    } else {\n"
        "        ParseMode::Enforce\n"
        "    };"
    )
    assert src.count(old) == 1, "route.rs vestibule mode line not found"
    route.write_text(
        src.replace(old, "let mode = ParseMode::Disabled;", 1), encoding="utf-8"
    )
    door = st.build_door(crate, target=st.ROOT / ".tmp" / "door-target-m7")
    res = st.run_scenario(
        _scn(S14),
        runner_override=lambda s, sb, seed: st.s_isolate(s, sb, seed, door=door),
    )
    assert res["status"] == "FAIL"
    assert res["actual"]["vestibule_rejected"] < res["expected"]["vestibule_rejected"]


def test_s14_rows_are_marked_stubbed():
    res = st.run_scenario(_scn(S14))
    assert res["real"] is False
    assert "| STUBBED |" in st.table([res])
    assert res["actual"]["door_receipts_real"] == 0


def test_s14_without_a_door_is_a_fail_row(monkeypatch, tmp_path):
    monkeypatch.delenv("CG_ISOLATE_DOOR", raising=False)
    monkeypatch.setenv("ISOLATION_LAYER_ROOT", str(tmp_path / "absent"))
    res = st.run_scenario(_scn(S14))
    assert res["status"] == "FAIL"
    assert "isolation-layer stub door" in res["detail"]["error"]


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
