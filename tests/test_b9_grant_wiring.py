"""B9 grants wired into Gate.evaluate: wiring-spec pins W1 to W14 plus the
D1, D4, D5 and D7 acceptance rows (M1-A*, M4-A*, M5-A*, M7-A*).

Every test uses temp folders and harmless marker files. No network.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import capability_gate as cg
import capability_gate_grants as gr
from capability_gate import Gate, Verdict, load_policy
from capability_gate_sdk import Client, may_run

KEY = b"k" * 32
OTHER_KEY = b"o" * 32
SESSION = "session-key-agent-one-0001"
SESSION2 = "session-key-agent-two-0002"
HUMAN = "human:landen"


class Clock:
    def __init__(self, t: float = 1_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def env(tmp_path):
    work = tmp_path / "work"
    (work / "a").mkdir(parents=True)
    (work / "b").mkdir(parents=True)
    for rel in ("a/x.txt", "a/y.txt", "b/x.txt"):
        (work / rel).write_text("marker\n")
    (work / "secret-canary.txt").write_text("canary marker\n")
    state = tmp_path / "state"
    state.mkdir()
    key_file = state / "grant.key"
    key_file.write_bytes(KEY)
    clock = Clock()
    cfg = gr.GrantConfig(
        key=KEY,
        audience="gate-1",
        store_path=str(state / "grants.json"),
        ledger_path=str(state / "ledger.json"),
        approval_nonce_path=str(state / "approvals.json"),
        approvers=frozenset({HUMAN}),
        key_paths=(str(key_file),),
        clock=clock,
    )
    policy_map = {
        "skills": {
            "worker": {
                "tools": ["read_file", "write_file", "delete_file", "run_box"],
                "paths": [str(work) + "/**"],
            }
        },
        "require_approval": ["delete_file"],
        "isolate": ["run_box"],
    }
    log = tmp_path / "log" / "decisions.jsonl"

    class E:
        pass

    e = E()
    e.tmp, e.work, e.state, e.cfg, e.clock, e.log = (
        tmp_path,
        work,
        state,
        cfg,
        clock,
        log,
    )
    e.key_file = key_file
    e.policy_map = policy_map
    e.policy = load_policy(policy_map)
    e.gate = Gate(e.policy, str(log), cg.ENFORCE, grants=cfg)

    def issue(
        principal="agent:one",
        session=SESSION,
        tools=("read_file",),
        paths=None,
        ttl=600,
        **kw,
    ):
        return gr.issue(
            cfg,
            principal_id=principal,
            skill="worker",
            tools=tools,
            paths=paths or (str(work) + "/**",),
            session_key=session,
            ttl=ttl,
            **kw,
        )

    e.issue = issue

    def call(
        tool="read_file",
        paths=None,
        principal="agent:one",
        grant=None,
        session=SESSION,
        gate=None,
        **kw,
    ):
        return (gate or e.gate).evaluate(
            "worker",
            tool,
            paths if paths is not None else [str(work / "a" / "x.txt")],
            principal_id=principal,
            grant=grant,
            session_key=session,
            **kw,
        )

    e.call = call
    return e


def rows(e):
    return [json.loads(line) for line in e.log.read_text().splitlines()]


def is_deny(d, fragment=""):
    return d.verdict is Verdict.DENY and fragment in d.reason


# ---------------------------------------------------------------- wiring spec W1..W14


def test_w0_valid_grant_allows(env):
    t = env.issue()
    d = env.call(grant=t)
    assert d.verdict is Verdict.ALLOW, d.reason
    assert d.gate == "execution" and d.principal_id == "agent:one" and d.grant_id


def test_w1_forged_ticket_denied(env):
    t = env.issue()
    payload, mac = t.split(".")
    forged = gr.encode(gr.decode_verified(t, KEY), OTHER_KEY)
    assert is_deny(env.call(grant=forged), "bad signature")
    flipped = (
        payload[:-2] + ("A" if payload[-2] != "A" else "B") + payload[-1] + "." + mac
    )
    assert env.call(grant=flipped).verdict is Verdict.DENY
    assert env.call(grant=t).verdict is Verdict.ALLOW


def test_w2_expired_ticket_denied(env):
    t = env.issue(ttl=60)
    assert env.call(grant=t).verdict is Verdict.ALLOW
    env.clock.t += 60
    d = env.call(grant=t)
    # The ticket's own not_after is checked first; the lineage walk is a
    # second layer and would say "ancestor expired".
    assert d.verdict is Verdict.DENY and d.reason == "grant: expired"


def test_w3_refreshed_away_ticket_denied(env):
    old = env.issue()
    new = gr.refresh(env.cfg, old, SESSION, 600)
    assert is_deny(env.call(grant=old), "nonce not current")
    assert env.call(grant=new).verdict is Verdict.ALLOW


def test_w4_revoke_parent_cascades_to_child(env):
    parent = env.issue(tools=("read_file", "write_file"))
    child = gr.attenuate(
        env.cfg,
        parent,
        SESSION,
        principal_id="agent:child",
        session_key=SESSION2,
        tools=("read_file",),
        paths=(str(env.work) + "/a/**",),
        ttl=300,
    )
    assert (
        env.call(grant=child, principal="agent:child", session=SESSION2).verdict
        is Verdict.ALLOW
    )
    gr.end(env.cfg, gr.decode_verified(parent, KEY).grant_id)
    assert is_deny(
        env.call(grant=child, principal="agent:child", session=SESSION2),
        "ancestor revoked",
    )


def test_w5_revoke_on_throw_survives_clear(env):
    t = env.issue()
    assert env.call(grant=t).verdict is Verdict.ALLOW
    assert env.gate.throw("test")
    assert is_deny(env.call(grant=t), "kill switch")
    os.remove(env.gate.halt_path)  # a person clears it
    env.clock.t += 1
    assert is_deny(env.call(grant=t), "revoked by kill switch")
    fresh = env.issue(session=SESSION)
    assert env.call(grant=fresh).verdict is Verdict.ALLOW


def test_w6_principal_must_match_grant(env):
    t = env.issue(principal="agent:one")
    assert is_deny(env.call(grant=t, principal="agent:two"), "principal does not match")


def test_w7_grant_narrows_tool_and_path(env):
    t = env.issue(tools=("read_file",), paths=(str(env.work) + "/a/**",))
    assert is_deny(env.call(tool="write_file", grant=t), "tool outside grant")
    assert is_deny(
        env.call(paths=[str(env.work / "b" / "x.txt")], grant=t), "outside grant"
    )
    assert (
        env.call(paths=[str(env.work / "a" / "y.txt")], grant=t).verdict
        is Verdict.ALLOW
    )


def test_w8_wide_grant_never_upgrades_policy(env, tmp_path):
    outside = tmp_path / "elsewhere.txt"
    outside.write_text("marker\n")
    t = env.issue(tools=("read_file", "delete_file", "run_box"), paths=("/**",))
    assert env.call(tool="delete_file", grant=t).verdict is Verdict.ASK
    assert env.call(tool="run_box", grant=t).verdict is Verdict.ISOLATE
    assert is_deny(env.call(paths=[str(outside)], grant=t), "outside allowlist")


def test_w9_log_keys_fail_closed_without_allowlist(env, monkeypatch):
    t = env.issue()
    legacy = cg._LOG_ALLOWED - {
        "principal_id",
        "grant_id",
        "parent_grant_id",
        "gate",
        "manifest_hash",
        "approval_id",
    }
    monkeypatch.setattr(cg, "_LOG_ALLOWED", legacy)
    # The grant row cannot be written, so the call fails closed: the fallback
    # row (no grant keys) records a gate-error denial instead.
    d = env.call(grant=t)
    assert is_deny(d, "unknown jsonl keys")
    assert "unknown jsonl keys" in rows(env)[-1]["reason"]
    monkeypatch.undo()
    assert env.call(grant=t).verdict is Verdict.ALLOW


def test_w10_log_never_holds_ticket_nonce_session_or_receipt(env):
    t = env.issue(tools=("read_file", "delete_file"))
    env.call(grant=t)
    d = env.call(tool="delete_file", grant=t)
    r = gr.mint_approval(
        KEY,
        manifest=d.manifest_hash,
        principal_id="agent:one",
        approver=HUMAN,
        tool="delete_file",
        pol_hash=gr.policy_hash(env.policy),
        not_after=int(env.clock.t) + 60,
    )
    env.call(tool="delete_file", grant=t, approval=r)
    text = env.log.read_text()
    g = gr.decode_verified(t, KEY)
    for secret in (
        t,
        t.split(".")[0],
        t.split(".")[1],
        g.nonce,
        SESSION,
        r,
        r.split(".")[1],
    ):
        assert secret not in text


def test_w11_observe_logs_would_deny(env):
    gate = Gate(env.policy, str(env.log), cg.OBSERVE, grants=env.cfg)
    d = env.call(grant=None, gate=gate)
    assert d.verdict is Verdict.DENY and d.enforced is False and may_run(d) is True
    last = rows(env)[-1]
    assert (
        last["verdict"] == "deny"
        and last["enforced"] is False
        and last["gate"] == "admission"
    )


def test_w12_legacy_row_has_no_grant_keys(tmp_path, env):
    log = tmp_path / "legacy" / "d.jsonl"
    gate = Gate(env.policy, str(log), cg.ENFORCE)
    d = gate.evaluate("worker", "read_file", [str(env.work / "a" / "x.txt")])
    assert d.verdict is Verdict.ALLOW
    row = json.loads(log.read_text().splitlines()[0])
    assert set(row) == {
        "ts",
        "mode",
        "verdict",
        "reason",
        "skill",
        "tool",
        "paths",
        "enforced",
        "parent",
        "arg_summary",
    }
    assert d.as_dict() == {
        "verdict": "allow",
        "reason": "allowed by policy",
        "skill": "worker",
        "tool": "read_file",
        "paths": [str(env.work / "a" / "x.txt")],
        "enforced": True,
    }


def test_w13_store_and_ledger_fail_closed(env):
    t = env.issue()
    assert env.call(grant=t).verdict is Verdict.ALLOW
    store = env.cfg.store_path
    saved = Path(store).read_text()
    os.remove(store)
    assert is_deny(env.call(grant=t), "missing after first use")
    with open(store, "w") as fh:
        fh.write("{not json")
    assert is_deny(env.call(grant=t), "unreadable")
    with open(store, "w") as fh:
        fh.write(saved)
    assert env.call(grant=t).verdict is Verdict.ALLOW
    os.remove(env.cfg.ledger_path)
    assert is_deny(env.call(grant=t), "ledger")


def test_w13b_ledger_rollback_is_stale(env):
    t = env.issue()
    assert env.call(grant=t).verdict is Verdict.ALLOW
    before = Path(env.cfg.ledger_path).read_text()
    assert env.call(grant=t).verdict is Verdict.ALLOW
    with open(env.cfg.ledger_path, "w") as fh:
        fh.write(before)
    assert is_deny(env.call(grant=t), "stale")


def test_w14_refresh_and_attenuate_only_shrink(env):
    parent = env.issue(
        tools=("read_file",),
        paths=(str(env.work) + "/a/**",),
        ttl=300,
        budget={"calls": 5},
    )
    pa = gr.decode_verified(parent, KEY).not_after
    child = gr.attenuate(
        env.cfg,
        parent,
        SESSION,
        principal_id="agent:child",
        session_key=SESSION2,
        tools=("read_file",),
        paths=(str(env.work) + "/a/x.txt",),
        ttl=300,
        budget={"calls": 2},
    )
    env.clock.t += 200
    refreshed = gr.refresh(env.cfg, child, SESSION2, 300)
    assert gr.decode_verified(refreshed, KEY).not_after <= pa
    with pytest.raises(gr.CredentialRefused, match="tools"):
        gr.attenuate(
            env.cfg,
            parent,
            SESSION,
            principal_id="agent:c2",
            session_key="session-key-c2-0000003",
            tools=("write_file",),
            paths=(str(env.work) + "/a/**",),
            ttl=60,
            budget={"calls": 1},
        )
    with pytest.raises(gr.CredentialRefused, match="path"):
        gr.attenuate(
            env.cfg,
            parent,
            SESSION,
            principal_id="agent:c3",
            session_key="session-key-c3-0000004",
            tools=("read_file",),
            paths=(str(env.work) + "/**",),
            ttl=60,
            budget={"calls": 1},
        )
    with pytest.raises(gr.CredentialRefused, match="budget"):
        gr.attenuate(
            env.cfg,
            parent,
            SESSION,
            principal_id="agent:c4",
            session_key="session-key-c4-0000005",
            tools=("read_file",),
            paths=(str(env.work) + "/a/**",),
            ttl=60,
            budget={"calls": 9},
        )


# ---------------------------------------------------------------- D1 two-gate honesty


def test_m1_a1_every_grant_row_names_its_gate(env):
    t = env.issue(tools=("read_file", "delete_file"))
    env.call(grant=t)
    env.call(grant=None)
    env.call(tool="write_file", grant=t)
    env.call(tool="delete_file", grant=t)
    env.call(paths=[str(env.work / "secret-canary.txt")], grant=t)
    env.call(grant=t, refuse="adapter could not read the paths")
    env.gate.throw("test")
    env.call(grant=t)
    got = rows(env)
    calls = [r for r in got if r["verdict"] != "thrown"]
    assert len(calls) == 7
    assert all(r.get("gate") in ("admission", "execution") for r in calls)
    assert calls[-2]["gate"] == "admission" and calls[-1]["gate"] == "admission"


def test_m1_a2_denied_tool_absent_from_list_and_forced_call_denied(env):
    t = env.issue(tools=("read_file",))
    listed = env.gate.admitted_tools(
        "worker",
        ["read_file", "write_file", "web"],
        principal_id="agent:one",
        grant=t,
        session_key=SESSION,
    )
    assert listed == ["read_file"]
    assert is_deny(env.call(tool="write_file", grant=t), "tool outside grant")


def test_m1_a3_execution_gate_runs_even_when_admitted(env):
    t = env.issue(paths=("/**",))
    d = env.call(paths=[str(env.work / "secret-canary.txt")], grant=t)
    assert is_deny(d, "canary") and d.gate == "execution"


def test_m1_a4_manifest_binds_args(env):
    t = env.issue(tools=("delete_file",))
    d1 = env.call(tool="delete_file", grant=t, args={"path": "a", "force": False})
    d2 = env.call(tool="delete_file", grant=t, args={"path": "a", "force": True})
    assert d1.manifest_hash and d1.manifest_hash != d2.manifest_hash
    assert rows(env)[-1]["manifest_hash"] == d2.manifest_hash
    r = gr.mint_approval(
        KEY,
        manifest=d1.manifest_hash,
        principal_id="agent:one",
        approver=HUMAN,
        tool="delete_file",
        pol_hash=gr.policy_hash(env.policy),
        not_after=int(env.clock.t) + 60,
    )
    assert is_deny(
        env.call(
            tool="delete_file", grant=t, args={"path": "a", "force": True}, approval=r
        ),
        "bound to another action",
    )


@pytest.mark.parametrize("which", ["store", "ledger", "nonces", "key", "state_dir"])
def test_m1_a5_agent_cannot_reach_grant_state(env, which):
    target = {
        "store": env.cfg.store_path,
        "ledger": env.cfg.ledger_path,
        "nonces": env.cfg.approval_nonce_path,
        "key": str(env.key_file),
        "state_dir": str(env.state),
    }[which]
    t = env.issue(tools=("write_file",), paths=("/**",))
    d = env.call(tool="write_file", paths=[target], grant=t)
    assert is_deny(d, "grant state or key file")


def test_m1_a6_absent_principal_denied_at_both_gates(env):
    t = env.issue()
    assert is_deny(env.call(grant=t, principal=None), "missing principal_id")
    assert (
        env.gate.admitted_tools("worker", ["read_file"], grant=t, session_key=SESSION)
        == []
    )


# ---------------------------------------------------------------- D4 bound approvals


def _ask(env, t, args=None):
    d = env.call(tool="delete_file", grant=t, args=args or {"path": "a/x.txt"})
    assert d.verdict is Verdict.ASK
    return d


def _mint(env, d, **over):
    kw = {
        "manifest": d.manifest_hash,
        "principal_id": "agent:one",
        "approver": HUMAN,
        "tool": "delete_file",
        "pol_hash": gr.policy_hash(env.policy),
        "not_after": int(env.clock.t) + 60,
    }
    kw.update(over)
    return gr.mint_approval(KEY, **kw)


def test_m4_a1_receipt_lifts_ask_once(env):
    t = env.issue(tools=("delete_file",))
    d = _ask(env, t)
    r = _mint(env, d)
    ok = env.call(tool="delete_file", grant=t, args={"path": "a/x.txt"}, approval=r)
    assert ok.verdict is Verdict.ALLOW and ok.approval_id
    assert is_deny(
        env.call(tool="delete_file", grant=t, args={"path": "a/x.txt"}, approval=r),
        "replay",
    )


def test_m4_a2_approver_must_be_a_named_human_not_an_agent(env):
    t = env.issue(tools=("delete_file", "read_file"))
    gr.attenuate(
        env.cfg,
        t,
        SESSION,
        principal_id="agent:child",
        session_key=SESSION2,
        tools=("read_file",),
        paths=(str(env.work) + "/a/**",),
        ttl=60,
    )
    d = _ask(env, t)
    assert is_deny(
        env.call(
            tool="delete_file",
            grant=t,
            args={"path": "a/x.txt"},
            approval=_mint(env, d, approver="agent:one"),
        ),
        "requesting principal",
    )
    cfg2 = gr.GrantConfig(
        **{**env.cfg.__dict__, "approvers": frozenset({HUMAN, "agent:child"})}
    )
    gate2 = Gate(env.policy, str(env.log), cg.ENFORCE, grants=cfg2)
    assert is_deny(
        env.call(
            tool="delete_file",
            grant=t,
            args={"path": "a/x.txt"},
            gate=gate2,
            approval=_mint(env, d, approver="agent:child"),
        ),
        "agent principal",
    )
    assert is_deny(
        env.call(
            tool="delete_file",
            grant=t,
            args={"path": "a/x.txt"},
            approval=_mint(env, d, approver="human:stranger"),
        ),
        "named human",
    )


def test_m4_a3_policy_change_voids_receipt(env):
    t = env.issue(tools=("delete_file",))
    d = _ask(env, t)
    r = _mint(env, d)
    pm = json.loads(json.dumps(env.policy_map))
    pm["skills"]["worker"]["tools"].append("list_dir")
    gate2 = Gate(load_policy(pm), str(env.log), cg.ENFORCE, grants=env.cfg)
    assert is_deny(
        env.call(
            tool="delete_file",
            grant=t,
            args={"path": "a/x.txt"},
            gate=gate2,
            approval=r,
        ),
        "another policy",
    )


def test_m4_a4_receipt_key_file_not_reachable(env):
    t = env.issue(tools=("read_file",), paths=("/**",))
    assert is_deny(
        env.call(paths=[str(env.key_file)], grant=t), "grant state or key file"
    )


def test_m4_a5_ask_without_receipt_does_not_run(env):
    t = env.issue(tools=("delete_file",))
    d = _ask(env, t)
    assert may_run(d) is False


@pytest.mark.parametrize(
    "mutant",
    ["replay", "args_swap", "expired", "wrong_approver", "policy_change", "bad_mac"],
)
def test_m4_a6_receipt_mutants_red(env, mutant):
    t = env.issue(tools=("delete_file",))
    d = _ask(env, t)
    args = {"path": "a/x.txt"}
    gate = env.gate
    if mutant == "replay":
        r = _mint(env, d)
        assert (
            env.call(tool="delete_file", grant=t, args=args, approval=r).verdict
            is Verdict.ALLOW
        )
    elif mutant == "args_swap":
        r = _mint(env, d)
        args = {"path": "b/x.txt"}
    elif mutant == "expired":
        r = _mint(env, d, not_after=int(env.clock.t))
    elif mutant == "wrong_approver":
        r = _mint(env, d, approver="agent:one")
    elif mutant == "policy_change":
        r = _mint(env, d, pol_hash="0" * 64)
    else:
        r = gr.mint_approval(
            OTHER_KEY,
            manifest=d.manifest_hash,
            principal_id="agent:one",
            approver=HUMAN,
            tool="delete_file",
            pol_hash=gr.policy_hash(env.policy),
            not_after=int(env.clock.t) + 60,
        )
    out = env.call(tool="delete_file", grant=t, args=args, approval=r, gate=gate)
    assert out.verdict is Verdict.DENY and not may_run(out)


# ---------------------------------------------------------------- D5 ledger and budgets


def test_m5_a1_ledger_keys_are_principal_grant_tool_unit(env):
    t = env.issue(budget={"calls": 5})
    env.call(grant=t)
    used = json.loads(Path(env.cfg.ledger_path).read_text())["used"]
    gid = gr.decode_verified(t, KEY).grant_id
    assert used == {f"agent:one|{gid}|read_file|calls": 1}


def test_m5_a2_cap_is_pre_call_and_fails_closed(env):
    t = env.issue(budget={"calls": 2})
    assert env.call(grant=t).verdict is Verdict.ALLOW
    assert env.call(grant=t).verdict is Verdict.ALLOW
    assert is_deny(env.call(grant=t), "budget: calls cap 2")
    with open(env.cfg.ledger_path, "w") as fh:
        fh.write("[]")
    assert is_deny(env.call(grant=t), "ledger")


def test_m5_a2b_reported_usage_counts_against_next_call(env):
    t = env.issue(budget={"calls": 10, "egress_bytes": 100})
    assert env.call(grant=t).verdict is Verdict.ALLOW
    gid = gr.decode_verified(t, KEY).grant_id
    env.gate._ledger.charge_usage(
        [("agent:one", gid, {})], "read_file", {"egress_bytes": 100}
    )
    assert is_deny(env.call(grant=t), "egress_bytes")


def test_m5_a3_child_spends_from_parent(env):
    parent = env.issue(budget={"calls": 3})
    child = gr.attenuate(
        env.cfg,
        parent,
        SESSION,
        principal_id="agent:child",
        session_key=SESSION2,
        tools=("read_file",),
        paths=(str(env.work) + "/a/**",),
        ttl=60,
        budget={"calls": 3},
    )
    for _ in range(2):
        assert (
            env.call(grant=child, principal="agent:child", session=SESSION2).verdict
            is Verdict.ALLOW
        )
    assert env.call(grant=parent).verdict is Verdict.ALLOW
    assert is_deny(env.call(grant=parent), "budget")
    assert is_deny(
        env.call(grant=child, principal="agent:child", session=SESSION2), "budget"
    )


def test_m5_a4_rate_limit_and_loop_guard(env):
    cfg = gr.GrantConfig(
        **{**env.cfg.__dict__, "rate_limit": (3, 60.0), "loop_limit": 2}
    )
    gate = Gate(env.policy, str(env.log), cg.ENFORCE, grants=cfg)
    t = env.issue(tools=("read_file", "write_file"))
    assert env.call(grant=t, gate=gate, args={"n": 1}).verdict is Verdict.ALLOW
    assert env.call(grant=t, gate=gate, args={"n": 1}).verdict is Verdict.ALLOW
    assert is_deny(env.call(grant=t, gate=gate, args={"n": 1}), "loop guard")
    assert env.call(grant=t, gate=gate, args={"n": 2}).verdict is Verdict.ALLOW
    assert is_deny(env.call(grant=t, gate=gate, args={"n": 3}), "rate limit")
    assert env.call(tool="write_file", grant=t, gate=gate).verdict is Verdict.ALLOW
    env.clock.t += 61
    assert env.call(grant=t, gate=gate, args={"n": 4}).verdict is Verdict.ALLOW


def test_m5_a5_good_behavior_never_raises_caps(env):
    t = env.issue(budget={"calls": 3})
    for _ in range(3):
        env.call(grant=t)
    gid = gr.decode_verified(t, KEY).grant_id
    assert json.loads(Path(env.cfg.store_path).read_text())["lineage"][gid][
        "budget"
    ] == {"calls": 3}
    assert is_deny(env.call(grant=t), "budget")


# ---------------------------------------------------------------- D7 agent identity as NHI


def test_m7_a1_retire_principal_kills_grants_and_descendants(env):
    parent = env.issue()
    child = gr.attenuate(
        env.cfg,
        parent,
        SESSION,
        principal_id="agent:child",
        session_key=SESSION2,
        tools=("read_file",),
        paths=(str(env.work) + "/a/**",),
        ttl=60,
    )
    gr.GrantStore(env.cfg.store_path).retire_principal("agent:one")
    assert is_deny(env.call(grant=parent), "revoked")
    assert is_deny(
        env.call(grant=child, principal="agent:child", session=SESSION2),
        "ancestor revoked",
    )


def test_m7_a2_one_principal_per_session(env):
    env.issue(principal="agent:one", session=SESSION)
    with pytest.raises(gr.CredentialRefused, match="another session"):
        env.issue(principal="agent:one", session=SESSION2)


@pytest.mark.parametrize("risk,cap", sorted(gr.RISK_TTL_CAPS.items()))
def test_m7_a3_ttl_capped_by_risk_at_mint(env, risk, cap):
    env.issue(
        principal=f"agent:{risk}",
        session=f"session-key-{risk}-00000",
        ttl=cap,
        risk=risk,
    )
    with pytest.raises(gr.CredentialRefused, match="ttl"):
        env.issue(
            principal=f"agent:{risk}x",
            session=f"session-key-{risk}-x0000",
            ttl=cap + 1,
            risk=risk,
        )


def test_m7_a4_grant_is_not_a_bearer_token(env):
    t = env.issue()
    assert is_deny(env.call(grant=t, session=None), "not bearer")
    assert is_deny(
        env.call(grant=t, session="session-key-human-000000"), "session does not match"
    )


def test_m7_a5_no_grant_no_call_even_with_env_credentials(env, monkeypatch):
    monkeypatch.setenv("FAKE_SERVICE_TOKEN", "marker-not-a-secret")
    assert is_deny(env.call(grant=None), "no grant")


# ---------------------------------------------------------------- SDK pass-through


def test_sdk_client_passes_grant_through(env, tmp_path):
    import yaml

    pol = tmp_path / "policy.yaml"
    pol.write_text(yaml.safe_dump(env.policy_map))
    c = Client.from_files(pol, tmp_path / "sdklog" / "d.jsonl", grants=env.cfg)
    t = env.issue()
    ok = c.check(
        "worker",
        "read_file",
        [str(env.work / "a" / "x.txt")],
        principal_id="agent:one",
        grant=t,
        session_key=SESSION,
    )
    assert may_run(ok)
    no = c.check("worker", "read_file", [str(env.work / "a" / "x.txt")])
    assert not may_run(no) and "missing principal_id" in no.reason


def test_w5b_throw_with_broken_store_still_thrown_and_says_so(env):
    t = env.issue()
    os.remove(env.cfg.store_path)
    os.mkdir(env.cfg.store_path)  # cannot be read or replaced as a file
    with pytest.raises(gr.StoreError):
        env.gate.throw("test")
    assert os.path.lexists(env.gate.halt_path)
    assert "grant revoke FAILED" in rows(env)[-1]["reason"]
    assert is_deny(env.call(grant=t), "kill switch")
