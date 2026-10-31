"""Strict regressions for persisted grant state and atomic admission.

Temp folders and harmless marker files only. No network.
"""

from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path

import pytest
import test_b9_grant_wiring as wiring
from test_b9_grant_wiring import APPROVAL_KEY, APPROVER, KEY, is_deny, rows

import capability_gate as cg
import capability_gate_grants as gr
from capability_gate import Gate, Verdict

env = wiring.env  # the shared temp-folder fixture


def new_gate(env, cfg=None):
    """A second process on the same state files: a restart."""
    return Gate(env.policy, str(env.log), cg.ENFORCE, grants=cfg or env.cfg)


def mint(env, d, **over):
    kw = {
        "manifest": d.manifest_hash,
        "principal_id": "agent:one",
        "approver": APPROVER,
        "tool": "delete_file",
        "pol_hash": gr.policy_hash(env.policy),
        "not_after": int(env.clock.t) + 60,
    }
    kw.update(over)
    return gr.mint_approval(APPROVAL_KEY, **kw)


ARGS = {"path": "a/x.txt"}


def ask(env, t):
    d = env.call(tool="delete_file", grant=t, args=ARGS)
    assert d.verdict is Verdict.ASK, d.reason
    return d


def spent(env):
    p = Path(env.cfg.approval_nonce_path)
    return json.loads(p.read_text())["spent"] if p.exists() else []


# ------------------------------------------------------------ H3 ledger restart


def test_h3_ledger_delete_then_restart_still_denies(env):
    t = env.issue(budget={"calls": 1})
    assert env.call(grant=t).verdict is Verdict.ALLOW
    assert is_deny(env.call(grant=t), "budget")
    os.remove(env.cfg.ledger_path)
    g2 = new_gate(env)
    assert not os.path.lexists(env.cfg.ledger_path), "ledger must not be re-created"
    assert is_deny(env.call(grant=t, gate=g2), "ledger missing after first use")


def test_h3_ledger_rollback_then_restart_still_denies(env):
    t = env.issue(budget={"calls": 1})
    fresh = Path(env.cfg.ledger_path).read_text()  # seq 0, nothing used
    assert env.call(grant=t).verdict is Verdict.ALLOW
    Path(env.cfg.ledger_path).write_text(fresh)
    g2 = new_gate(env)
    assert is_deny(env.call(grant=t, gate=g2), "ledger stale")


def test_h3_first_gate_on_fresh_state_creates_ledger_and_seal(env):
    st = json.loads(Path(env.cfg.store_path).read_text())
    assert st["seals"]["ledger"] == 0
    t = env.issue()
    assert env.call(grant=t).verdict is Verdict.ALLOW
    st = json.loads(Path(env.cfg.store_path).read_text())
    assert (
        st["seals"]["ledger"]
        == json.loads(Path(env.cfg.ledger_path).read_text())["seq"]
    )
    # A clean restart keeps working.
    assert env.call(grant=t, gate=new_gate(env)).verdict is Verdict.ALLOW


# ------------------------------------------------------------ H3b approval nonce file


def test_h3b_approval_file_delete_does_not_revive_receipt(env):
    t = env.issue(tools=("delete_file",))
    r = mint(env, ask(env, t))
    assert env.call(tool="delete_file", grant=t, args=ARGS, approval=r).verdict is (
        Verdict.ALLOW
    )
    os.remove(env.cfg.approval_nonce_path)
    d = env.call(tool="delete_file", grant=t, args=ARGS, approval=r)
    assert is_deny(d, "approval nonce file missing after first use")
    d = env.call(tool="delete_file", grant=t, args=ARGS, approval=r, gate=new_gate(env))
    assert is_deny(d, "approval nonce file missing after first use")


def test_h3b_approval_file_rollback_does_not_revive_receipt(env):
    t = env.issue(tools=("delete_file",))
    r1 = mint(env, ask(env, t))
    assert env.call(tool="delete_file", grant=t, args=ARGS, approval=r1).verdict is (
        Verdict.ALLOW
    )
    before = Path(env.cfg.approval_nonce_path).read_text()
    r2 = mint(env, ask(env, t))
    assert env.call(tool="delete_file", grant=t, args=ARGS, approval=r2).verdict is (
        Verdict.ALLOW
    )
    Path(env.cfg.approval_nonce_path).write_text(before)  # drops r2's nonce
    d = env.call(tool="delete_file", grant=t, args=ARGS, approval=r2)
    assert is_deny(d, "approval nonce file stale")


# ------------------------------------------------------------ H4 clock and not-before


def test_h4_clock_rollback_does_not_revive_expired_grant(env):
    t = env.issue(ttl=60)
    assert env.call(grant=t).verdict is Verdict.ALLOW
    env.clock.t += 61
    assert is_deny(env.call(grant=t), "expired")
    env.clock.t -= 61
    # I4: a rollback is now refused outright, before expiry is even checked.
    assert is_deny(env.call(grant=t), gr.CLOCK_BACKWARD)
    assert is_deny(env.call(grant=t, gate=new_gate(env)), gr.CLOCK_BACKWARD)


def test_h4_grant_from_a_clock_set_ahead_is_not_yet_valid(env):
    env.clock.t += 3600
    t = env.issue(ttl=600)
    env.clock.t -= 3600
    assert is_deny(env.call(grant=t), "not yet valid")


def test_h4_clock_rollback_does_not_revive_expired_receipt(env):
    t = env.issue(tools=("delete_file",), ttl=600)
    d = ask(env, t)
    r = mint(env, d, not_after=int(env.clock.t) + 30)
    env.clock.t += 31
    assert is_deny(
        env.call(tool="delete_file", grant=t, args=ARGS, approval=r),
        "approval receipt expired",
    )
    env.clock.t -= 31
    # I4: a rollback is now refused outright, before the receipt is checked.
    assert is_deny(
        env.call(tool="delete_file", grant=t, args=ARGS, approval=r),
        gr.CLOCK_BACKWARD,
    )


def test_h4_throw_kills_a_grant_issued_ahead_of_the_clock(env):
    env.clock.t += 120
    t = env.issue(ttl=600)
    env.clock.t -= 120
    assert env.gate.throw("test")
    os.remove(env.gate.halt_path)
    env.clock.t += 200  # past issued_at, so not-before no longer hides it
    assert is_deny(env.call(grant=t), "revoked by kill switch")


# ------------------------------------------------------------ H5 verify-to-charge


def test_h5_revoke_between_admission_and_charge_wins(env, monkeypatch):
    t = env.issue()
    gid = gr.decode_verified(t, KEY).grant_id
    seq0 = json.loads(Path(env.cfg.ledger_path).read_text())["seq"]
    real = gr.Ledger.admit_and_charge

    def racing(self, **kw):
        gr.end(env.cfg, gid)  # lands after Gate 1 verify, before the charge
        return real(self, **kw)

    monkeypatch.setattr(gr.Ledger, "admit_and_charge", racing)
    d = env.call(grant=t)
    assert is_deny(d, "revoked")
    assert json.loads(Path(env.cfg.ledger_path).read_text())["seq"] == seq0


def test_h5b_budget_deny_does_not_burn_the_receipt(env):
    t = env.issue(tools=("read_file", "delete_file"), budget={"calls": 1})
    assert env.call(grant=t).verdict is Verdict.ALLOW  # spends the only call
    r = mint(env, ask(env, t))
    d = env.call(tool="delete_file", grant=t, args=ARGS, approval=r)
    assert is_deny(d, "budget")
    assert spent(env) == []


def test_h5b_receipt_is_spent_once_on_a_charged_call(env):
    t = env.issue(tools=("delete_file",))
    r = mint(env, ask(env, t))
    assert env.call(tool="delete_file", grant=t, args=ARGS, approval=r).verdict is (
        Verdict.ALLOW
    )
    assert len(spent(env)) == 1
    assert is_deny(
        env.call(tool="delete_file", grant=t, args=ARGS, approval=r), "replay"
    )


# ------------------------------------------------------------ H2 split key, H1 repr


def test_h2_grant_key_cannot_mint_an_approval(env):
    t = env.issue(tools=("delete_file",))
    d = ask(env, t)
    r = gr.mint_approval(
        KEY,
        manifest=d.manifest_hash,
        principal_id="agent:one",
        approver=APPROVER,
        tool="delete_file",
        pol_hash=gr.policy_hash(env.policy),
        not_after=int(env.clock.t) + 60,
    )
    assert is_deny(
        env.call(tool="delete_file", grant=t, args=ARGS, approval=r), "bad mac"
    )


def test_h2_approval_key_must_differ_and_must_be_set(env):
    with pytest.raises(ValueError):
        dataclasses.replace(env.cfg, approval_key=KEY)
    cfg = dataclasses.replace(env.cfg, approval_key=None)
    g = new_gate(env, cfg)
    t = env.issue(tools=("delete_file",))
    d = env.call(tool="delete_file", grant=t, args=ARGS, gate=g)
    r = mint(env, d)
    assert is_deny(
        env.call(tool="delete_file", grant=t, args=ARGS, approval=r, gate=g),
        "approval key not configured",
    )


def test_h1_config_repr_does_not_print_keys(env):
    text = repr(env.cfg)
    assert repr(KEY) not in text and repr(APPROVAL_KEY) not in text


# ------------------------------------------------------------ H7 rate history


def test_h7_other_principals_cannot_push_rows_out_of_the_window(env):
    cfg = dataclasses.replace(env.cfg, rate_limit=(2, 60.0))
    g = new_gate(env, cfg)
    t = env.issue()
    assert env.call(grant=t, gate=g).verdict is Verdict.ALLOW
    assert env.call(grant=t, gate=g).verdict is Verdict.ALLOW
    assert is_deny(env.call(grant=t, gate=g), "rate limit")
    # Other principals' rows inside the window, more than the old 1000 cap.
    led = json.loads(Path(cfg.ledger_path).read_text())
    now = env.clock.t
    led["history"] += [
        {"ts": now, "p": f"agent:busy{i}", "tool": "read_file", "m": "x"}
        for i in range(1200)
    ]
    led["seq"] += 1
    Path(cfg.ledger_path).write_text(json.dumps(led))
    other = env.issue(principal="agent:other", session="session-key-agent-other-03")
    assert (
        env.call(
            grant=other,
            principal="agent:other",
            session="session-key-agent-other-03",
            gate=g,
        ).verdict
        is Verdict.ALLOW
    )
    assert is_deny(env.call(grant=t, gate=g), "rate limit")


def test_h7_rows_outside_the_window_are_pruned(env):
    cfg = dataclasses.replace(env.cfg, rate_limit=(5, 10.0))
    g = new_gate(env, cfg)
    t = env.issue()
    assert env.call(grant=t, gate=g).verdict is Verdict.ALLOW
    env.clock.t += 11
    assert env.call(grant=t, gate=g).verdict is Verdict.ALLOW
    hist = json.loads(Path(cfg.ledger_path).read_text())["history"]
    assert len(hist) == 1 and hist[0]["ts"] == env.clock.t


# ------------------------------------------------------------ marker and refusal paths


def test_marker_down_without_throw_still_revokes(env):
    t = env.issue()
    assert env.call(grant=t).verdict is Verdict.ALLOW
    Path(env.gate.halt_path).write_text("marker\n")  # not via Gate.throw
    assert is_deny(env.call(grant=t), "kill switch")
    os.remove(env.gate.halt_path)
    env.clock.t += 1
    assert is_deny(env.call(grant=t), "revoked by kill switch")


def test_retry_throw_after_failed_revoke_rearms_it(env, monkeypatch):
    t = env.issue()
    real = gr.GrantStore.revoke_all_registered

    def broken(self, ts):
        raise OSError("marker: store write failed")

    monkeypatch.setattr(gr.GrantStore, "revoke_all_registered", broken)
    with pytest.raises(OSError):
        env.gate.throw("test")
    monkeypatch.setattr(gr.GrantStore, "revoke_all_registered", real)
    assert env.gate.throw("retry") is False  # already thrown, but revokes now
    os.remove(env.gate.halt_path)
    env.clock.t += 1
    assert is_deny(env.call(grant=t), "revoked by kill switch")


def test_refused_ticket_row_names_its_grant(env):
    t = env.issue()
    g = gr.decode_verified(t, KEY)
    gr.end(env.cfg, g.grant_id)
    d = env.call(grant=t)
    assert is_deny(d, "revoked") and d.grant_id == g.grant_id
    assert rows(env)[-1]["grant_id"] == g.grant_id
    forged = gr.encode(g, b"o" * 32)
    d = env.call(grant=forged)
    assert is_deny(d, "bad signature") and d.grant_id is None
