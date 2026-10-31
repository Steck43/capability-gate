"""Decay slice 1: a never-backward clock that fails closed (I4) and
human-only renewal (D3).

Each control has a known-answer test and a go-red test. The go-red test
removes the control with monkeypatch inside the run, never by editing the
repo, and shows the bad outcome comes back. So the known-answer test would
fail if the control were deleted.

Temp folders and harmless marker files only. No network.
"""

from __future__ import annotations

import dataclasses
import json
import math
from pathlib import Path

import pytest
import test_b9_grant_wiring as wiring
from test_b9_grant_wiring import APPROVER, KEY, SESSION, SESSION2, is_deny, renew, rows

import capability_gate_grants as gr
from capability_gate import Verdict

env = wiring.env  # the shared temp-folder fixture


def _no_clock_check(monkeypatch):
    monkeypatch.setattr(gr, "_check_clock", lambda raw, st, slack: None)


# ------------------------------------------------------------ I4 clock, G-6


def test_g6_step_back_with_a_live_grant_is_deny_with_a_row(env):
    t = env.issue(ttl=600)
    assert env.call(grant=t).verdict is Verdict.ALLOW
    env.clock.t -= 10  # the grant is still live at the high-water mark
    d = env.call(grant=t)
    assert is_deny(d, gr.CLOCK_BACKWARD)
    row = rows(env)[-1]
    assert row["verdict"] == "deny" and gr.CLOCK_BACKWARD in row["reason"]


def test_g6_go_red_without_the_check_the_live_grant_still_works(env, monkeypatch):
    _no_clock_check(monkeypatch)
    t = env.issue(ttl=600)
    assert env.call(grant=t).verdict is Verdict.ALLOW
    env.clock.t -= 10
    assert env.call(grant=t).verdict is Verdict.ALLOW  # the old clamp


def test_g6_refusal_holds_until_the_clock_catches_up(env):
    t = env.issue(ttl=600)
    assert env.call(grant=t).verdict is Verdict.ALLOW
    env.clock.t -= 10
    assert is_deny(env.call(grant=t), gr.CLOCK_BACKWARD)
    env.clock.t += 10  # back at the high-water: no automatic reset, just time
    assert env.call(grant=t).verdict is Verdict.ALLOW


def test_g6_slack_allows_a_small_step_and_refuses_a_larger_one(env):
    cfg = dataclasses.replace(env.cfg, clock_backward_slack=5.0)
    gate = wiring.Gate(env.policy, str(env.log), wiring.cg.ENFORCE, grants=cfg)
    t = env.issue(ttl=600)
    assert env.call(grant=t, gate=gate).verdict is Verdict.ALLOW
    env.clock.t -= 5
    assert env.call(grant=t, gate=gate).verdict is Verdict.ALLOW
    env.clock.t -= 1
    assert is_deny(env.call(grant=t, gate=gate), gr.CLOCK_BACKWARD)


def test_g6_a_nan_reading_is_deny_and_leaves_no_nan_high_water(env):
    t = env.issue(ttl=60)
    env.clock.t += 120  # the grant has expired
    env.clock.t = float("nan")
    assert is_deny(env.call(grant=t), gr.CLOCK_NOT_FINITE)
    high = json.loads(Path(env.cfg.store_path).read_text()).get("clock_high")
    assert high is None or math.isfinite(high)
    env.clock.t = 1_000_000.0 + 120
    assert is_deny(env.call(grant=t), "expired")


def test_g6_go_red_without_the_finite_check_nan_revives_an_expired_grant(
    env, monkeypatch
):
    monkeypatch.setattr(gr, "_finite_clock", lambda raw, high: None)
    t = env.issue(ttl=60)
    env.clock.t += 120
    assert is_deny(env.call(grant=t), "expired")
    env.clock.t = float("nan")
    assert env.call(grant=t).verdict is Verdict.ALLOW


@pytest.mark.parametrize("slack", [float("nan"), float("inf"), -1.0, True])
def test_g6_bad_slack_is_refused_at_config(env, slack):
    with pytest.raises(ValueError, match="clock_backward_slack"):
        dataclasses.replace(env.cfg, clock_backward_slack=slack)


def test_g6_go_red_without_the_slack_check_nan_slack_turns_i4_off(env, monkeypatch):
    monkeypatch.setattr(gr, "_slack_ok", lambda slack: None)
    cfg = dataclasses.replace(env.cfg, clock_backward_slack=float("nan"))
    gate = wiring.Gate(env.policy, str(env.log), wiring.cg.ENFORCE, grants=cfg)
    t = env.issue(ttl=600)
    assert env.call(grant=t, gate=gate).verdict is Verdict.ALLOW
    env.clock.t -= 100
    assert env.call(grant=t, gate=gate).verdict is Verdict.ALLOW


def test_g6_restart_does_not_forget_the_high_water(env):
    t = env.issue(ttl=600)
    assert env.call(grant=t).verdict is Verdict.ALLOW
    env.clock.t -= 10
    restarted = wiring.Gate(env.policy, str(env.log), wiring.cg.ENFORCE, grants=env.cfg)
    assert is_deny(env.call(grant=t, gate=restarted), gr.CLOCK_BACKWARD)


# ------------------------------------------------------------ I4 ledger site, G-6b


def _step_back_between_admission_and_charge(env, monkeypatch):
    real = gr.Ledger.admit_and_charge

    def racing(self, **kw):
        env.clock.t -= 10  # lands after Gate 1 verify, before the charge
        return real(self, **kw)

    monkeypatch.setattr(gr.Ledger, "admit_and_charge", racing)


def test_g6b_step_back_after_admission_is_refused_at_the_charge(env, monkeypatch):
    t = env.issue(ttl=600)
    assert env.call(grant=t).verdict is Verdict.ALLOW
    seq0 = json.loads(Path(env.cfg.ledger_path).read_text())["seq"]
    _step_back_between_admission_and_charge(env, monkeypatch)
    assert is_deny(env.call(grant=t), gr.CLOCK_BACKWARD)
    assert json.loads(Path(env.cfg.ledger_path).read_text())["seq"] == seq0


def test_g6b_go_red_without_the_ledger_check_the_call_is_charged(env, monkeypatch):
    t = env.issue(ttl=600)
    assert env.call(grant=t).verdict is Verdict.ALLOW
    _step_back_between_admission_and_charge(env, monkeypatch)
    _no_clock_check(monkeypatch)
    assert env.call(grant=t).verdict is Verdict.ALLOW


# ------------------------------------------------------------ D3 renewal, G-5


def test_g5_refresh_without_a_receipt_is_refused(env):
    t = env.issue()
    with pytest.raises(gr.CredentialRefused, match="human renewal receipt"):
        gr.refresh(env.cfg, t, SESSION, 600)


def test_g5_go_red_without_the_receipt_check_refresh_goes_through(env, monkeypatch):
    monkeypatch.setattr(gr, "renewal_reason", lambda *a, **k: (None, "n" * 32))
    t = env.issue()
    assert gr.refresh(env.cfg, t, SESSION, 600)


def test_g5_the_agent_cannot_approve_its_own_renewal(env):
    t = env.issue()
    with pytest.raises(gr.CredentialRefused, match="requesting principal"):
        gr.refresh(
            env.cfg, t, SESSION, 600, renewal=renew(env, t, 600, approver="agent:one")
        )


def test_g5_an_agent_in_the_lineage_cannot_approve(env):
    # Even if an agent id is wrongly listed as an approver, the lineage check holds.
    cfg = dataclasses.replace(env.cfg, approvers=frozenset({APPROVER, "agent:child"}))
    parent = env.issue(tools=("read_file",))
    child = gr.attenuate(
        cfg,
        parent,
        SESSION,
        principal_id="agent:child",
        session_key=SESSION2,
        tools=("read_file",),
        paths=(str(env.work) + "/a/**",),
        ttl=300,
    )
    with pytest.raises(gr.CredentialRefused, match="agent principal"):
        gr.refresh(
            cfg,
            parent,
            SESSION,
            600,
            renewal=renew(env, parent, 600, approver="agent:child"),
        )
    assert child  # the child exists, so its principal is in the lineage


def test_g5_unknown_approver_is_refused(env):
    t = env.issue()
    with pytest.raises(gr.CredentialRefused, match="named human approver"):
        gr.refresh(
            env.cfg, t, SESSION, 600, renewal=renew(env, t, 600, approver="human:other")
        )


def test_g5_receipt_for_another_grant_or_lifetime_is_refused(env):
    t, other = env.issue(), env.issue()
    with pytest.raises(gr.CredentialRefused, match="another grant"):
        gr.refresh(env.cfg, t, SESSION, 600, renewal=renew(env, other, 600))
    with pytest.raises(gr.CredentialRefused, match="another lifetime"):
        gr.refresh(env.cfg, t, SESSION, 300, renewal=renew(env, t, 600))


def test_g5_an_approval_receipt_cannot_renew(env):
    t = env.issue()
    g = gr.decode_verified(t, KEY)
    approval = gr.mint_approval(
        wiring.APPROVAL_KEY,
        manifest="m",
        principal_id=g.principal_id,
        approver=APPROVER,
        tool="read_file",
        pol_hash=gr.policy_hash(env.policy),
        not_after=int(env.clock.t) + 60,
    )
    # "bad mac", not just "renewal receipt": the renewal domain is what refuses
    # it. With the approval domain reused, the body-key check would catch it.
    with pytest.raises(gr.CredentialRefused, match="renewal receipt bad mac"):
        gr.refresh(env.cfg, t, SESSION, 600, renewal=approval)


def test_g5_expired_receipt_is_refused(env):
    t = env.issue()
    r = renew(env, t, 600, not_after=int(env.clock.t) + 30)
    env.clock.t += 31
    with pytest.raises(gr.CredentialRefused, match="renewal receipt expired"):
        gr.refresh(env.cfg, t, SESSION, 600, renewal=r)


def test_g5_a_receipt_renews_once(env):
    t = env.issue()
    r = renew(env, t, 600)
    new = gr.refresh(env.cfg, t, SESSION, 600, renewal=r)
    assert env.call(grant=new).verdict is Verdict.ALLOW
    g = gr.decode_verified(new, KEY)
    replay = renew(env, new, 600, nonce=json.loads(gr._b64d(r.split(".")[0]))["nonce"])
    with pytest.raises(gr.CredentialRefused, match="replay"):
        gr.refresh(env.cfg, new, SESSION, 600, renewal=replay)
    assert g.grant_id  # still the same grant id, renewed in place
