"""Thin client for capability-gate: four calls and may_run, fail-closed.

Phase A of the thin client. The client holds no policy logic
and no glob matching; every decision comes from ``Gate.evaluate``. Mode is
fixed when the client is built and there is no way to change it through this
module, so a caller cannot flip a live client to observe.

Contract a caller can rely on:

* ``Client.from_files`` either returns a working client or raises
  ``ClientRefused``. No half-built client exists after a failed load.
* ``Client.check`` always asks the gate. Any exception from the gate becomes a
  DENY decision; a caller that sees an exception from ``check`` anyway must
  treat it as a deny.
* ``Client.verify_log`` returns the head hash or raises. It never returns a
  pass value on error.
* ``Client.throw`` throws the kill switch. Nothing here clears it; a person
  removes the marker.
* ``may_run(decision)`` is True only for ALLOW, or for any verdict when the
  decision was not enforced (observe mode blocks nothing).

Out of scope on purpose: ``set_mode``, isolate routing, packaging, other
languages, any network transport. The gate's single-log hash chain is the only
record; this module makes no cross-plane receipt claim.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence

from capability_gate import (
    ENFORCE,
    OBSERVE,
    CheckpointConfig,
    Decision,
    Gate,
    KillSwitchUnthrowable,
    Verdict,
    load_policy,
    load_yaml_mapping,
    verify_hash_chain,
)

__all__ = [
    "Client",
    "ClientRefused",
    "KillSwitchUnthrowable",
    "may_run",
]

# Only from_files holds this, so Client(...) called directly is refused rather
# than producing a client that skipped the policy load.
_BUILD_TOKEN = object()


class ClientRefused(Exception):
    """The client could not be built. There is no client to call."""


def _text(value: object) -> str:
    try:
        return str(value)
    except Exception:
        return "<unprintable>"


class Client:
    __slots__ = ("_anchor_path", "_checkpoint", "_gate", "_log_path", "_mode")

    def __init__(
        self,
        token: object,
        gate: Gate,
        mode: str,
        log_path: str,
        anchor_path: str | None,
        checkpoint: CheckpointConfig | None,
    ) -> None:
        if token is not _BUILD_TOKEN:
            raise ClientRefused("build a client with Client.from_files")
        self._gate = gate
        self._mode = mode
        self._log_path = log_path
        self._anchor_path = anchor_path
        self._checkpoint = checkpoint

    @classmethod
    def from_files(
        cls,
        policy_path: str | os.PathLike,
        log_path: str | os.PathLike,
        mode: str = ENFORCE,
        *,
        anchor_path: str | os.PathLike | None = None,
        checkpoint: CheckpointConfig | None = None,
        grants=None,
    ) -> Client:
        try:
            # type() rather than isinstance: a str subclass could compare equal
            # to "enforce" here and still behave differently inside the gate.
            if type(mode) is not str or mode not in (ENFORCE, OBSERVE):
                raise ValueError(
                    f"mode must be '{ENFORCE}' or '{OBSERVE}', got {mode!r}"
                )
            with open(policy_path, encoding="utf-8") as fh:
                text = fh.read()
            policy = load_policy(load_yaml_mapping(text))
            log = os.path.abspath(os.fspath(log_path))
            anchor = os.path.abspath(os.fspath(anchor_path)) if anchor_path else None
            gate = Gate(
                policy,
                log,
                mode,
                anchor_path=anchor,
                checkpoint=checkpoint,
                grants=grants,
            )
        except Exception as exc:
            raise ClientRefused(f"capability-gate client refused: {exc!r}") from exc
        return cls(_BUILD_TOKEN, gate, mode, log, anchor, checkpoint)

    @property
    def mode(self) -> str:
        return self._mode

    def _deny(self, skill: object, tool: object, reason: str) -> Decision:
        return Decision(
            Verdict.DENY,
            reason,
            _text(skill),
            _text(tool),
            (),
            enforced=(self._mode == ENFORCE),
        )

    def check(
        self,
        skill: str,
        tool: str,
        paths: Sequence[str] = (),
        *,
        args: Mapping | None = None,
        trace: Mapping[str, str] | None = None,
        base_dir: str | None = None,
        refuse: str | None = None,
        principal_id: str | None = None,
        grant: str | None = None,
        session_key: str | None = None,
        approval: str | None = None,
    ) -> Decision:
        # The gate object is reachable as a private attribute. If anything
        # moved its mode away from the one this client was built with, the
        # client no longer knows what "enforced" means, so it denies.
        try:
            drifted = self._gate.mode != self._mode
        except Exception as exc:
            return self._deny(
                skill, tool, f"sdk: gate mode unreadable, failing closed: {exc!r}"
            )
        if drifted:
            return Decision(
                Verdict.DENY,
                "sdk: gate mode changed after the client was built, failing closed",
                _text(skill),
                _text(tool),
                (),
                enforced=True,
            )
        try:
            decision = self._gate.evaluate(
                skill,
                tool,
                paths,
                trace=trace,
                args=args,
                refuse=refuse,
                base_dir=base_dir,
                principal_id=principal_id,
                grant=grant,
                session_key=session_key,
                approval=approval,
            )
        except Exception as exc:
            # Enforce-mode log failure lands here: the gate re-raises because
            # it could not write a row. No row can be written now either.
            return self._deny(skill, tool, f"sdk: gate raised, failing closed: {exc!r}")
        if not isinstance(decision, Decision) or not isinstance(
            decision.verdict, Verdict
        ):
            return self._deny(
                skill, tool, "sdk: gate returned no decision, failing closed"
            )
        return decision

    def verify_log(self) -> str:
        head = verify_hash_chain(self._log_path, self._anchor_path, self._checkpoint)
        if type(head) is not str or not head:
            raise ValueError("audit log verify returned no head hash")
        return head

    def throw(self, reason: str = "") -> bool:
        return self._gate.throw(reason)


def may_run(decision: object) -> bool:
    """True when the tool call may run on the host.

    Same rule ``open_authorized_read`` uses: ALLOW, or a decision the gate did
    not enforce. Anything that is not a gate Decision is a no.
    """
    if not isinstance(decision, Decision):
        return False
    if decision.enforced is False:
        return True
    return decision.enforced is True and decision.verdict is Verdict.ALLOW
