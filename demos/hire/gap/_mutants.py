"""Fail-when-removed mutants for the hire gap tests. HIRE_GAP_MUTANT=<name> breaks one control
before the tests import the builds; RUN-ALL.sh checks that each one turns the suite red."""

import contextlib
import json
import os

from _cg import cg, sdk

MUT = os.environ.get("HIRE_GAP_MUTANT", "")


def apply():
    if MUT == "hollow-gate":
        cg.Gate.evaluate = lambda self, skill, tool, paths=(), **k: cg.Decision(
            cg.Verdict.ALLOW, "MUTANT", str(skill), str(tool), (), enforced=True
        )
    elif MUT == "may-run-always":
        sdk.may_run = lambda d: True
    elif MUT == "kill-noop":
        cg.Gate.throw = lambda self, reason="": True
    elif MUT == "verify-noop":
        sdk.Client.verify_log = lambda self: "f" * 64
    elif MUT == "ledger-no-cap":
        import token_ledger as tl

        orig = tl.Ledger.spend

        def spend(self, r, a, ref, d):
            cap = self._caps.get(r)
            if cap is not None:
                self._caps[r] = 10**12
            try:
                return orig(self, r, a, ref, d)
            finally:
                if cap is not None:
                    self._caps[r] = cap

        tl.Ledger.spend = spend
    elif MUT == "ledger-repeat-stepback":
        import token_ledger as tl

        orig = tl.Ledger.step_back

        def sb(self, ref):
            if ref not in self._open and ref in self._used:
                self._open[ref] = ("alice-agent", 0)
            return orig(self, ref)

        tl.Ledger.step_back = sb
    elif MUT == "ledger-verify-noop":
        import token_ledger as tl

        tl.Ledger.verify = lambda self, return_rows=False: (
            [] if return_rows else "0" * 64
        )
    elif MUT == "wrapper-backend-first":
        import mcp_refuse_wrapper as mw

        orig = mw.Wrapper.handle

        def handle(self, raw):
            # The mutant calls the backend before the gate, ignoring bad input.
            with contextlib.suppress(Exception):
                p = json.loads(raw)["params"]
                self.backend_calls += 1
                self.backend(p["name"], p.get("arguments") or {})
            return orig(self, raw)

        mw.Wrapper.handle = handle
    elif MUT == "meter-validate-noop":
        import shadow_enforce_meter as sem

        sem.validate = lambda doc: None
    elif MUT == "meter-self-promote":
        import shadow_enforce_meter as sem

        orig = sem.run_window
        sem.run_window = (
            lambda approver="pending-human-review", decision="stay_shadow": orig(
                "auto", "promote_enforce"
            )
        )
    elif MUT:
        raise SystemExit(f"unknown mutant {MUT}")
