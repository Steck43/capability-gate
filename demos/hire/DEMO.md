# Hire demo: allow, deny, kill switch, fail closed, forge reject

Four commands, no network, no secrets. Each runs the real gate
(`capability_gate.py`) on a throwaway folder and exits 0 only when every
expected outcome held.

```
python demos/hire/hire_demo.py --out out/hire     # allow / deny / kill / fail closed / verify
python demos/hire/forge_audit.py --out out/hire   # rewrite a log row, verify rejects
python claimgate/claimgate.py check               # claims lint; the red fixture must fail
python demos/hire/pins.py --out out/hire          # every fail-when-removed mutant goes red
python demos/hire/decision_record.py demo --out out/hire  # CISO record: real accepts, forged rejects
```

`make hire-all` runs the five.

## What each shows

| Step | Shows | Claim id |
|---|---|---|
| 1 ALLOW | a granted tool on a granted path is allowed and the host runs it | |
| 2 DENY | tool not granted, path outside the grant, canary file, `.env`: denied, not run | CG-DENY-* |
| 3 KILL | after `throw`, every tool (granted, ungranted, unknown) is denied with no restart; `executed_after_kill = 0`; one THROWN row plus one DENY row per call | CG-KILL-DENIES-ALL, CG-KILL-LOGGED-CHAIN-VERIFIES |
| 4 FAIL CLOSED | malformed allowlist refused at load; an error inside `evaluate` is a logged DENY; a removed log folder denies a granted call and is not re-created | CG-FAILCLOSED-* |
| 5 VERIFY | the hash chain verifies after the kill; head and row count printed | CG-KILL-LOGGED-CHAIN-VERIFIES |
| 6 OBSERVE | the same denied call in observe mode is logged with `enforced: false` and the host would run it | CG-OBSERVE-LOGS-ONLY |
| record | a decision record bound to the DENY row's receipt is accepted; a missing receipt, each forged field (also rehashed), an expired record and a rewritten log are rejected | CG-DECISION-RECORD-BOUND |
| forge | row rewrite, last-row rewrite, delete, truncate, re-chain, re-chain plus witness, insert: each rejected, append refused, first broken row named | CG-FORGE-REJECTED, CG-FORGE-NAMES-ROW |

## Limits, stated

- This is the gate alone. It says nothing about whether a live harness hook
  calls it (claim CG-LIVE-HOOK-COVERAGE is PLANNED).
- Observe mode blocks nothing.
- The decision record is checked after the fact; the runtime gate does not
  read it, so approve-then-run on the live path is not built
  (CG-DECISION-RECORD-AFTER-THE-FACT is PARTIAL).
- `shadow_enforce_metrics.schema.json` is a template only; no command emits
  it yet (CG-SHADOW-ENFORCE-SCHEMA).
- An attacker who rewrites the log, witness and anchor in one folder passes
  verification. With the anchor outside the log folder the same rewrite is
  rejected (`forge_audit.py` prints both rows); the signed checkpoint is the
  stronger root.

## ClaimGate is not Gate.evaluate

`Gate.evaluate` decides tool calls at run time. ClaimGate
(`claimgate/claimgate.py`) is CI on claims: every row in
`claimgate/claims.yaml` has `claim_id, text, status, enforcement_path,
evidence` and, at REAL, `pins` naming mutants in `demos/hire/mutants.yaml`.
A status above what resolves is OVERREACH and the tests job fails
(`tests/test_claimgate.py::test_repo_claims_file_is_green`). The red fixture
`claimgate/fixtures/red-overreach.yaml` stays red on purpose.

## Fail-when-removed pins

`demos/hire/mutants.yaml` lists one mutant per control the demo asserts. Each
deletes or flips the control in a scratch copy and must turn its tests red
(`tests/test_hire_pins.py::test_mutant_is_killed`). The working tree is never
edited.
