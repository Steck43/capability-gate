# Hire gap builds: four small programs on the Phase A client

Four builds and one meter that run the real gate through the Phase A thin
client (`capability_gate_sdk.Client`). Offline, synthetic inputs, no secrets.

One command from the repo root:

    demos/hire/gap/RUN-ALL.sh

`CG_ROOT` defaults to this checkout. `PY` defaults to `python3` with
`requirements-dev.txt` installed (jsonschema is needed by the meter).

| Build | File | What it checks |
|---|---|---|
| Graded agent drill | `training_tuesday.py` | 8 bad plans caught, 0 false blocks |
| Fixed attack set scoreboard | `adversary_scoreboard.py` | 15 attacks, each held; attack set pinned by sha256 |
| Per-recipient token ledger | `token_ledger.py` | 7 accept/refuse cases, hash chain verifies |
| Refuse before the model | `mcp_refuse_wrapper.py` | 6 cases, backend never invoked on a refusal |
| Shadow to enforce meter | `shadow_enforce_meter.py` | schema-valid document, flagged sets identical, risky executed 0 |
| Tests | `tests/test_hire_gap.py` | 15 tests |
| Fail-when-removed mutants | `_mutants.py` + `RUN-ALL.sh` | 10 mutants, each must turn the suite red |

## Limits, stated

- Our code on our machine, on synthetic traffic. Not an independent third
  party and not customer data.
- The gate alone. Nothing here shows a live harness hook calls the gate.
- The refuse wrapper is a JSON-RPC shaped simulation in one process, not a
  live MCP server. Its demo backend records effects and never writes a real
  path.
- The ledger has no currency, no multi-writer locking and one local file. It
  is not billing.
- Scoreboard known gap KG1: a symlink swapped in after the check (TOCTOU) is
  named and not scored. A symlink present at check time is denied.
- The meter never decides promotion. It writes `stay_shadow` and
  `pending-human-review` unless a person passes `--approver` and
  `--decision`.
- Observe mode blocks nothing.
