# A1 — Kill switch (F-073) (2026-10-09)

## Scope measured

Gate-level kill switch on `capability-gate`: `Gate.throw` creates
`{log_path}.halt` and one THROWN row; `Gate.evaluate` materializes paths once,
then denies when the marker exists or is unreadable. Independent review
R4-1 (iterator drain fail-open) is closed. R4-3 stays the documented observe
limit (strict xfail). `always_invoked` stays false.

## Source

Held patch `Grok-Bot-Hub/burn-queue/2026-10-07-proof-build-1/kill-switch.patch`
(sha256 `34315dd8…ccab`) on base `7cbc6eb`, verdict fix-first. Ported to tip
`bcb5783` with:

- path materialization once per evaluate (R4-1)
- absolute log and halt paths at Gate init (R2-3)
- THROWN rows via `record_decision` (keeps F-2/F-3 lock and witness)
- R5-2 pins: EACCES, dangling symlink, halt checked in observe

## Tests

| Suite | Result |
|---|---|
| `tests/test_kill_switch.py` | 13 passed, 1 xfailed (observe limit) |
| Full roof `pytest -q` (local siblings) | kill-switch green; `test_siblings_pinned` red only when local sibling HEADs differ from CI pins (CI checkouts own the pin) |

## NOT measured

- Live Hermes or Claude Code hook calling `Gate.throw` / honouring the marker
  on a running agent process.
- Observe mode blocking while halted (documented limit).
- Operator CLI to throw the switch (must construct a Gate or create the marker).
- `always_invoked` (stays false).

## Moves paper claim

None for the unified-policy boundary centerpiece. Optional standing note: a
gate-level kill switch exists and is tested; it is not a live-hook prove.
