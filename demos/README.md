# Demos on synthetic traffic

`make demo-all` runs every scenario in `demos/scenarios/` against the real gate
(`capability_gate.py`, and for S09 the real Claude Code hook as a subprocess),
prints a summary table and writes `out/summary.json` plus one record per
scenario under `out/runs/`. `make demo-test` runs the same scenarios as
pytest assertions, with a changed seed, a determinism check and one mutation
check per scenario (the control is removed and the scenario must go red).

All traffic is synthetic and seeded (`random.Random(seed)`); the same seed gives
the same events (`events_sha256` in each record). Nothing touches the network.
Paths live in a temp sandbox that is removed after each scenario.

Each YAML file has a `traffic:` block (what to generate) and an `expect:` block
(the assertions). Expected values may be numbers or sums over traffic counts.

| Scenario | Control |
|---|---|
| S01 baseline benign | allowlist, every call logged, chain verifies |
| S02 risky command | tool grants; each risky call denied with the rule expected for its kind (tool-not-granted or path-outside-allowlist), none executed |
| S03 allow / deny / ask | allowlist, path globs, require_approval |
| S04 kill switch mid run | halt marker; every call after the throw is denied |
| S08 receipt chain tamper | hash chain, witness; edit, truncate and delete are detected and the next append is refused |
| S09 gate outage | hook fails closed while the policy store or log store is down |
| S12 shadow vs enforce | observe mode records the same decisions, enforce blocks |
| S14 isolate route | isolate verdict; each call goes through the plugin hook to the stub box door (`real: false`), each planted box outcome blocks with its own message, none run on the host |

Not supported by the code at this commit (listed in `out/summary.json`):
S05, S06, S10, S11, S13, the broken row index for S08 (the gate reports that
the chain is broken, not where) and an alerts count for S01 (the gate has no
alerting). S07 lives in the isolation-layer repo.

Note on S02: the gate does not parse command text. Risky shell commands are
denied because the shell tool is not granted to the skill, and the rule id says
so.

Note on S14: the box door is the isolation-layer stub (`sandbox-demo route`),
so every S14 row is STUBBED. The run builds it with cargo from
`../isolation-layer`, or `ISOLATION_LAYER_ROOT`, or uses the built binary
named in `CG_ISOLATE_DOOR`. With no door, S14 is a FAIL row. The planted box
outcomes are clear, suspect, failed, hash lie, malformed and oversize results,
a door that is down, a replayed receipt and a kill switch thrown while the
task is in the box. `make demo-isolate` runs S14 alone. A door command
passes the state folder as its own argument, `--state DIR`; the route
refuses `--state=DIR`, because that argument is not an absolute path.
S14 does not run isolation-layer `scripts/box_entry.py`, so its
`replay_refused` and `reuse_refused` counts come from the gate route's receipt
checks against the stub door, not from box_entry's spent store. The boundary
test `test_one_write_needs_three_receipts` in `tests/test_gate_boundary.py`
checks that store at the pinned isolation-layer commit: the same box ticket
handed to `box_entry.run` a second time is refused.

Note on S09: the log store outage is simulated with `chmod 000` on the log
folder, which has no effect when the tests run as root. The expected outage
counts are computed from the windows declared in the scenario file.

A control that raises, or a chain check that fails, gives a FAIL row with the
error in the record, not a traceback.

`scripts/readme_proof.py` writes and checks the Proof section of the top-level
README against `out/summary.json`.
