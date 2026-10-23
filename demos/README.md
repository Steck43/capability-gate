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

Not supported by the code at this commit (listed in `out/summary.json`):
S05, S06, S10, S11, S13, the broken row index for S08 (the gate reports that
the chain is broken, not where) and an alerts count for S01 (the gate has no
alerting). S07 lives in the isolation-layer repo.

Note on S02: the gate does not parse command text. Risky shell commands are
denied because the shell tool is not granted to the skill, and the rule id says
so.

Note on S09: the log store outage is simulated with `chmod 000` on the log
folder, which has no effect when the tests run as root. The expected outage
counts are computed from the windows declared in the scenario file.

A control that raises, or a chain check that fails, gives a FAIL row with the
error in the record, not a traceback.

`scripts/readme_proof.py` writes and checks the Proof section of the top-level
README against `out/summary.json`.
