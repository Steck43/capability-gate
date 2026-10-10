# Wave 2 test source map

Hermes runtime source is pinned to `ccd8deaa6705bd6ca1890584d8f4055fe61227b5`. This map names code and gaps; it is not a live-run receipt.

| T8 question | Source of record | Current finding |
| --- | --- | --- |
| Rollup function | No single stack rollup function found | `MEASURED-GAP`: `harness/truth-table-enforce-expected.json` supplies the 96-row enforce oracle, but no production function computes a five-layer final verdict. |
| Decision-log verifier | `capability_gate.py::verify_hash_chain` → `_verify_log` | Checks parent links plus sibling witness head/count. It returns the head hash; it does not report the first bad row index required by T-FAIL-03. |
| Decision-log replay | No dedicated replay command found | `report.py` verifies before reading, and tests mutate/recheck logs. `MEASURED-GAP`: no CLI replays rows through the decider. |
| Layer order | `tests/test_gate_boundary.py::_run_chain` | Contract harness order is gate → atoms → box. Judge application is inside atoms; live permutation testing is not present. |
| Deadlines | `adapters/claude_code_hook.py::_deadline_s`; atoms `action_gating.py::_HANDOFF_TIMEOUT_S`; isolation `scripts/b1-prove.py` | Claude Code default 5 s, capped 14 s; atoms handoff 5 s; box prove contains local waits up to 120 s. No single end-to-end deadline budget exists. |
| Kill/fault hooks | `Gate.throw`; pytest monkeypatches; process boundaries in `b1-prove.py` | Gate kill marker is production code. Other layers have test injection or process-kill seams, but no unified test-only kill-hook interface. |
| `judge_subtracted` | atoms `engine.py` result field and final assignment | Means an applied subtract mutated the floor: `would_subtract and judge_apply_verdict`. It does not mean judge consultation alone. |
| Canonical allow | atoms `engine.py` gate-composition branch; `tests/test_t_comp_01_verdict_matrix.py` | Only exact string `allow`, after reading `Enum.value` when present, falls through. Other shapes block or escalate. |
| Inventory reconciliation | atoms `tools/build_registry.py`, `.floor/derived.tsv`, `SHA256SUMS`; capability-gate has no registry | Atoms has derived-inventory tooling. `MEASURED-GAP`: no cross-roof command reconciles gate, atoms, box, Hermes doors, and paper rows. |

## Offline Wave 2 starts

- T-COMP-02: 96 expected enforce rows, all marked `LIVE` as plan rows and `measured: false`.
- T-COMP-05: `paper_contracts.py` recomputes the gate digest and compares both receipt digests; this helper is not yet wired into isolation-layer `accept_bound_receipt`.
- T-FAIL-01: injected gate log-layer death raises and does not create the target.
- T-FAIL-03: strict expected failure pins the missing first-bad-row index.
- T-FAIL-04: a new Gate instance denies 20/20 calls while the same `.halt` marker remains.
- T-ADV-02: AgentDojo mapping discards output-carried privilege metadata before the Hermes hook boundary.
- T-ADV-03: the five K2b outside-set Glob canaries are classified as parent-climbing patterns.

## Not measured

Live Hermes doors, a live AgentDojo suite, aegisbox execution, judge apply, layer-order permutations, disk-full tmpfs behavior, Windows ACLs, and a sanitized benign-day recording.
