# Wave 2 test source map

Source baseline: capability-gate `bc02541cbf41979fb546d9fd44279c83913f6684`,
aegis-atoms `5e92ae10ab81ffa6c13fb95e56ca35ed9f98e236` (merged
PR #60), and Hermes runtime
`ccd8deaa6705bd6ca1890584d8f4055fe61227b5`. This is a source map, not a
live-run receipt.

## T8 source questions

| Question | Production node | Test node | Finding |
| --- | --- | --- | --- |
| Rollup function | aegis-atoms `triad_types.py:203::rollup_control`, `triad_types.py:261::combine_control_rollups` | aegis-atoms `tests/test_rollup_population.py:232::test_rollup_invariants_hold_over_population` | The atoms control rollup is deny-overrides and order-independent. `MEASURED-GAP`: no production node rolls gate, atoms, box, judge, and human into one five-layer verdict; `harness/truth-table-enforce-expected.json:1` is only the 96-row enforce oracle. |
| Decision-log verifier | `capability_gate.py:232::_verify_log`, `capability_gate.py:262::verify_hash_chain` | `tests/test_kill_switch.py:161::test_ks_tamper_thrown_row_breaks_chain` | Verifies row hashes, parent links, and sibling witness head/count. It returns the head hash, not the first bad row index. |
| Decision-log replay | `report.py:26::_load_jsonl` verifies before reading | `tests/test_report_verify.py` | `MEASURED-GAP`: report generation consumes verified rows, but no command replays each row through the decider. |
| Layer order | aegis-atoms `__init__.py:680` and `engine.py:1416::apply_judge_phase` | aegis-atoms `tests/test_judge_wiring.py:97::test_pre_tool_order_gate_atoms_box_judge_human`; local boundary `tests/test_gate_boundary.py:383::_run_chain` | Merged plugin order is gate → atoms → optional box → judge → human. The local boundary harness stops at gate → atoms → box. |
| Deadlines | aegis-atoms `judge_slot_sonnet.py:67::JUDGE_PHASE_DEADLINE_S = 10.0`; `adapters/claude_code_hook.py:30::MAX_DEADLINE_S = 14.0` | aegis-atoms `tests/test_judge_wiring.py:279::test_judge_timeout_fail_closed`; `tests/test_cc_adapter.py:234::test_deadline_inf_and_over_cap_clamped` | The judge phase is capped at 10 s, inside the Claude Code hook's 14 s ceiling. Hermes `invoke_hook` at the pinned runtime has no independent deadline. |
| Kill/fault hooks | `capability_gate.py:691::Gate.throw`; judge phase cancellation at aegis-atoms `engine.py:1496` | `tests/test_wave2_offline_scaffolds.py:109::test_t_fail_01_log_layer_death_never_becomes_allow`; aegis-atoms `tests/test_judge_wiring.py:337::test_judge_exception_fail_closed` | Gate halt is a production marker; judge timeout/fault paths escalate and cancel. Other failures use bounded monkeypatch/process seams; no unified cross-layer kill-hook interface exists. |
| `judge_subtracted` | aegis-atoms `engine.py:1416::apply_judge_phase` | aegis-atoms `tests/test_judge_shadow_attestation.py:66::test_shadow_sets_applied_false_and_would_subtract`, `:113::test_apply_sets_applied_true` | True means the subtract-only consumer tightened the floor while apply was armed. A consultation that only computes `judge_would_subtract` leaves it false. |
| Canonical allow | aegis-atoms `engine.py:51::classify_gate_verdict` | aegis-atoms `tests/test_t_comp_01_verdict_matrix.py:80::test_verdict_matrix_row`, `:115::test_canonical_allow_is_exact_allow_string` | Only exact string `allow`, after `Enum.value`, passes. ASK escalates; deny, thrown, malformed, missing, wrong-type, and plain-dict shapes block. |
| Inventory reconciliation | aegis-atoms `tools/build_registry.py`, `.floor/derived.tsv`, `REGISTRY.tsv`, `SHA256SUMS` | aegis-atoms `tests/test_registry.py:19::test_registry_tsv_matches_a_fresh_local_harvest` | The atoms roof checks its derived registry. `MEASURED-GAP`: no command reconciles gate, atoms, box, Hermes doors, and paper rows across roofs. |

## Paper-test locators

Every paper test named in this roof resolves to a test node. External atoms
locators are pinned to `5e92ae10`; local locator syntax and node existence are
checked by `tests/test_source_map.py::test_source_map_nodes_exist`.

| Paper test | Test node | Production / fixture node |
| --- | --- | --- |
| T-COMP-01 | aegis-atoms `tests/test_t_comp_01_verdict_matrix.py:80::test_verdict_matrix_row` | aegis-atoms `engine.py:51::classify_gate_verdict` |
| T-COMP-02 | `tests/test_wave2_offline_scaffolds.py:24::test_t_comp_02_has_96_live_contract_rows` | `harness/truth-table-enforce-expected.json:1` |
| T-COMP-03 | aegis-atoms `tests/test_judge_wiring.py:97::test_pre_tool_order_gate_atoms_box_judge_human` | aegis-atoms `__init__.py:680` |
| T-COMP-04 | aegis-atoms `tests/test_judge_shadow_attestation.py:113::test_apply_sets_applied_true` | aegis-atoms `engine.py:1416::apply_judge_phase` |
| T-COMP-05 | `tests/test_wave2_offline_scaffolds.py:41::test_t_comp_05_rejects_valid_format_wrong_digest` | `paper_contracts.py:27::decision_digest`, `paper_contracts.py:41::receipt_digests_match` |
| T-FAIL-01 | `tests/test_wave2_offline_scaffolds.py:109::test_t_fail_01_log_layer_death_never_becomes_allow` | `capability_gate.py:748::Gate.evaluate` |
| T-FAIL-03 | `tests/test_wave2_offline_scaffolds.py:150::test_t_fail_03_verifier_reports_first_bad_row_index` | `capability_gate.py:232::_verify_log` |
| T-FAIL-04 | `tests/test_wave2_offline_scaffolds.py:124::test_t_fail_04_restart_keeps_kill_switch_thrown` | `capability_gate.py:691::Gate.throw` |
| T-ADV-02 | `tests/test_wave2_offline_scaffolds.py:71::test_t_adv_02_tool_output_cannot_supply_privilege_metadata` | `adapters/agentdojo_adapter.py:28::map_agentdojo_call` |
| T-ADV-03 | `tests/test_wave2_offline_scaffolds.py:88::test_t_adv_03_outside_set_glob_canaries_are_denied` | `adapters/claude_code_hook.py:169::_glob_climbs` |

## Not measured

Live Hermes doors, a live AgentDojo suite, aegisbox execution, judge apply,
layer-order permutations, disk-full tmpfs behavior, Windows ACLs, and a
sanitized benign-day recording remain outside this offline map.
