# Required controls: old vs new policy check

`control_check.py` compares an old and a new allowlist against a profile of
required controls and refuses a change that leaves one unmet. It is an
automated policy diff that flags widening, in the spirit of a "no new access"
check such as AWS IAM Access Analyzer `CheckNoNewAccess`. It is not edit
protection: agent platforms already guard their config files (hooks that
watch config changes, signed policy, admin requirements). This check answers
a different question: did this edit drop a control the deployment depends on?

## Inputs

- `controls/catalog.yaml`: seed rows from eight frameworks (OWASP LLM Top 10
  2026, MITRE ATLAS 2026.09, NIST AI RMF 1.0, EU AI Act, ISO/IEC 42001:2023,
  ISO/IEC 27001:2022, NIST CSF 2.0, EU Cyber Resilience Act). Each row holds
  key, framework, edition, control_id, the published title, binding
  (`mandatory`, `advisory`, `advisory_as_selected`), grade and an https
  source. No paraphrase text. `mandatory` means law within its scope: EU AI
  Act Art. 14 binds high-risk AI systems from 2027-12-02 (Annex III) and
  2028-08-02 (Annex I), and EU CRA Annex I applies from 2027-12-11. The
  catalog header gives the detail.
- A profile (`controls/profile.example.yaml`): the controls a deployment
  requires, each with a level (`mandatory` or `adopted`) and obligations. A
  catalog row bound as mandatory law must be required as mandatory.
- Both files need `version: 1` as an integer (`true` and `1.0` are refused)
  and refuse any top-level key other than `version` and `controls` or
  `requires`. A misspelled key is an error, never a silent default.
- The old and new policy, read with the strict YAML loader and `load_policy`.

## Obligations

| Obligation | Met when |
| --- | --- |
| `approval_for: [tools]` | each tool is in `require_approval`, or no skill grants it (an approval for an ungranted tool is inert, since `_decide` checks the grant before approval). A granted tool in `isolate` counts as unapproved, since a tool cannot be in both lists; require it under `no_new_grants` instead |
| `never_granted: [tools]` | no skill grants the tool |
| `no_new_grants: true` | the new policy adds no skill, no tool to a skill, no path glob to a skill, drops no approval for a tool it still grants, and takes no tool it still grants out of `isolate` (that moves the call from the box to the host); a changed glob counts as new even when narrower |

## Verdicts

Per control: `KEPT` (met in new), `DROPPED` (met in old, not in new),
`UNMET` (met in neither, including a mixed row that carries `no_new_grants`
plus another obligation that fails on both sides). An unmet mandatory control
is DENY and an unmet adopted control is ASK. With `--old-profile`, a required
control removed from the profile, lowered from mandatory to adopted, or kept
with fewer obligations or tools than before is DENY. The overall verdict is
the strictest.

CLI exit codes: 0 ALLOW, 1 ASK, 3 DENY, and 2 for any error while loading or
checking (malformed YAML, duplicate keys, unknown control, empty profile,
an empty or whitespace `--old-profile`, unknown obligation, bad catalog row,
missing file, or any other exception), which also prints DENY. Exit 1 means
ASK: a person decides. A CI job should fail on any exit code other than 0,
so a crash outside the check can never pass as ASK.

The report also carries `warnings`: an `approval_for` tool that neither
policy grants. Such an obligation is met by default, so a typo in a tool name
would otherwise pass unseen. A warning does not change the verdict.

## Running it

Run from the repository root, since the catalog and profile defaults are
relative paths. `HERMES_HOME` must be set, because the allowlist globs use
it and an unresolved variable is a load error (exit 2).

```
python control_check.py old-allowlist.yaml allowlist.yaml \
  --profile controls/profile.example.yaml --old-profile old-profile.yaml
```

The check runs at load time or in CI. `Gate.evaluate` does not call it, so
decision latency and the decision path are unchanged.

## Tests (`tests/test_control_check.py`)

1. `test_unchanged_policy_allows`
2. `test_granted_tool_dropped_from_approval_denies`
3. `test_same_drop_under_an_adopted_control_asks`
4. `test_approval_dropped_for_a_tool_no_skill_grants_allows`
5. `test_new_tool_grant_is_widening`
6. `test_new_path_glob_is_widening`
7. `test_new_skill_is_widening`
8. `test_changed_glob_counts_as_new_even_when_narrower`
9. `test_granting_a_never_granted_tool_asks_or_denies_by_level`
10. `test_control_unmet_before_and_after_is_unmet_not_allowed`
11. `test_narrowing_allows`
12. `test_property_narrowing_is_never_widening` (40 seeds)
13. `test_property_any_widening_is_flagged` (40 seeds)
14. `test_profile_dropping_a_required_control_denies`
15. `test_profile_downgrading_a_control_denies`
16. `test_profile_raising_a_control_allows`
17. `test_bad_profile_is_a_policy_error` (12 shapes)
18. `test_bad_catalog_row_is_a_policy_error` (5 shapes)
19. `test_duplicate_catalog_key_is_a_policy_error`
20. `test_profile_yaml_with_a_duplicate_key_is_refused`
21. `test_catalog_covers_each_framework`
22. `test_mandatory_rows_are_the_eu_laws`
23. `test_example_profile_holds_on_the_example_allowlist`
24. `test_gate_does_not_import_the_check`
25. `test_cli_exit_codes` (ALLOW, ASK, DENY)
26. `test_cli_malformed_policy_exits_2` (4 shapes)
27. `test_cli_missing_file_exits_2`
28. `test_profile_with_weakened_obligations_denies`
29. `test_same_profile_on_both_sides_allows`
30. `test_approval_for_a_tool_no_policy_grants_is_a_warning`
31. `test_tool_taken_out_of_isolate_is_widening`
32. `test_tool_put_into_isolate_allows`
33. `test_bad_catalog_top_level_is_a_policy_error` (3 shapes)
34. `test_cli_any_load_error_exits_2_not_ask` (3 shapes)
35. `test_cli_old_profile_weakened_denies`
36. `test_cli_empty_old_profile_exits_2` (empty, spaces, tab)
37. `test_mixed_no_new_grants_unmet_in_both_is_unmet_not_dropped`
38. `test_empty_catalog_list_is_a_policy_error`
39. `test_catalog_row_must_be_a_mapping`
40. `test_catalog_root_must_be_a_mapping`
41. `test_ungranted_tool_leaving_isolate_is_not_widening`
42. `test_profile_with_stronger_obligations_allows`

Each mutant in `mutants.py` (a clause removed or inverted) turns at least
one of these red. Near-equivalent catalog checks that a later fail-closed
path would still catch are not claimed here. `python
design/required-controls/mutants.py` runs the set and prints which were
killed.

## Not done yet

- CI wiring: run `control_check.py` on a pull request with the base branch's
  allowlist as the old policy and the head's as the new one, the base
  profile as `--old-profile`, and fail on any exit code other than 0. That
  is a separate CI change.
- The profile is an example. Which controls a deployment requires, and at
  what level, is an owner decision.
- Obligations cover tool grants, approvals, isolation and path globs.
  Controls that are about logging, the kill switch or checkpoints have no
  obligation type yet.
- The catalog is read once, not compared old vs new. A pull request that
  rebinds a mandatory row to advisory would let that control be required as
  adopted, so its drop reads ASK, not DENY. The CI job should load the
  catalog from the base branch.
