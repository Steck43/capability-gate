# PASTE-PACKET - capability-gate BH-130 leftover nits

Sprint 2026-10-25 task 1. Feature branch only. Do not merge to main from this
checkout. Do not push to main.

## Identifiers

| Field | Value |
| --- | --- |
| Branch | `steck43/control-check-cli-nits-clean` |
| Head SHA | `78c5a94651e4cd8085f16737c9a9645546ccbed3` (refresh after this file if the tip moved) |
| Code SHA | `c3308c35e7504a443ec126bf300cbb5ceac045f7` (behavior change) |
| Base SHA | `7f174bdf9daeaf957ed4dde126ee3f3903c9f268` (`main` at branch point; includes S11 merge #133) |
| Draft PR | https://github.com/Steck43/capability-gate/pull/134 (draft; do not merge from this agent) |
| Remote | `origin` (`Steck43/capability-gate`) |

Confirm with `git log --oneline 7f174bdf9daeaf957ed4dde126ee3f3903c9f268..HEAD`.

## Files touched

- `control_check.py` - `--old-profile is not None`; refuse empty/whitespace path (exit 2); mixed `no_new_grants` uses `unmet(req, old)` so UNMET is possible
- `tests/test_control_check.py` - CLI `--old-profile` DENY/exit 3 and empty/whitespace exit 2; mixed UNMET; catalog/tool/isolate/superset pins; scrubbed internal review labels
- `design/required-controls/mutants.py` - 10 added mutants, including `cli old-profile ignored` and `cli old-profile truthy check`
- `design/required-controls/README.md` - mutant claim is the `mutants.py` set; CI plan names `--old-profile`; UNMET/empty-path wording
- `CHANGELOG.md` - `--old-profile` qualifies profile-weakening DENY; Fixed row for empty path and mixed UNMET

## How to verify from the operator PC

This checkout already pushed the branch to `origin` (draft PR #134). From the
operator PC, review then merge later. Never push to `main` from here.

```
git fetch origin steck43/control-check-cli-nits-clean
git checkout steck43/control-check-cli-nits-clean
git log --oneline 7f174bdf9daeaf957ed4dde126ee3f3903c9f268..HEAD
python3 -m pytest -q tests/test_control_check.py
python3 design/required-controls/mutants.py
```

Merge from the PC when Seat A (gate) and floor are green. Do not merge from this agent.

## Proposed STATUS row

| Date | Roof | Item | Status | Pointer |
| --- | --- | --- | --- | --- |
| 2026-10-25 | capability-gate | BH-130 leftover nits (CLI `--old-profile`, mutant honesty) | BRANCH | `steck43/control-check-cli-nits-clean` @ tip of draft PR #134 (code `c3308c3`, base `7f174bd`) |

## Tester ask

Seat A (gate) on the gate, focused on the required-controls CLI:

1. Weakened profile through `--old-profile` -> DENY, exit 3 (not ALLOW).
2. `--old-profile ""` and whitespace-only path -> exit 2, JSON DENY + error, no traceback. Must not be treated as "no old profile".
3. Omit `--old-profile` on an unchanged pair -> still ALLOW, exit 0.
4. Mixed `no_new_grants` + `approval_for` unmet on both sides -> status UNMET, not DROPPED.
5. Confirm `python3 design/required-controls/mutants.py` prints every mutant killed (42/42 at this SHA).

## Fixed vs deferred

Fixed (S3 + cheap S4):

- BH-130-10: empty `--old-profile` fail-open; CLI tests drive `main()`; `cli: old-profile ignored` killed
- Mutant README claim: narrowed to `mutants.py`, and the former strip-proof survivors that had clean tests are now in that set (42/42 killed)
- BH-130-5: mixed `no_new_grants` UNMET
- BH-130-4: CHANGELOG and CI-plan text say profile-weakening DENY is with `--old-profile`
- BH-130-9: internal review labels removed from the lines we touched

Deferred:

- BH-130-11: example-profile warning noise on `execute_code` (still ALLOW; warning is documented)
- BH-130-12: optional `--strict` (warnings -> exit 2). New flag; not cheap, not required for this leftover
- BH-130-6: "runs at load time or in CI" still aspirational (CI wiring is Not done yet)
- Isolation-layer pin `d4275fc`: **not bumped**. Current pin remains `00ef3f9` (floor.yml / `run_full_suite.py` / `test_gate_boundary.py`). No reason in this leftover to move it; this checkout has no sibling clones to prove a pin bump green. Leave the bump for a dedicated pin PR.

## Local proof (this checkout)

- RED: `test_cli_empty_old_profile_exits_2` was exit 0 on `""`; mixed row was DROPPED
- GREEN: `pytest -q tests/test_control_check.py` -> 151 passed
- GREEN: `pytest -q tests/test_control_check.py test_capability_gate.py test_report.py tests/test_run_full_suite_pins.py tests/test_public_text_paths.py` -> 373 passed
- `python3 design/required-controls/mutants.py` -> 42 of 42 killed
- `ruff check` / `ruff format --check` on the touched Python files: clean
- Full `pytest` without sibling clones is not the CI suite (boundary tests need the pins). Floor CI on the draft PR is the green bar.
