# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Plugin bundle version `0.1.1` (tag `plugin-v0.1.1`): same SLSA attestation path as `plugin-v0.1.0`, zip includes `__init__.py` plus the kill switch tip. Verify: `gh attestation verify capability-gate-plugin-0.1.1.zip --repo Steck43/capability-gate`.
- Kill switch. `Gate.throw` creates a marker beside the decision log (the log path plus `.halt`) and appends one THROWN row to the hash chain; a second throw adds no row. `Gate.evaluate` materializes paths once, then reads the marker before the allowlist, so a running gate denies the next call with no restart, and a marker it cannot read is a deny. A call that names the marker is denied with the switch on or off. Only a human removing the marker clears it. Observe mode still blocks nothing (`test_kill_switch_blocks_in_observe`, strict expected failure). `tests/test_kill_switch.py` is gate-level only: it does not show the live hook calls the gate.
- Claude Code adapter (`adapters/claude_code_hook.py`), Windows. The decider runs as a `PreToolUse` hook. Allow is exit 0 with no output, so Claude Code's own permissions still apply; every deny and every error is exit 2 with a reason, under a 5 s self-deadline. Calls carry no skill label and are judged as `UNLABELED`, which the allowlist must grant by name. A `PostToolUse` twin flags a call whose input changed after the check. `tests/test_cc_adapter.py` pins each branch.

### Fixed

- Claude Code adapter S3 close (red-team B-P2-R2-1 / R2-2 / R3-1): Glob patterns that climb via character-class or brace obfuscation are denied; a tool missing from the closed path schema is denied even when granted; `CG_CC_DEADLINE_S` rejects non-finite values and clamps to 14 s so a stalled check cannot outrun Claude Code's hook timeout.
- Deny secret-canary.txt even when a grant glob covers its directory (FL-3 canary).
- Fail-closed denials that never reach `Gate.evaluate` (unresolved mode, failed plugin load, outer adapter exception) still write a decision row and update the `.witness` via shared `record_decision` (2026-09-28 zero-row incident).
- The plugin release zip includes `__init__.py` so the Hermes hook entry point `register` is present in the bundle (D-3).
- Two writers cannot fork the decision-log chain: read-head and append run under an exclusive `.lock` file (F-3).
- Config and allowlist YAML refuse duplicate keys and merge keys (`<<`) via `load_yaml_mapping` (permissive-YAML / D-4 family). PyYAML's default last-key-wins load is no longer used for those files.
- A short audit-log write rolls back the torn bytes and raises (F-2) instead of leaving a partial JSONL line.
- `report.py` runs `verify_hash_chain` before suggesting grants (G-3), and reads tools from `UNLABELED`, `*`, and every named skill (G-report-star-only).
- Observe-mode errors that used to raise before a log line was written (including a lone UTF-16 surrogate in content) now deny inside the evaluate boundary and still record a decision (H1-1). The adapter no longer fail-opens on an unrecorded exception in observe.
- Decision-log truncation and whole-log deletion fail closed. A sibling `.witness` file stores the head hash and record count; `verify_hash_chain` checks it on every append. Cutting the log from 4 lines to 2, or deleting the log while the witness remains, raises the same way rewriting an older line does (#32).
- Issue #33 shapes stay denied on the closed argument schema: list-valued paths, alternate keys alone, non-dict args, and blank/`*` skill names resolving to `UNLABELED` (not the `*` grant) are pinned by `tests/test_issue33_shapes.py`.
- The adapter opens `config.yaml` and the allowlist without following a symlink, and refuses either file when it is not a regular file owned by the current user or when group or others can write it (`0644` loads; `0664` and `0666` do not). A refused config resolves to enforce and blocks every call until it is fixed. On Windows a reparse point is refused; the owner and ACL check is not done there yet. A write tool (`write_file`, `patch`) aimed at the gate's own config, allowlist, decision log, witness, or plugin folder is denied whatever the grant says. Repairing a refused config is a manual step outside the agent; see README.
- A relative path is resolved against the folder Hermes itself will use for the call, read from Hermes's own `_resolve_base_dir`, and the decision log records the absolute path. A relative path with no usable base folder is denied. Before, it was resolved against the process working directory, which can differ from where Hermes writes. `Gate.evaluate` takes `base_dir`; a direct caller that passes a relative path without one is now denied.
- The Hermes adapter reads each call against a closed argument schema. A `patch` call's V4A header lines (Add, Update, Delete, Move) are read as paths whatever its mode, so a granted `patch` can no longer write a file its headers name outside the grant. A tool with no schema, an argument its schema does not list, arguments that are not a dict, a path argument that is not a string, a patch mode other than `replace` or `patch`, and a patch body with no file header are denied, and the denial is logged in both modes. Schemas cover `read_file`, `write_file`, `patch`, `search_files`, `skills_list`, `execute_code`, `web_search` and `terminal`; any other tool is denied until it has one, and a new argument Hermes adds is denied until its schema lists it. `search_files` `target` is no longer read as a path.
- A call with no skill resolves to `UNLABELED` and is denied unless the allowlist grants `UNLABELED` by name. It used to fall to the `*` grant, and Hermes 0.18 sends no skill, so that was every live call. An allowlist that relied on `*` for hook traffic needs an `UNLABELED` entry. A labeled skill the allowlist does not name is still denied.
- Path matching resolves the real path before it matches, and a request path that needs `~` or `$VAR` expansion is denied. A grant rooted at a symlink still matches its own files. `S1` moves from FALSE-ALLOW to CAUGHT, so the Stage-1 tally is 8 / 7 / 4 / 0. `S4` (`/proc/self/root`) is denied as a side effect. A hardlink to an off-grant file and a swap between the check and the open stay open as strict expected failures.
- Audit JSONL is hash-chained. Rewriting an older line fails closed; the old line-count test stayed green on that rewrite.
- Adapter extracts every path argument. A notes path plus `target=/etc/passwd` is denied.

### Changed

- CI checks out `aegis-atoms` at `41b6e83` (merge of aegis-atoms #51, decision digest and box ticket) and `isolation-layer` at `a27c8ee` (merge of isolation-layer #24, `box_entry` bind). `test_one_write_needs_three_receipts` is a normal test. Clearing it in CI is a receipt contract, not a jailer proof. `always_invoked` stays false.
- CI checks out `aegis-atoms` at `46db989` (merge of aegis-atoms #49, `gate_decision` on `evaluate_tool_call`), up from `8074e7b`. `floor.yml` and the boundary test's pin move together. `test_deny_decision_makes_atoms_block` is a normal test.
- README Status names the author profile so a stranger can click once from this roof to `github.com/Steck43`.
- README Figure 1 is the dest-true SVG. The box sits between floor and judge. Mermaid stays the sketch. This roof is the allowlist baseline of the floor. The atom plane is a sibling roof in the same plane.
- README and Stage-1 note say written-up remedy, not a venue claim.

### Added

- `tests/test_gate_boundary.py` is a strict expected failure (`xfail(strict=True)`) on three named misses until they clear: atoms records the gate decision it read, the box echoes the per-call ticket atoms issued (two calls must get two tickets), and the box returns a prove-shaped receipt bound to this call, whose dropbox hash is the content argument handed to the box. Clearing them in CI is a receipt contract, not a jailer proof. CI checks out `aegis-atoms` and `isolation-layer` at pinned commits beside this roof and runs pytest from this roof only, so the expected failure is those misses and not a missing checkout. Sibling presence and loading have their own test.
- Adapter `_resolve_skill` reads a real Hermes skill field when one is present and otherwise stays `*`. Hermes 0.18.0 still has no skill on `pre_tool_call`. D15 remains NON-TRANSFER on the live dispatch.
- Gate JSONL writes fail closed on unknown keys. Optional `SITTING_RUN_ID` becomes `run_id`.
- Stage-1 case `S1`: in-grant symlink to an off-grant `.ssh`-shaped target. Expected deny, gate ALLOW, matrix FALSE-ALLOW. Tally is 7 / 8 / 4 / 0 (19 cases, 15 deny-expected). Counts are derived from the harness sets. The decide path is unchanged; `realpath` is not the written-up remedy.
- `harness/CASES.md` is generated from those same sets. `tests/test_cases_table.py` fails if a human retypes the counts.
- D15: the same nineteen cases through the live `pre_tool_call` hook (`harness/d15_hermes_faithful.py`). Grade is NON-TRANSFER because the adapter resolves skill as `*`. Public CI does not install Hermes to unskip adapter tests.
- §8.2 distinguish: after S1 ALLOW, reopen by the name given still ALLOWs; the resolved target DENYs (`tests/test_s1_distinguish.py`).
- Alias class S2–S5 (hardlink, junction, `/proc/self/root`, bind-mount) as their own ids. Skip only if the OS refuses the alias. They do not change the Stage-1 tally.
- Plugin-not-loaded liveness and FIG-1 (`evaluate` does not call the box).
- Craft jobs call `.floor/craft/empty_range.py` instead of an inline BASE==HEAD bash.
- Stage-1 insufficiency harness in-tree. `tests/test_harness_tally.py` asserts cases by id. `REPRODUCE.md` is the cold-clone path. The `plugin-v0.1.0` DOI tarball predates this kit.
- `doi` on CITATION.cff: `10.5281/zenodo.22018053` (version) and `10.5281/zenodo.22018052` (concept).

### Fixed

- Scheduled and workflow_dispatch craft jobs skip when BASE equals HEAD instead of exiting 3 on an empty range. Unresolvable BASE still exits 3.
- First push of a new branch resolves craft BASE to the origin default, so required craft jobs do not fail on an all-zero `github.event.before`.
- Test fixtures no longer carry the author's home directory. `test_report.py` used a real home path as sample data and now uses a neutral one under `/home/agent/`. A home directory is not a credential, so `gitleaks` was green on it; the estate publish gate treats host paths as their own class. A changelog that quotes the removed string republishes it, so this entry names the change without reproducing the path.

### Added

- Named empty-diff BREAK: CI job `craft (empty-diff)` runs `.floor/craft/empty_diff_gate.py`. An empty `base...head` range fails. `changelog_gate` skip-green on non-user-facing ranges is a different job and is not this BREAK. The job runs on pull requests only: on push, schedule and workflow_dispatch the base resolves to `origin/main`, which on a push to main is head, so the range is empty by definition rather than by defect. Its selftest carries a forced-red case and a must-not-fire case.
- Senior craft floor: craft (voice), craft (changelog), craft (comments) required CI jobs.
- Dev container pinned by digest, with pre-commit, ruff, and checksummed gitleaks 8.30.1 so a Codespace arrives with the local floor wired.
- `.gitattributes` so text files stay LF and Windows scripts stay CRLF.
- Weekly Dependabot for GitHub Actions and pip, with a 7-day cooldown. Dependabot PRs still pass the floor; no bypass actor.
- SECURITY.md. Reports go through GitHub private vulnerability reporting, not a public issue.
- Workflow lint job: zizmor (SHA-pinned) plus actionlint 1.7.12 with a baked checksum.
- CITATION.cff so GitHub can render a cite button. DOI left blank until Zenodo mints one.
- `.zenodo.json` so a tagged release does not let Zenodo guess the record.
- OpenSSF Scorecard workflow, SHA-pinned, `publish_results` on. First score is a baseline.
- Versioned Hermes plugin bundle: `scripts/build_plugin_bundle.py` plus workflow `plugin-bundle` (attest-build-provenance v2.4.0, GitHub Release on `plugin-v*` tags). Not a wheel. Not GitHub's source zip.

### Changed

- README leads with the unbroken thought-to-action line and drops the supervisory observe order. The Why section is unchanged.
- Floor push trigger is `main` only, with a concurrency group that cancels in-progress runs.
- Craft jobs resolve BASE from the PR base SHA or `github.event.before`. Empty range exits 3 instead of passing on nothing. Root-commit fallback removed.

### Fixed

- Tests job no longer swallows a failed `pip install -e .`.
- Every floor job now has `timeout-minutes: 10`.
- Do not enable `setup-python` `cache: pip` on roofs without `requirements.txt` or `pyproject.toml`. The cache lookup fails the job.
