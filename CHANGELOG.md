# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Leak scan for private names and personal paths before they merge. `.gitleaks.toml` extends the default gitleaks rules with Windows and POSIX user-home paths and private IPv4 ranges. `scripts/leak_denylist_scan.py` checks the same shapes plus a list of names that lives outside the tree (the `LEAK_DENYLIST` repo secret, or an untracked local file under `.git/info`), so the list itself is never published. A name matches as a case-insensitive substring, so a name glued to other text still hits; an entry can be a regex instead. Pre-commit checks the lines a staged change adds. CI runs the scanner from the default branch rather than from the change, checks each commit in the range on its own plus its message, and checks the pull request title and body; on a push to main the range starts at the previous tip. CI fails closed when the list is not set or the range is empty. File names that git quotes are unquoted, and a diff header the scanner cannot parse fails the run. The current tree still has known hits, so CI does not yet scan the full tree. Known gaps: non-UTF-8 text, binary files, file names themselves, `~` and environment-variable home paths, forward-slash Windows paths, other IP address forms, and commits made with `--no-verify` until CI sees them. `tests/test_leak_scan.py`.
- Hook behavior tests (`tests/test_hook_behavior.py`) run the Claude Code hook script through its `main()` and the Hermes plugin through `register()` and the `pre_tool_call` it registers. Each must deny an off-grant read, allow an in-grant read, and deny when `Gate.evaluate` raises. These are the wiring control.
- Wiring source check (`tests/test_live_wiring.py`, `tests/wiring_manifest.json`), a fast hint beside the behavior tests. It requires `main()` to reach `_pre`, `register()` to bind `pre_tool_call`, and each hook to assign `gate.evaluate` on its straight-line path to a name a later `if` reads as `.verdict`. Calls after an unconditional return, raise, or process exit, and calls under a constant guard, do not count. It cannot see a rebound gate or an error handler that allows; the behavior tests catch those. The descriptor-bound read is a pending entry held as a strict expected failure (`raises=AssertionError`), and the read binding cannot be dropped from the manifest without moving into the wired entries.
- Known-answer test linter (`scripts/kat_lint.py`, pre-commit and CI). KAT files are found recursively and case-insensitively: names like `test_k*.py` or containing `kat`, a `# KAT` comment, or a test that names a `receipts/` path. In those files it rejects any `pytest.fail` (under any import alias) and any `raise AssertionError`, and requires each test to reach the gate on its straight-line path, directly or through a same-file helper or fixture, before any return or raise. Constant-guarded and unreachable calls do not count. It also rejects `assert` on a constant false value, `getattr(pytest, ...)`, imperative `pytest.skip` or `pytest.xfail` outside a platform check, and an unconditional skip mark. A call to `.evaluate` or `.throw` counts only on a gate: a `Gate(...)` result, a same-file fixture or helper that returns one, a parameter named after such a fixture or annotated `Gate`, or a name assigned from those. In every test file, KAT or not, it rejects `xfail(strict=False)` and imperative `pytest.xfail`, which defeat strict xfail. `tests/test_kat_lint.py`.
- `pytest.ini` sets `xfail_strict = true`, so an expected failure that starts passing fails the run instead of hiding a fix or a broken test, and turns `SyntaxWarning` into an error. No existing expected failure passes under the strict setting.
- Floor config test (`tests/test_floor_config.py`). It fails when `xfail_strict` or the `SyntaxWarning` error filter is turned off, when a guardrail CI job or step (gitleaks, the name and path scan with its title and body step, the KAT linter, the tests) is removed from `floor.yml`, when the scan stops reading the denylist secret, or when the local leak and KAT hooks or the custom gitleaks rules are removed. Turning a guardrail off now needs this file changed in the same review.
- The floor reruns when a pull request title or body is edited (`pull_request` types include `edited`), so the title and body leak scan reads the current text, not the text at the last push. `tests/test_floor_config.py` pins the trigger list.
- The floor config test checks effect, not only presence. A guardrail job or step that is skipped (`if: false`), soft-failed (`continue-on-error`, `|| true`, `exit 0`, `set +e`), fed `PYTEST_ADDOPTS`, or loads the leak scanner from the change instead of main fails the test, and comment lines no longer count toward a match. `pytest.ini` may not set `addopts` or relax the `SyntaxWarning` error filter with a later entry.
- A guardrail job may only use the commands, actions, environment keys, and shell that the floor lists. A workflow, job, or step mechanism that can change pytest's arguments, the process environment, the module search path, or stop-on-error is rejected, including shell and package variables, unpinned actions, expressions inside `run`, and a script the step calls. No `shell` key, and `bash -e` or `bash -eo pipefail`, stay allowed. Job display names are unique and cannot copy a guardrail name.
- OS-1/OS-2 collected as strict xfail under `tests/test_os_01_02_collected.py` (Track B). Design under `design/os/` stays unscanned. Receipt `OS-1-2-COLLECTED-XFAIL-2026-10-11.md`. No implementation. No paper claim.

- Explicit deny for path segments `.env` and `.aegis` even when a grant glob covers the parent directory (Forseti #60 nit). Deny-by-default alone is not enough once those names sit inside a granted tree; the reason names the protected segment. The check follows `realpath` (symlink aliases under a whole-home grant) and the realpath of the parent for new files; also denies `.env.*`, `.envrc`, and case-folded `.ENV` / `.Aegis` (Forseti #65 FIX-FIRST). Names that merely *end* in `.env` (for example `foo.env`) stay allowed - only the exact segment `.env` / `.env.*` / `.envrc` / `.aegis` is protected.
- Full-suite runner (`scripts/run_full_suite.py`) that sets `AEGIS_ATOMS_ROOT` and `ISOLATION_LAYER_ROOT` to detached worktrees at the sibling pins in `tests/test_gate_boundary.py`, so a local pytest matches CI instead of the operator's live sibling HEAD.
- Folded Part C design scaffolds under `design/part-c/`, plus pre-code OS, specification-gaming, and policy-decay designs. None of those folders change the gate decision path.
- Wave 3 measured-gap receipt: AgentDojo, GAIA2, TAU-Bench, and SWE-Gym stays unmeasured until a live boxed run exists; B7, live AgentDojo, and paid runs remain held. The Wave 3 document is a MEASURED-GAP design, not a paper claim.
- Wave 2 offline paper contracts: a 96-row enforce oracle, digest recomputation helper, dependency-free AgentDojo-to-`pre_tool_call` adapter stub, failure/adversarial scaffolds, source map, sanitized benign-day template, and bounded reproduction instructions. Live Hermes, AgentDojo, box, and judge claims remain explicitly unmeasured.
- The Hermes hook exports its live allow `Decision` and `tool_call_id` through the shared per-call context, so downstream atoms can bind their receipt and box prove to the exact gate decision that was evaluated.
- Plugin bundle version `0.1.1` (tag `plugin-v0.1.1`): same SLSA attestation path as `plugin-v0.1.0`, zip includes `__init__.py` plus the kill switch tip. Verify: `gh attestation verify capability-gate-plugin-0.1.1.zip --repo Steck43/capability-gate`.
- Kill switch. `Gate.throw` creates a marker beside the decision log (the log path plus `.halt`) and appends one THROWN row to the hash chain; a second throw adds no row. `Gate.evaluate` materializes paths once, then reads the marker before the allowlist, so a running gate denies the next call with no restart, and a marker it cannot read is a deny. A call that names the marker is denied with the switch on or off. Only a human removing the marker clears it. Observe mode still blocks nothing (`test_kill_switch_blocks_in_observe`, strict expected failure). `tests/test_kill_switch.py` is gate-level only: it does not show the live hook calls the gate.
- Claude Code adapter (`adapters/claude_code_hook.py`), Windows. The decider runs as a `PreToolUse` hook. Allow is exit 0 with no output, so Claude Code's own permissions still apply; every deny and every error is exit 2 with a reason, under a 5 s self-deadline. Calls carry no skill label and are judged as `UNLABELED`, which the allowlist must grant by name. A `PostToolUse` twin flags a call whose input changed after the check. `tests/test_cc_adapter.py` pins each branch.

### Fixed

- Claude Code Glob canaries now deny five additional segment spellings that can match `..`: `.?`, `?.`, `[.x][.x]`, `[!a][!a]`, and `[.-.][.-.]`.
- T-FAIL-05 path coercion now runs inside `Gate.evaluate`'s recorded fail-closed boundary. A path whose string conversion raises returns DENY and appends a deny row instead of escaping before the boundary.
- Claude Code adapter Glob climb residuals (K2b): deny escaped character-class parents (`[\.][\.]/*`), mixed `.`/`[.]` segments, `..*`, nested brace alternatives, and absolute brace alts before separator normalize. Collapse `[.]` / `[\.]` / `[..]` to literal dots first so a global `\`→`/` rewrite cannot turn `[\.]` into `[/.]`. Still a denylist over climb shapes, not a full Glob semantic model.
- K5 hardlink hole: a regular file with `st_nlink > 1` is denied, so an in-grant hardlink name cannot open an off-grant inode that realpath cannot see. Alias S2 moves to DENY. The check-open swap stays a strict expected failure (needs open-by-fd in the host).
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

- CI now pins `zizmorcore/zizmor-action` at v0.6.4 (`cc914d7`) so workflow analysis runs against the reviewed release while checkout credentials remain disabled.
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
