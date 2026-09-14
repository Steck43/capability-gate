# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- README Status names the author profile so a stranger can click once from this roof to `github.com/Steck43`.
- README Figure 1 is the dest-true SVG. The box sits between floor and judge. Mermaid stays the sketch. This roof is the allowlist baseline of the floor. The atom plane is a sibling roof in the same plane.
- README and Stage-1 note say written-up remedy, not a venue claim.

### Added

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
