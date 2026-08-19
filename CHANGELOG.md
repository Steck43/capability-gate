# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Three README badges: Scorecard, floor, license.

### Changed

- Floor push trigger is `main` only, with a concurrency group that cancels in-progress runs.
- Craft jobs resolve BASE from the PR base SHA or `github.event.before`. Empty range exits 3 instead of passing on nothing. Root-commit fallback removed.

### Fixed

- Tests job no longer swallows a failed `pip install -e .`.
- Every floor job now has `timeout-minutes: 10`.
- Do not enable `setup-python` `cache: pip` on roofs without `requirements.txt` or `pyproject.toml`. The cache lookup fails the job.
