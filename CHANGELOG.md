# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Named empty-diff BREAK: CI job `craft (empty-diff)` runs `.floor/craft/empty_diff_gate.py`. An empty `base...head` range fails. `changelog_gate` skip-green on non-user-facing ranges is a different job and is not this BREAK. The job runs on pull requests only: on push, schedule and workflow_dispatch the base resolves to `origin/main`, which on a push to main is head, so the range is empty by definition rather than by defect. Its selftest carries a forced-red case and a must-not-fire case.
- Senior craft floor: craft (voice), craft (changelog), craft (comments) required CI jobs.
- Dev container pinned by digest, with pre-commit, ruff, and checksummed gitleaks 8.30.1 so a Codespace arrives with the local floor wired.
