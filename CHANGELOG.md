# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Senior craft floor: craft (voice), craft (changelog), craft (comments) required CI jobs.
- `.gitattributes` so text files stay LF and Windows scripts stay CRLF.
- Weekly Dependabot for GitHub Actions and pip, with a 7-day cooldown. Dependabot PRs still pass the floor; no bypass actor.
- SECURITY.md. Reports go through GitHub private vulnerability reporting, not a public issue.
- Workflow lint job: zizmor (SHA-pinned) plus actionlint 1.7.12 with a baked checksum.

### Changed

- Floor push trigger is `main` only, with a concurrency group that cancels in-progress runs.
- Craft jobs resolve BASE from the PR base SHA or `github.event.before`. Empty range exits 3 instead of passing on nothing. Root-commit fallback removed.

### Fixed

- Tests job no longer swallows a failed `pip install -e .`.
- Every floor job now has `timeout-minutes: 10`.
- Do not enable `setup-python` `cache: pip` on roofs without `requirements.txt` or `pyproject.toml`. The cache lookup fails the job.
