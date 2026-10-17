# C1 design stub — 2026-10-09

Target roof: `capability-gate`. Hermes source pin: `ccd8deaa67`.

State: IMPLEMENTED IN THE GATE ROOF. `open_authorized_read` binds policy
evaluation and the host action to one Linux file descriptor. The pinned Hermes
host does not consume that primitive yet, so this is not a live-runtime claim.

## Pre-code contract

- Start from a named input, expected verdict, and fail-closed negative.
- Preserve the existing gate decision type and append-only receipt boundary.
- Do not widen an allow when policy input is absent, malformed, or unresolved.
- Add a failing test before production code.

## Dependency

Hermes `ccd8deaa6705bd6ca1890584d8f4055fe61227b5` still resolves a name in
`read_file_tool`, then passes that name to `ShellFileOperations.read_file`.
Host integration must consume `open_authorized_read.stream` instead of
reopening the request path.

## NOT measured

The CI scaffold runs 100 deterministic swaps. The 10,000-iteration T-ADV-04
campaign, live Hermes integration, box, judge, B7, Zenodo, release, and tag
actions remain unmeasured.
