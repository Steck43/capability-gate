# C1 design stub — 2026-10-09

Target roof: `capability-gate`. Hermes source pin: `ccd8deaa67`.

State: SCAFFOLD. This branch reserves C1 without implementing or measuring it.
The exact acceptance criterion remains owned by the Paper Master Plan, which
this branch does not edit or paraphrase into a new requirement.

## Pre-code contract

- Start from a named input, expected verdict, and fail-closed negative.
- Preserve the existing gate decision type and append-only receipt boundary.
- Do not widen an allow when policy input is absent, malformed, or unresolved.
- Add a failing test before production code.

## Dependency

No gate decision-path code changes here. If C1 later changes that path, its PR
must be the dependency base for any simultaneous Part C decision-path work.

## NOT measured

No runtime, benchmark, Hermes, box, judge, B7, Zenodo, release, or tag action.
