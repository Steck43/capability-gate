# C2 design stub — 2026-10-09

Target roof: `capability-gate`. Hermes source pin: `ccd8deaa67`.

State: SCAFFOLD. The Paper Master Plan remains the requirement source and is
not edited by this branch.

## Pre-code contract

- Pin the exact input schema and canonicalization boundary.
- Treat unknown fields and malformed values as a failing negative, not an
  implicit grant.
- Preserve decision-log ordering before any side effect.
- Add a failing test before production code.

## Dependency

This branch does not edit the gate decision path. A later C2 implementation
that does must depend on any open predecessor touching that path.

## NOT measured

No runtime, benchmark, Hermes, box, judge, B7, Zenodo, release, or tag action.
