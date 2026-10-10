# C4 design stub — 2026-10-09

Target roof: `capability-gate`. Hermes source pin: `ccd8deaa67`.

State: SCAFFOLD. The Paper Master Plan remains unchanged.

## Pre-code contract

- Bind every decision and receipt to one caller-supplied call identifier.
- Reject replay and wrong-call identifiers within the stated caller boundary.
- Distinguish format validation from provenance or digest re-derivation.
- Add failing fake, replay, and mismatch tests before production code.

## Dependency

No gate decision-path code changes here. A future C4 implementation that
touches that path must depend on the active predecessor.

## NOT measured

No runtime, benchmark, Hermes, box, judge, B7, Zenodo, release, or tag action.
