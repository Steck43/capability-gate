# C7 design stub — 2026-10-09

Target implementation roofs: `capability-gate` and `isolation-layer`.
Scaffold host: `capability-gate`. Hermes source pin: `ccd8deaa67`.

State: SCAFFOLD. This branch defines only the cross-roof dependency boundary.
The Paper Master Plan remains unchanged.

## Pre-code contract

- Pin both published inputs before a cross-roof test.
- Keep floor decision, box result, bounded-judge result, and audit receipt as
  distinct objects.
- Fail when a required object or binding is absent; never synthesize success.
- Sequence any decision-path change behind its predecessor before opening the
  second implementation PR.

## NOT measured

No cross-roof execution, runtime, benchmark, Hermes, box, judge, B7, Zenodo,
release, or tag action.
