# C3 design stub — 2026-10-09

Target roof: `capability-gate`. Hermes source pin: `ccd8deaa67`.

State: SCAFFOLD. The Paper Master Plan remains unchanged.

## Pre-code contract

- Name the authority that owns each transition.
- Keep `deny`, `ask`, `block`, and unresolved states distinct.
- Prove that no exception or omitted field projects to `allow`.
- Add a failing transition-table test before production code.

## Dependency

No gate decision-path code changes here. A future C3 implementation that
touches that path must use a dependent PR base while another such PR is open.

## NOT measured

No runtime, benchmark, Hermes, box, judge, B7, Zenodo, release, or tag action.
