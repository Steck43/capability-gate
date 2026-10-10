# C5 design stub — 2026-10-09

Target implementation roof: `isolation-layer`. Scaffold host:
`capability-gate`. Hermes source pin: `ccd8deaa67`.

State: SCAFFOLD. The isolation-layer worktree had active Step-12b receipt
changes, so this branch does not write through that work. The Paper Master
Plan remains unchanged.

## Pre-code contract

- Name the box entry point, host, profile, and rollback before execution.
- Keep the box between the floor and bounded judge.
- Prove the negative path and receipt binding before claiming a live boot.
- Land implementation on isolation-layer only after its active branch closes.

## NOT measured

No box boot, runtime, benchmark, Hermes, judge, B7, Zenodo, release, or tag
action.
