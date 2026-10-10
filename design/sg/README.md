# Part SG — specification-gaming detection (pre-code)

Hermes pin: `ccd8deaa67`. Source: MASTER-PLAN addendum 3 (2026-10-09).
Detect builds that pass checks without doing the real work.

| Wave | Item | Failing test | Receipt |
|---|---|---|---|
| SG-1 | mutation testing on gate and atoms | `T-SG-01` | `MUTATION-GATE-ATOMS-2026-10-xx` |
| SG-2 | hidden hold-out checker | `T-SG-02` | `HOLD-OUT-CHECKER-2026-10-xx` |
| SG-3 | behavior-not-string CI lint | `T-SG-03` | `BEHAVIOR-TEST-STANDARD-2026-10-xx` |
| SG-4 | writes to tests/CI/policy escalate | `T-SG-04` | `SENSITIVE-TEST-WRITE-2026-10-xx` |
| SG-5 | env-detect, loosened assert, receipt-without-evidence | `T-SG-05a`–`c` | `SPEC-GAMING-SIGNALS-2026-10-xx` |

SG-3 and SG-4 can land early (policy). SG-1 after atoms fail-closed (already
merged). SG-2 and SG-5 travel with the Hermes corpus harness.

## NOT measured

Mutation score, hold-out runs, live agent gaming, judge apply, paid API.
