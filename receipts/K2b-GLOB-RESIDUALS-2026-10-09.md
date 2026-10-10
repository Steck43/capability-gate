# K2b — Glob climb residual denials (2026-10-09)

Hostile-review residual on K2: the first Glob denylist closed the pinned
KATs (`[.][.]/*`, `{..,x}/*`) but still allowed climb obfuscations a reviewer
will try next.

Hermes runtime pin for this paper pass: `ccd8deaa67`.

## Claim (exact)

On capability-gate tip after this PR, residual Glob climb patterns from the
Step 10 / K2 interrogate panel are denied with known-answer tests: escaped
character-class parents (`[\.][\.]/*`), mixed `.` / `[.]` segments, `..*`,
nested brace alternatives, and absolute brace alts. That is a denylist over
those shapes, not a full Glob semantic model.

## Already closed (K2)

| Id | Test | State |
| --- | --- | --- |
| B-P2-R2-1 | `test_glob_obfuscated_climb_denied` | CLOSED on main |
| B-P2-R2-2 | `test_tool_without_path_schema_denied_even_when_granted` | CLOSED |
| B-P2-R3-1 | `test_deadline_inf_and_over_cap_clamped` | CLOSED |

## Closed this sitting

| Pattern class | Test | Result |
| --- | --- | --- |
| Residual climb obfuscations | `test_glob_climb_residuals_denied` | PASS (was FAIL at stub `40518e6`) |

Failing stub first: `40518e6`. Wire: this PR.

The squash merge does not preserve the failing-first commit in main's
first-parent history; `40518e6` is the explicit red receipt. Linux CI measured
**24 passed, 1 skipped**. A Windows re-run on this Wave 1 branch measured
**25 passed**.

Branch: `steck43/k2b-glob-claim-and-residuals`.

## NOT measured / still open

- Full Glob semantic equivalence (this is still a denylist over climb shapes).
- T-ADV-03 canary: add one outside-set climb spelling to prove this denylist
  still reports a residual instead of being described as complete.
- Host Hermes S3s (0004 / 0009 / `mini_swe_runner`).
- Windows grant-file owner / ACL check.
- K5 check-open swap (still strict xfail).
- always_invoked (stays false).
