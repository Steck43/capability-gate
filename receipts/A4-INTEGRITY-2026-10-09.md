# A4 — Integrity monitor / tip census (2026-10-09)

## Scope measured

Published default-branch tips for the five public roofs, plus the
aegis-atoms derived `SHA256SUMS` regenerate check after this sitting's merges.
`always_invoked` stays false.

## Five-roof tip census (API dest-read this sitting)

| Roof | Default | Tip SHA |
|---|---|---|
| capability-gate | `main` | `e143c0246a231606574acd9d2011e42b639e8426` |
| aegis-atoms | `master` | `035d9d34af8967793287d5ff591b435a786b18e1` |
| isolation-layer | `main` | `9cdf7ee6658a6c90b3860509a4cabaa523f2bb75` |
| newwave-owasp-security-lab | `main` | `3c6f15e7ed57d56d4b44f0a4344873ee3eb04ca9` |
| owasp-dual-top10-lab | `master` | `a02e3e97c92c912a2f859c6d7c3b790e6e477e14` |

## Derived / bundle integrity

| Check | Result |
|---|---|
| aegis-atoms `bash .floor/craft/verify_derived.sh` | EXIT=0; `SHA256SUMS` reproduces |
| capability-gate plugin zip `plugin-v0.1.1` | attested; see A3 receipt (sha256 `a3634306…`) |
| isolation-layer tree SHA256SUMS | absent on this roof (no registry) |
| newwave / dual-lab SHA256SUMS refresh | not regenerated this sitting (no content change this sitting) |

## NOT measured

- A hosted "nightly readiness probe" job run this sitting (no LandensPC
  schedule fired here; tip census is the dest-read substitute).
- Byte-identity of every derived artifact on newwave and dual-lab.
- `always_invoked` (stays false).

## Moves paper claim

None. Standing: five public tips named above; atoms derived registry green.
