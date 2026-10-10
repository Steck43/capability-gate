# Policy decay — failing tests (not collected yet)

Commit these red, then implement. Do not land them on main while red.

| Id | Assert |
|---|---|
| T-DEC-01 | A grant with `expires_at` in the past is absent; evaluate returns DENY and writes a deny row. |
| T-DEC-02 | Missing `expires_at` on a timed grant class is DENY, not implicit forever. |
| T-DEC-03 | Unreadable expiry metadata is DENY (fail closed). |
| T-DEC-04 | Approval TTL expiry refuses the next call that needed that GO. |
| T-DEC-05 | Replaying a logged GO after its TTL does not restore allow. |
| T-DEC-06 | Evidence older than the evidence TTL cannot satisfy a bound-live stamp. |
| T-DEC-07 | Re-attestation with a *wider* tool/path set is refused; only equal or subset scope is accepted. |
| T-DEC-08 | Property: for random lattice pairs, `decay(pre)` ⊆ `pre` (no added tools, paths, hosts, skills). |
| T-DEC-09 | Decay never maps BLOCK or ESCALATE onto ALLOW. |
| T-DEC-10 | Observe-mode decay rows are reported separately and never counted as enforce (G4). |
| T-DEC-11 | ASK and THROWN stay non-allow across a decay tick. |
| T-DEC-12 | Clock rollback (system time before issuance) is DENY, not a TTL refresh. |
