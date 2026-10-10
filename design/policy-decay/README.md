# Policy decay — pre-code design (Forseti before implementation)

Hermes pin: `ccd8deaa67`. No production code in this folder.

Today a grant, an approval, and a piece of evidence last until a human
removes them. Long-lived allow is the failure mode. Decay is a narrowing
operator on the existing lattice. It never introduces a permission the
current policy would refuse.

## Lattice (narrowing only)

Rank, highest authority first: BLOCK > ESCALATE > REQUIRE_DUAL_APPROVAL >
REQUIRE_APPROVAL > MONITOR > ALLOW.

Decay may:

- shorten a grant TTL or an approval TTL
- age evidence so that a later call must re-attest
- replace ALLOW with MONITOR, REQUIRE_APPROVAL, ESCALATE, or BLOCK
- replace a remaining grant with the intersection of the grant and a tighter
  path/tool set

Decay must not:

- lengthen any TTL
- restore a lapsed grant without a new attestation
- turn BLOCK or ESCALATE into ALLOW
- add a tool, path, host, or skill the pre-decay grant did not name
- apply a judge verdict (judge apply stays off)

Proof obligation for the implementation PR: for every pair (pre, post) the
post permission set is a subset of the pre permission set. Encode that as a
property test over the lattice, not a source-string check.

## Four clocks

1. **Grant TTL.** Wall-clock from issuance. Expiry → the grant is absent, which
   the floor already treats as deny. Missing or unreadable expiry metadata is
   deny, not "no TTL."
2. **Approval TTL.** A dual-approval or human GO expires. A later call with the
   same tool/path must collect a new GO. Stale GO bytes in the log are not a
   live grant.
3. **Evidence aging.** Prove receipts, pin files, and sibling SHAs older than
   the evidence TTL cannot satisfy a later bound-live stamp. The stamp is
   withheld; the call is not widened to compensate.
4. **Re-attestation.** A grant that survives wall-clock TTL only by being
   long-lived must present a fresh attestation (same identity, same or
   narrower scope) before the next allow. Failure to re-attest narrows to
   deny.

## Composition

Decay runs on the floor before atoms and before the box. It cannot be skipped
by observe mode for the purpose of an enforce claim (G4: observe stays in its
own table). ASK and THROWN remain non-allow; decay does not convert them.

## Failing tests the implementation PR must commit first

See `FAILING-TESTS.md`. Forseti reviews this design before any of those tests
are wired into roof pytest.

## NOT measured

Live TTL on the WSL Hermes profile, judge apply, AgentDojo, paid API, B7.
