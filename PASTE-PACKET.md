# S10 phishing-investigation REPLAY - paste packet

Sprint 2026-10-25 sprint task (S10). Feature branch only. Do not merge or push to main.

## Where

`Steck43/capability-gate`, path `demos/`:
`demos/scenarios/S10-phishing-investigation.yaml`, `demos/synthtraffic.py`,
`demos/samples/phishing/*.eml` + `MANIFEST.json`,
`demos/samples/recorded/S10-phishing-investigation.json`, `demos/test_demos.py`.

## Git

- Branch: `steck43/s10-phishing-investigation-pc`
- Base SHA: `13ada55fded50f2244ddabb52b4a2e2259e87a2a` (`main`). Independent of the S11 PR.
- Head SHA: `6467de15f857c55e676763bf5a510da67b203f3d`
- Draft PR: see the draft on this branch

## What it does

15 synthetic emails. Pre-check before the recorded verdict: header domain
mismatch (Return-Path / Reply-To), brand lookalike (digit swap, one edit),
link text vs href host, and body text aimed at the assistant. A hard fail
floors the verdict at suspicious; the recorded verdict cannot overrule it.
The recorded fixture deliberately says "benign" for the injection email and
for one link-swap email, so trusting the recording goes red. Every email is
queued for a human. Replay only: no model, no network, no cost figures.

## How to run

Fresh clone of this branch, Python 3, `pip install -r requirements-dev.txt`. No API key.

    python3 demos/synthtraffic.py run demos/scenarios/S10-phishing-investigation.yaml
    python3 -m pytest -q -p no:cacheprovider demos/ -k s10
    make demo-test
    make demo-all

`make demo-all` still needs the isolation-layer sibling for S14 (same as
before). S10 does not.

## Expect

emails=15, hard_fail_flagged=9, injection_flagged=1, verdicts_match=15,
human_review_queue=15, auto_safe=0, auto_closed=0, replay=1. Summary no
longer lists S10 as unsupported.

## Mutants (each must turn the S10 row FAIL)

1. Pre-check skipped → the injection email ends benign.
2. Recorded verdict trusted over hard fail → injection and link-swap emails end benign.
3. Auto-mark safe or skip the human queue → auto_safe > 0 or auto_closed > 0.

## Proposed STATUS row

| date | item | owner | repo | state | branch | testers | proofs |
|---|---|---|---|---|---|---|---|
| 2026-10-25 | S10 phishing-investigation REPLAY | sprint task | capability-gate | BRANCH (draft PR, not main) | steck43/s10-phishing-investigation-pc | two tester roles named in the sprint brief | fresh-clone |

## Tester ask

The two tester roles named in the sprint brief. Prove it from a fresh clone of
this branch, not a dirty worktree. Re-run the mutants yourselves. Synthetic
data only. No public claims. S13 token-usage is still deferred.
