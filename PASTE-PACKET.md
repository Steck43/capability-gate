# S11 alert-triage REPLAY — paste packet

Sprint 2026-10-25 task 2 (Atreus). Feature branch only. Do not merge or
push to main.

## Where

This is `Steck43/capability-gate`. The path is `demos/` in this repo
(`demos/scenarios/S11-alert-triage-burst.yaml`, `demos/synthtraffic.py`,
`demos/samples/recorded/S11-alert-triage-burst.json`). There is no sibling
`defensive-workflows` tree.

## Git

- Branch: `steck43/s11-alert-triage-replay-ff74`
- Base SHA: `13ada55fded50f2244ddabb52b4a2e2259e87a2a` (`main`)
- Head SHA: `905fb73d1abca2343b58fe648730fb4033601fe7` (runner + docs; branch tip may sit one packet commit above this)
- Draft PR: https://github.com/Steck43/capability-gate/pull/131

RED then GREEN is on the branch: first commit is the failing assertions,
later commit is the replay runner.

## How Landen pushes from the PC

From a `capability-gate` clone. Never push `main`.

    git fetch origin
    git checkout steck43/s11-alert-triage-replay-ff74
    # if the branch is only on origin yet:
    git checkout -B steck43/s11-alert-triage-replay-ff74 origin/steck43/s11-alert-triage-replay-ff74

    # after local edits, push the feature branch only:
    git push origin steck43/s11-alert-triage-replay-ff74

Do not `git push origin main`. Do not merge the draft PR.

## How to run

From a fresh clone of this branch, Python 3 and `pip install -r requirements-dev.txt`.
No API key. No network.

    make demo-test
    make demo-all
    python3 demos/synthtraffic.py run demos/scenarios/S11-alert-triage-burst.yaml

`make demo-all` still needs the isolation-layer sibling for S14 (same as
before). S11 itself does not.

Verified on this branch: `make demo-all` 9/9 PASS, README Proof matches,
`python3 -m pytest -q -p no:cacheprovider demos/` 64 passed (S11 included).
Summary no longer lists S11 as unsupported.

## Proposed STATUS row

| date | item | owner | repo | state | branch | testers | proofs |
|---|---|---|---|---|---|---|---|
| 2026-10-25 | S11 alert-triage REPLAY | Atreus | capability-gate | BRANCH (draft PR, not main) | steck43/s11-alert-triage-replay-ff74 | Bug_Hunter + Adversary | fresh-clone |

## Tester ask

Bug_Hunter + Adversary. Proofs from a fresh clone of this branch, not a
dirty worktree. Synthetic data only. No public claims. S10 phishing and
S13 token-usage are deferred.

## Expect

500 alerts, 220 unique groups, 280 duplicates grouped, true positive in
the top 3, auto-closed == 0. Summary no longer lists S11 as unsupported.
