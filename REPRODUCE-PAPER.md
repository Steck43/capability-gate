# Reproduce the paper evidence

This guide separates source-reproducible checks from live measurements. The
capability-gate baseline is
`bc02541cbf41979fb546d9fd44279c83913f6684`; Hermes remains pinned to
`ccd8deaa6705bd6ca1890584d8f4055fe61227b5`.

## Cold clone

Use a new parent directory. The full-suite runner needs sibling clones that
contain its pinned atoms and isolation commits; it creates and removes detached
worktrees without moving those clones.

```powershell
git clone https://github.com/Steck43/capability-gate.git
git clone https://github.com/Steck43/aegis-atoms.git aegis-atoms-public
git clone https://github.com/Steck43/isolation-layer.git
Set-Location capability-gate
git checkout bc02541cbf41979fb546d9fd44279c83913f6684
python -m pip install -r requirements-dev.txt
```

## One-command offline reproduction

```powershell
python scripts/run_full_suite.py -- -q
```

Expected at the baseline: `251 passed, 10 skipped, 3 xfailed`. The runner
checks out atoms `41b6e8396b998d7f2a7bb95fb6f3ced186e28ee1` and isolation-layer
`a27c8ee424d96a18a9147bab5689a78e819b7184`; the test
`tests/test_run_full_suite_pins.py::test_runner_pins_match_boundary` prevents
the runner and boundary harness from drifting.

The narrower Wave 2 contract command is:

```powershell
python -m pytest -q tests/test_wave2_offline_scaffolds.py
```

Expected: `11 passed, 1 xfailed`. Its T-COMP-02 fixture has 96 rows, 2 expected
allows, and sha256
`57e3718feb056c403a97605cbab26b111f1bf5ebdcf33f87f7fc4791a457f555`;
every row is a plan row with `status: LIVE` and `measured: false`.

## Release attestation

The published `plugin-v0.1.1` asset is independently verifiable:

```powershell
gh release download plugin-v0.1.1 --repo Steck43/capability-gate --pattern capability-gate-plugin-0.1.1.zip --clobber
gh attestation verify capability-gate-plugin-0.1.1.zip --repo Steck43/capability-gate
(Get-FileHash capability-gate-plugin-0.1.1.zip -Algorithm SHA256).Hash.ToLower()
```

The final line must be
`a363430649a92dc765935b4ee408e0bf2a37672c647c4737b807c0ce06b00a14`.
This attests the release asset and its workflow provenance; it does not prove a
live Hermes mount.

## Derived inventory

From the cold-cloned `aegis-atoms-public` sibling:

```powershell
Set-Location ..\aegis-atoms-public
bash .floor/craft/verify_derived.sh
```

Expected: exit 0. The check regenerates every path in `.floor/derived.tsv`,
including `SHA256SUMS`, and refuses a committed derived artifact that differs.
Return to `capability-gate` before running the other commands.

## Live KVM / aegisbox evidence

The offline command does not start a KVM or contact aegisbox. The live
three-object replay is recorded separately in
`Steck43/hermes-agent-estate:wsl/receipts/STEP-11b-2026-10-09.md`:
call id `step11-20261010T050143Z`, raw artifact
`wsl/receipts/raw/step11b-bound-prove.json`, sha256
`c6884b7a9941885f71d4fffe27e7dba4b2d363f2ae55bc183d1115bda1a7e7b6`,
and 7 passing behavioral negatives. That receipt proves the named replay only;
it does not independently attest the host hypervisor or make a KVM path always
invoked. Judge apply remains false.

## Vör hand-off — T-REP-01

Vör should run the Cold clone block in an empty directory, then run the
one-command offline reproduction without a vault, host allowlist, or existing
sibling worktree. Return the three checked-out SHAs, Python and operating-system
versions, the exact pytest summary, exit code, and a sha256 of the captured
console output. T-REP-01 passes only if the baseline count is reproduced from
those cold clones; a run from an existing estate checkout is not the cold-clone
test.

## Claim boundary

These commands do not run Hermes, AgentDojo, a model, or aegisbox. They do not
establish live mount coverage, end-to-end utility, attack success rate, box
containment, judge application, or benign-day performance. Live tiers must
write separate receipts with immutable raw artifacts and final sha256 values.
