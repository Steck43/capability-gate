# Wave 2 offline scaffolds — 2026-10-09

Hermes runtime pin: `ccd8deaa6705bd6ca1890584d8f4055fe61227b5`

## Results

| Todo | Offline result | Live status |
| --- | --- | --- |
| T-COMP-02 | 96-row enforce oracle generated; 2 expected allows; fixture sha256 `57e3718feb056c403a97605cbab26b111f1bf5ebdcf33f87f7fc4791a457f555` | `NOT measured` |
| T-COMP-05 | Shared gate-digest recompute and two-digest comparison helper passes wrong-digest denial KAT | Isolation acceptance wiring `NOT measured` |
| T-FAIL-01 | Injected gate log-layer death raises; target remains absent | Other layers and live doors `NOT measured` |
| T-FAIL-03 | Existing verifier mapped; strict expected failure pins missing first-bad-row index | Disk-full and exact-index requirements `NOT measured` |
| T-FAIL-04 | Fresh Gate instance denies 20/20 calls with the existing marker; one THROWN row | Hermes/plugin restart `NOT measured` |
| T-ADV-02 | Adapter mapping strips output-carried privilege metadata | Live induced calls `NOT measured` |
| T-ADV-03 | Five outside-set Glob parent canaries now classify as climb attempts | Live CC/Hermes matching and Windows rows `NOT measured` |
| B1 | `REPRODUCE-PAPER.md` names offline commands and boundaries | Vör cold reproduction `NOT measured` |

Failing-first commit: `8d7d3e5` (missing adapter/module/table). The T-ADV-03 canaries then failed 5/5 before the classifier repair.

## Claim boundary

This receipt records local unit contracts only. It does not move a live AgentDojo, box, judge, Hermes-door, or benign-day paper claim.
