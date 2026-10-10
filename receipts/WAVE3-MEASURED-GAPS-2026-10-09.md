# Wave 3 measured gaps and pre-code designs — 2026-10-09

Hermes source pin: `ccd8deaa67`.

This receipt scaffolds Paper Master Plan Wave 3 without changing the plan. It
records no benchmark result. Budget ceiling: expected external spend `$0`,
estimated agent time `7–9 h`; stop before either `$50` or `10 h`.

## Benchmark ledger

| Todo | State | Scaffold / missing measurement |
| --- | --- | --- |
| BENCH-ASB | MEASURED-GAP | No Agent Security Bench runner, model invocation, scenario count, utility score, attack-success rate, or confidence interval was run. |
| BENCH-INJECAGENT | MEASURED-GAP | No InjecAgent dataset or evaluator was installed or executed. |
| BENCH-AGENTHARM | MEASURED-GAP | No AgentHarm suite, model, refusal/utility metric, or attack-success rate was executed. |
| BENCH-RJUDGE | MEASURED-GAP | No external judge baseline, judge-apply run, agreement rate, or calibration result was measured. |
| FALSE-ALLOWS | SCAFFOLD | Report false allows only from a named harness and denominator. Existing Stage-1 and atoms fixture tallies are not Wave 3 benchmark results. |
| BASELINES | MEASURED-GAP | No unguarded, gate-only, atoms-only, box-only, or composed benchmark baseline was run. |
| Progent-on-AgentDojo | MEASURED-GAP | The dependency-free adapter stub is not Progent, AgentDojo, a model run, utility, ASR, or a confidence interval. |

## R3 ledger

- R3-a — SCAFFOLD: define the input states and ordering before implementing a
  reducer; no result or code is claimed.
- R3-b — DESIGN: `CONFLICTING` is not an ordinary denial. The floor must hand
  the contradiction to the box before a paid judge call. Escalation is an
  explicit outcome after the box cannot settle the conflict; it must not be
  encoded as an implicit widening or allow.
- R3-c — DESIGN: compose independent policy dimensions as a product of
  lattices. Each coordinate keeps its own partial order; reduction is
  coordinate-wise, and any projection into one scalar must be documented as
  lossy and must not turn incomparability into permission.
- R3-d — SCAFFOLD: specify monotonicity and fail-closed properties before test
  vectors or implementation.
- R3-e — SCAFFOLD: name the receipt fields and replay boundary before wiring a
  runtime caller.

### R3-b pre-code contract

Inputs that are mutually satisfiable may reduce normally. Inputs marked
`CONFLICTING` must produce a typed conflict containing the source coordinates
and evidence references. The next authority is the box. Only a box result that
still cannot settle the conflict may request bounded-judge review. Neither
handoff may emit `allow`.

### R3-c pre-code contract

Let each policy dimension be a bounded lattice `L_i`. The composed state is in
`L_1 × ... × L_n`; join and meet operate coordinate-wise. Tests must include
incomparable pairs, top and bottom identities, idempotence, commutativity, and
associativity. Any operational verdict is a separate, named projection with
tests proving that unknown or incomparable coordinates cannot project to
`allow`.

## B4 and B6 scaffolds

### B4 BOOT-PROFILE

SCAFFOLD only. A future receipt must name the host, clean repository tips,
profile path, exact startup command, mounted plugins, mode values, rollback,
and post-boot negative probe. No profile was booted by this wave.

### B6 THREAT-MODEL

SCAFFOLD only. Minimum sections: protected assets, trust boundaries, attacker
capabilities, entry points, abuse cases, controls by the four planes, residual
risks, and falsifying tests. Memory is a governed surface, not a fifth plane.

## Part C branch policy

C1–C7 receive independent design-only branches. They do not modify the gate
decision path. A later implementation branch that changes that path must name
its predecessor and use a dependent PR base; two independent decision-path
PRs are forbidden.

## NOT measured

No paid API, model, benchmark package, AgentDojo suite, Progent run, live
Hermes turn, aegisbox hour, judge application, B7/Zenodo action, release, or
tag was executed. `always_invoked` remains false.
