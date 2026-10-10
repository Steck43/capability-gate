# AgentDojo adapter sketch — 2026-10-09

Hermes runtime pin: `ccd8deaa6705bd6ca1890584d8f4055fe61227b5`

## Built

`adapters/agentdojo_adapter.py` maps four dependency-free tool families onto Hermes door names and delegates each normalized call to an injected Hermes `pre_tool_call` callable. The closed mapping forwards only schema-approved arguments; tool-output text cannot supply skill, mode, approval, or hook metadata.

The unit contract proves mapping and metadata stripping. It does not instantiate AgentDojo or Hermes.

## Authoring estimate

| Suite surface | Mapping rows | Policy work estimate | Status |
| --- | ---: | ---: | --- |
| filesystem read/write | 2 | 1–2 hours after suite inventory | stubbed |
| web search | 1 | 1 hour after suite inventory | stubbed |
| shell execute | 1 | 2–4 hours because command policy is suite-specific | stubbed |
| email, calendar, banking, workspace applications | 0 | unknown until official AgentDojo schemas are pinned | `MEASURED-GAP` |

## NOT measured

- AgentDojo package version, suite inventory, task count, or policy line count.
- Live Hermes mount, model loop, seeds, utility, utility under attack, ASR, confidence intervals, or API spend.
- Atoms, box, or judge behavior on an AgentDojo task.
- Compatibility with AgentDojo tool schemas beyond the four explicit names.

No live AgentDojo end-to-end claim is made.
