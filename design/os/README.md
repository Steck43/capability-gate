# Part OS — output-side security (pre-code)

Hermes pin: `ccd8deaa67`. Source: MASTER-PLAN addendum 2 (2026-10-09).
Input-side least privilege already exists. This track covers what returns from
an allowed tool that is compromised, rug-pulled, or adversarial.

Judge apply stays off. B7, live AgentDojo, and paid runs stay held.

Failing tests live under `design/os/tests/` and are **not** collected by the
roof pytest until the matching implementation PR. Landing them on main while
red would break the floor.

| Wave | Item | Failing test | Receipt |
|---|---|---|---|
| OS-1 | MCP tool-list/description pin | `T-OS-01` | `MCP-PIN-2026-10-xx` |
| OS-2 | provenance/taint on tool results | `T-OS-02a`–`d` | `TAINT-FLOW-2026-10-xx` |
| OS-3 | result-boundary scanner (signal only) | `T-OS-03` | `RESULT-SCAN-2026-10-xx` |
| OS-4 | high-risk MCP inside the box | `T-OS-04` | `MCP-IN-BOX-2026-10-xx` |
| OS-5 | size/shape anomaly flags | `T-OS-05` | `BEHAVIOR-FLAG-2026-10-xx` |
| OS-6 | e2e poisoned MCP/DB/file/web/rug-pull | OS-6 suite | per-case receipts |

Order: OS-1 and OS-2 first; OS-3 and OS-5 next; OS-4 after box mount is free;
OS-6 after 1–5 have receipts. Blocks B6 threat model and B7 freeze.

## NOT measured

Live third-party MCP, real databases, judge apply, paid API, AgentDojo.
