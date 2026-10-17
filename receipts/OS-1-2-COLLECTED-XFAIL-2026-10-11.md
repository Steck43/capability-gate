# OS-1 / OS-2 collected suite (strict xfail) — 2026-10-11

Status: **COLLECTED as xfail(strict=True).** No implementation. Apply N/A (gate roof).
Hermes pin `ccd8deaa6705bd6ca1890584d8f4055fe61227b5` (dirty disclose on citing roofs).

## What landed

| Item | Path |
|---|---|
| Collected tests | `tests/test_os_01_02_collected.py` (T-OS-01, T-OS-02a–d) |
| Design (pre-code) | `design/os/` remains unscanned (`pytest.ini` norecursedirs) |

## Accept

`pytest tests/test_os_01_02_collected.py` reports 5 xfailed (strict). Flipping any
to pass without the feature is a CI fail.

## NOT measured

Live MCP, real taint engine, paid API, AgentDojo, judge apply.
