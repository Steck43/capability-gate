# Reproduce the paper evidence

This scaffold separates offline contract checks from live measurements. Hermes source stays pinned to `ccd8deaa6705bd6ca1890584d8f4055fe61227b5`.

## B1 — offline contract tier

```powershell
python -m pytest -q tests/test_wave2_offline_scaffolds.py
python -m pytest -q tests/test_gate_boundary.py tests/test_failclosed_rows.py tests/test_kill_switch.py tests/test_cc_adapter.py
python -c "import hashlib,pathlib; p=pathlib.Path('harness/truth-table-enforce-expected.json'); print(hashlib.sha256(p.read_bytes()).hexdigest())"
```

Expected T-COMP-02 fixture:

- rows: 96
- enforce oracle allows: 2
- fixture sha256: `57e3718feb056c403a97605cbab26b111f1bf5ebdcf33f87f7fc4791a457f555`
- every row has `status: LIVE` and `measured: false`

## B1 limits

These commands do not run Hermes, AgentDojo, a model, or aegisbox. They do not establish live mount coverage, end-to-end utility, attack success rate, box containment, judge application, or benign-day performance.

Live tiers must write separate receipts with immutable raw artifacts and final sha256 values. Do not promote the template digest placeholder or the expected truth table into a live result.
