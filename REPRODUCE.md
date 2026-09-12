# Reproduce Stage-1 insufficiency

Cold clone. No vault. No host allowlist.

```
git clone https://github.com/Steck43/capability-gate.git
cd capability-gate
python -m pip install -r requirements-dev.txt
python -m pytest tests/test_harness_tally.py -q
```

The CG Stage-1 lab (`evidence_receipt.json`) asserts eighteen cases by id. A green print of `7/14` without those assertions is not this kit.

Expected tally on this HEAD, named harness CG Stage-1 lab (`tests/test_harness_tally.py`) against `capability_gate.py`:

- 14 deny-expected: 7 CAUGHT-NAIVE, 7 FALSE-ALLOW
- 4 CORRECT-ALLOW
- 0 FALSE-DENY

`plugin-v0.1.0` on Zenodo (`10.5281/zenodo.22018053`) predates this kit. The concept DOI `10.5281/zenodo.22018052` resolves to the latest release.

To emit the in-roof receipt and matrix:

```
python harness/lab_insufficiency_harness.py
```

Writes `harness/evidence_receipt.json` and `harness/MATRIX.md`. Those files are generated from this run, not copied from a vault.
