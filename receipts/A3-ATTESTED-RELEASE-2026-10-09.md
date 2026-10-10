# A3 — Attested release plugin-v0.1.1 (2026-10-09)

## Scope measured

Cut capability-gate plugin bundle `0.1.1` with the same SLSA provenance
attestation path as `plugin-v0.1.0`. A third party can verify with one command.
`always_invoked` stays false.

## Tips

| Item | Value |
|---|---|
| Tag | `plugin-v0.1.1` |
| Tagged commit | `f596b8f6d85a748f7cd69f32eec114a23b2ea8ba` |
| Workflow run | `38012814949` (plugin-bundle, success) |
| Release | https://github.com/Steck43/capability-gate/releases/tag/plugin-v0.1.1 |
| Asset | `capability-gate-plugin-0.1.1.zip` |
| Asset sha256 | `a363430649a92dc765935b4ee408e0bf2a37672c647c4737b807c0ce06b00a14` |

## Verify command (third party)

```
gh release download plugin-v0.1.1 --repo Steck43/capability-gate
gh attestation verify capability-gate-plugin-0.1.1.zip --repo Steck43/capability-gate
```

Measured this sitting: EXIT=0. `--format json` shows subject
`capability-gate-plugin-0.1.1.zip` digest sha256 `a3634306…0a14`, signer
workflow `.github/workflows/plugin-bundle.yml@refs/tags/plugin-v0.1.1`,
source digest `f596b8f6…`.

## Bundle members

`__init__.py`, `capability_gate.py`, `plugin.yaml`, `allowlist.example.yaml`,
plus `SHA256SUMS` of those bytes (includes the kill-switch tip on main).

## NOT measured

- Zenodo DOI mint for `0.1.1` (concept DOI still points at latest when tagged).
- Live Hermes load of the `0.1.1` zip on a running profile.
- `always_invoked` (stays false).

## Moves paper claim

None for the boundary centerpiece. Standing: an attested plugin zip exists at
`plugin-v0.1.1` and verifies with the published one-command check.
