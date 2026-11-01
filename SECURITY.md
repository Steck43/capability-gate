# Security policy

## Supported versions

The default branch is the supported line. Older tags are snapshots; they do not receive backports unless a release note says otherwise.

## Reporting a vulnerability

Use GitHub private vulnerability reporting on this repository: https://github.com/Steck43/capability-gate/security/advisories/new (Security tab, then Report a vulnerability). Do not open a public issue for a live vulnerability.

I read reports and reply when I can. There is no promised SLA. If I confirm the issue I will say so, patch on a private fork when needed, and credit you if you want that.

Please include: affected version or commit, what you did, what you expected, and a minimal repro.

## Known limit: same OS user

An attacker running as the same OS user as the agent can rewrite the log, the witness and the anchor together, and capability-gate does not detect it. Moving the anchor to another folder does not change this, because the same user can still write the new folder. Tamper evidence holds only against a writer that cannot reach all three files.

A gate can now take a signed checkpoint (`Gate(..., checkpoint=CheckpointConfig(...))`). A CI job that alone holds the signing key signs a C2SP checkpoint of the log: origin, tree size and RFC 9162 Merkle root. It signs only when a consistency proof shows the new log extends the last signed one. On every decision the gate checks its log against the newest signed checkpoint in a local folder, and a log that does not match is denied. With that in place, the same-user rewrite of rows a checkpoint covers is denied: `tests/test_c4_checkpoint.py` runs the A1, A2, A3b and A4 attacks, and `test_default_anchor_log_witness_and_anchor_rewritten` passes with a checkpoint configured.

What a checkpoint does not cover:

- rows written after the newest signed checkpoint, until the next one is signed;
- an older genuine note left after the newest is deleted, until the next sync from the signed branch;
- a gate with no checkpoint configured. Neither hook sets one yet.

Please do not report these limits as new findings; do report any way around them that does not need the same OS user.
