# Security policy

## Supported versions

The default branch is the supported line. Older tags are snapshots; they do not receive backports unless a release note says otherwise.

## Reporting a vulnerability

Use GitHub private vulnerability reporting on this repository (Security tab, then Report a vulnerability). Do not open a public issue for a live vulnerability.

I read reports and reply when I can. There is no promised SLA. If I confirm the issue I will say so, patch on a private fork when needed, and credit you if you want that.

Please include: affected version or commit, what you did, what you expected, and a minimal repro.

## Known limit: same OS user

An attacker running as the same OS user as the agent can rewrite the log, the witness and the anchor together, and capability-gate does not detect it. Moving the anchor to another folder does not change this, because the same user can still write the new folder. Tamper evidence holds only against a writer that cannot reach all three files.

`tests/test_witness_tamper.py` pins this as a strict expected failure, `test_default_anchor_log_witness_and_anchor_rewritten`. An anchor the agent's OS user cannot write is planned and is not in this release. Please do not report this limit as a new finding; do report any way around it that does not need the same OS user.
