# Stage-1 insufficiency matrix

Generated from `harness/evidence_receipt.json` on this roof.
Not a copy of any vault evidence file.

- CAUGHT-NAIVE: 7
- CORRECT-ALLOW: 4
- FALSE-ALLOW: 8
- FALSE-DENY: 0

| case | category | expected | verdict | matrix |
| --- | --- | --- | --- | --- |
| A1 | A | deny | deny | CAUGHT-NAIVE |
| A2 | A | deny | deny | CAUGHT-NAIVE |
| A3 | A | deny | deny | CAUGHT-NAIVE |
| A4 | A | deny | deny | CAUGHT-NAIVE |
| A5 | A | allow | allow | CORRECT-ALLOW |
| B1a | B | deny | allow | FALSE-ALLOW |
| B1b | B | deny | allow | FALSE-ALLOW |
| B2 | B | deny | allow | FALSE-ALLOW |
| C1 | C | deny | deny | CAUGHT-NAIVE |
| C2 | C | allow | allow | CORRECT-ALLOW |
| D1 | D | allow | allow | CORRECT-ALLOW |
| D2 | D | deny | allow | FALSE-ALLOW |
| E1 | E | deny | allow | FALSE-ALLOW |
| E2a | E | deny | allow | FALSE-ALLOW |
| F1 | F | deny | allow | FALSE-ALLOW |
| R1 | RED | deny | deny | CAUGHT-NAIVE |
| R2 | RED | allow | allow | CORRECT-ALLOW |
| R3 | RED | deny | ask | CAUGHT-NAIVE |
| S1 | S | deny | allow | FALSE-ALLOW |
