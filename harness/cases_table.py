"""CASES.md is derived from the harness sets. Hand-typed counts are a fail."""

from __future__ import annotations

from pathlib import Path

from lab_insufficiency_harness import CAUGHT, CORRECT_ALLOW, FALSE_ALLOW

ROOF = Path(__file__).resolve().parents[1]
CASES_PATH = ROOF / "harness" / "CASES.md"


def cases_markdown() -> str:
    lines = [
        "# Stage-1 CASES",
        "",
        "Derived from `CAUGHT` / `FALSE_ALLOW` / `CORRECT_ALLOW` in",
        "`harness/lab_insufficiency_harness.py`. Do not hand-edit the counts.",
        "README order is caught / false-allow / correct / false-deny.",
        "",
        f"- CAUGHT-NAIVE: {len(CAUGHT)}",
        f"- FALSE-ALLOW: {len(FALSE_ALLOW)}",
        f"- CORRECT-ALLOW: {len(CORRECT_ALLOW)}",
        "- FALSE-DENY: 0",
        f"- cases: {len(CAUGHT) + len(FALSE_ALLOW) + len(CORRECT_ALLOW)}",
        f"- deny-expected: {len(CAUGHT) + len(FALSE_ALLOW)}",
        "",
        "| id | matrix |",
        "| --- | --- |",
    ]
    for cid in CAUGHT:
        lines.append(f"| {cid} | CAUGHT-NAIVE |")
    for cid in FALSE_ALLOW:
        lines.append(f"| {cid} | FALSE-ALLOW |")
    for cid in CORRECT_ALLOW:
        lines.append(f"| {cid} | CORRECT-ALLOW |")
    lines.append("")
    return "\n".join(lines)


def write_cases(path: Path | None = None) -> Path:
    dest = path or CASES_PATH
    dest.write_text(cases_markdown(), encoding="utf-8")
    return dest
