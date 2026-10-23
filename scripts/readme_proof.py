"""Keep the README Proof section equal to out/summary.json.

    python3 demos/readme_proof.py write   rewrite the Proof block from the summary
    python3 demos/readme_proof.py check   exit 1 if any README number disagrees

The block sits between the two proof markers in README.md. It holds one row
per scenario (scenario, seed, result, REAL or STUBBED) and one line of counts
per scenario, each named by scenario and seed, so every number in it traces to
a scenario run at a stated seed. It needs nothing outside the standard library.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
START = "<!-- proof:start -->"
END = "<!-- proof:end -->"
NUMBER = re.compile(r"\d+")


def render(summary: dict) -> str:
    rows = summary["scenarios"]
    out = [
        START,
        "| scenario | seed | result | REAL/STUBBED |",
        "|---|---|---|---|",
    ]
    for r in rows:
        mode = "REAL" if r["real"] else "STUBBED"
        out.append(f"| {r['scenario']} | {r['seed']} | {r['status']} | {mode} |")
    out += ["", "Counts from the same run (`actual` in out/summary.json):", ""]
    for r in rows:
        counts = ", ".join(f"{k}={v}" for k, v in r["actual"].items())
        out.append(
            f"- {r['scenario']}, seed {r['seed']}: events={r['events']}, {counts}"
        )
    out.append(END)
    return "\n".join(out)


def split(text: str) -> tuple[str, str, str]:
    if text.count(START) != 1 or text.count(END) != 1:
        raise SystemExit("README: expected exactly one proof:start and one proof:end")
    head, rest = text.split(START, 1)
    block, tail = rest.split(END, 1)
    return head, START + block + END, tail


def check(readme: Path, summary: dict) -> int:
    _, block, _ = split(readme.read_text(encoding="utf-8"))
    want = render(summary)
    if block == want:
        print(f"readme_proof: {readme.name} Proof section matches out/summary.json")
        return 0
    have_lines, want_lines = block.splitlines(), want.splitlines()
    print(f"readme_proof: {readme.name} Proof section does not match out/summary.json")
    for i in range(max(len(have_lines), len(want_lines))):
        h = have_lines[i] if i < len(have_lines) else ""
        w = want_lines[i] if i < len(want_lines) else ""
        if h != w:
            hn, wn = NUMBER.findall(h), NUMBER.findall(w)
            diff = [f"{a} != {b}" for a, b in zip(hn, wn) if a != b]
            if len(hn) != len(wn):
                diff.append(f"{len(hn)} numbers != {len(wn)} numbers")
            print(f"  README: {h}")
            print(f"  summary: {w}")
            if diff:
                print(f"  numbers: {', '.join(diff)}")
    return 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=("check", "write"))
    ap.add_argument("--readme", type=Path, default=ROOT / "README.md")
    ap.add_argument("--summary", type=Path, default=ROOT / "out" / "summary.json")
    args = ap.parse_args(argv)
    summary = json.loads(args.summary.read_text(encoding="utf-8"))
    if args.mode == "check":
        return check(args.readme, summary)
    head, _, tail = split(args.readme.read_text(encoding="utf-8"))
    args.readme.write_text(head + render(summary) + tail, encoding="utf-8")
    print(f"readme_proof: wrote the Proof section of {args.readme.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
