#!/usr/bin/env python3
"""voice_lint.py — deterministic anti-slop / clone-fidelity pattern floor.

Derived from aegis-corner skill egress-voice. This is NOT a claim that Landen
authored the text. It fails closed on known AI/slop tells in commits and
public prose so agent dumps do not pass required CI.

Exit 0 = clean. Exit 2 = hit(s) or measurement failure.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

EXIT_FAIL = 2

# (rule_id, severity, pattern, what, fix) — patterns from egress-voice bars.
RULES: list[tuple[str, str, re.Pattern[str], str, str]] = [
    (
        "AI-VOCAB",
        "BLOCK",
        re.compile(
            r"\b(additionally|crucial|delve|enduring|enhance|fostering|garner|"
            r"interplay|intricate|pivotal|showcase|tapestry|testament|underscore|"
            r"vibrant|landscape)\b",
            re.I,
        ),
        "AI vocabulary / abstract landscape metaphor",
        "Use a plain concrete word",
    ),
    (
        "SIGNIFICANCE",
        "BLOCK",
        re.compile(
            r"pivotal moment|testament to|evolving landscape|setting the stage|"
            r"indelible mark|deeply rooted|groundbreaking|seamlessly",
            re.I,
        ),
        "Significance inflation / promotional sludge",
        "State what happened without puffery",
    ),
    (
        "CHATBOT",
        "BLOCK",
        re.compile(
            r"I hope this helps|Let me know if|Of course!|Certainly!|"
            r"Great question|You're absolutely right|Found the smoking gun",
            re.I,
        ),
        "Chatbot / sycophantic phrase",
        "Delete; speak as the operator",
    ),
    (
        "FILLER",
        "WARN",
        re.compile(
            r"\bIn order to\b|\bDue to the fact that\b|"
            r"\bIt is important to note that\b|\bcould potentially\b",
            re.I,
        ),
        "Filler / hedge stack",
        "Tighten: To / Because / delete / may",
    ),
    (
        "EMDASH",
        "BLOCK",
        re.compile(r"—"),
        "Em dash (AI tell on this estate)",
        "Use a period or comma",
    ),
    (
        "AI-TRAILER",
        "BLOCK",
        re.compile(
            r"co-authored-by:.*(claude|cursor|copilot|gpt|gemini|assistant)|"
            r"generated with .*(claude|cursor|copilot)",
            re.I,
        ),
        "AI authorship trailer",
        "Author line is Landen Stecker only",
    ),
    (
        "NOT-JUST",
        "WARN",
        re.compile(r"it's not just .{1,40}, it's ", re.I),
        "Negative parallelism template",
        "State the point directly",
    ),
]


def _run(cmd: list[str]) -> str:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
    except OSError as exc:
        print(f"voice_lint: measurement failure: {exc}", file=sys.stderr)
        raise SystemExit(EXIT_FAIL) from exc
    if r.returncode not in (0, 1):  # git log empty ranges can be 0
        if r.returncode != 0 and "does not have any commits" not in (r.stderr or ""):
            print(
                f"voice_lint: {' '.join(cmd)} exited {r.returncode}: {r.stderr}",
                file=sys.stderr,
            )
            raise SystemExit(EXIT_FAIL)
    return r.stdout or ""


def scan_text(label: str, text: str, *, fail_on_warn: bool) -> list[str]:
    hits: list[str] = []
    for rid, sev, pat, what, fix in RULES:
        if sev == "WARN" and not fail_on_warn:
            continue
        for m in pat.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            snippet = m.group(0).replace("\n", " ")[:80]
            hits.append(
                f"{label}:{line_no}: {sev} {rid}: {what}. saw {snippet!r}. Fix: {fix}"
            )
    return hits


def scan_commits(base: str, head: str, *, fail_on_warn: bool) -> list[str]:
    # Prefer range; fall back to last 20 if base missing.
    out = _run(["git", "log", f"{base}..{head}", "--format=%B"])
    if not out.strip():
        out = _run(["git", "log", "-n", "20", "--format=%B"])
    return scan_text("commit", out, fail_on_warn=fail_on_warn)


def scan_paths(paths: list[Path], *, fail_on_warn: bool) -> list[str]:
    hits: list[str] = []
    for path in paths:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"voice_lint: cannot read {path}: {exc}", file=sys.stderr)
            raise SystemExit(EXIT_FAIL) from exc
        hits.extend(scan_text(str(path), text, fail_on_warn=fail_on_warn))
    return hits


def default_prose_paths(root: Path) -> list[Path]:
    names = ["CHANGELOG.md", "CHANGELOG", "README.md", "README"]
    found = [root / n for n in names if (root / n).is_file()]
    docs = root / "docs"
    if docs.is_dir():
        found.extend(sorted(docs.rglob("*.md")))
    return found


def selftest() -> int:
    bad = 0

    def expect(label: str, text: str, want_hit: bool) -> None:
        nonlocal bad
        hits = scan_text(label, text, fail_on_warn=True)
        got = bool(hits)
        ok = got == want_hit
        print(f"  {'ok' if ok else 'FAIL'} {label} want_hit={want_hit} got={got}")
        if not ok:
            bad += 1
            for h in hits[:3]:
                print(f"    {h}")

    expect("nc-vocab", "Additionally, this pivotal landscape is crucial.", True)
    expect("nc-chat", "I hope this helps! Let me know if you need anything.", True)
    expect("nc-emdash", "Ship the floor — then unlock egress.", True)
    expect("nc-trailer", "Co-Authored-By: Cursor <cursor@example.com>", True)
    expect(
        "clean",
        "Require PR plus floor checks before merge. Author: Landen Stecker.",
        False,
    )
    print(f"\n{5 - bad}/5 selftest cases correct")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--commits", action="store_true", help="scan git commit messages")
    ap.add_argument("--base", default="origin/main")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--paths", nargs="*", type=Path, help="explicit files to scan")
    ap.add_argument(
        "--prose",
        action="store_true",
        help="scan CHANGELOG/README/docs under cwd",
    )
    ap.add_argument(
        "--fail-on-warn",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="treat WARN rules as failing (default: true for CI)",
    )
    args = ap.parse_args()
    if args.selftest:
        return selftest()

    hits: list[str] = []
    fail_on_warn = bool(args.fail_on_warn)
    if args.commits:
        hits.extend(scan_commits(args.base, args.head, fail_on_warn=fail_on_warn))
    paths = list(args.paths or [])
    if args.prose:
        paths.extend(default_prose_paths(Path.cwd()))
    if paths:
        hits.extend(scan_paths(paths, fail_on_warn=fail_on_warn))
    if not args.commits and not paths:
        print("voice_lint: nothing to scan (pass --commits and/or --prose/--paths)", file=sys.stderr)
        return EXIT_FAIL
    for h in hits:
        print(h, file=sys.stderr)
    if hits:
        print(f"voice_lint: {len(hits)} hit(s)", file=sys.stderr)
        return EXIT_FAIL
    print("voice_lint: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
