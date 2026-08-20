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
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
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


# --- EMDASH: position matters, the character does not -------------------------
#
# Landen's ruling, 2026-08-18: an em dash used for FORMATTING is fine; an em
# dash used as a GRAMMATICAL BREAK is the tell. The original rule was
# re.compile("—") - a bare character match with no context, which is why it
# produced 114 of 114 hits on isolation-layer-review while the rules aimed at
# actual slop (AI vocab, chatbot phrasing, trailers) found nothing at all. A
# detector whose loudest rule is also its least meaningful one gets removed.
#
# A formatting dash follows a STRUCTURAL MARKER: a heading, a table cell, a list
# label, or a bold/link/code label. It separates a label from its gloss.
# A grammatical dash sits in a plain sentence and joins clauses. Shortness alone
# is NOT the discriminator - "Ship the floor — then unlock egress." has a short
# left side and is exactly the thing being caught.
EMDASH = "—"
_HEADING = re.compile(r"^\s*#{1,6}\s")
_LIST_MARK = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
_FM_KEY = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_-]*:\s")
_MARKUP_LABEL = re.compile(
    r"^\s*(?:\*\*.+?\*\*|__.+?__|`.+?`|\[.+?\]\([^)]*\))\s*" + EMDASH
)
_LABEL_MAX = 60


def _strip_label_spans(line: str) -> str:
    """Remove emphasis and code spans - a dash inside one is part of a label.

    `**Stage 0 - Ingestion (Q0).**` names a stage; the dash separates the
    number from the name. That is the same construct as a heading, just inline.
    A dash that survives this strip is sitting in open prose.
    """
    line = re.sub(r"\*\*.+?\*\*", "", line)
    line = re.sub(r"__.+?__", "", line)
    line = re.sub(r"`[^`]*`", "", line)
    return line


def _emdash_is_formatting(line: str) -> bool:
    """True when the em dash on this line is structural, not grammatical."""
    if EMDASH not in _strip_label_spans(line):
        return True
    if _HEADING.match(line):
        return True
    if "|" in line:  # table row
        return True
    if _FM_KEY.match(line):  # frontmatter / key: value
        return True
    if _MARKUP_LABEL.match(line):  # **Label** - gloss
        return True
    m = _LIST_MARK.match(line)
    if m:
        label = line[m.end() :].split(EMDASH, 1)[0].strip()
        # Strip link targets and code spans first. A filename inside a link -
        # `[OPEN NOW](open.md)` - carries a dot that is not sentence punctuation,
        # and reading it as one misfiles an index line as prose.
        label = re.sub(r"\]\([^)]*\)", "]", label)
        label = re.sub(r"`[^`]*`", "", label)
        # A list LABEL is a short noun phrase. A list item that has run on into
        # full sentences before reaching the dash is prose wearing a bullet.
        if len(label) <= _LABEL_MAX and not re.search(r"[.!?]", label):
            return True
    return False


def scan_emdash(label: str, text: str) -> list[str]:
    hits: list[str] = []
    in_fence = False
    in_frontmatter = False
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if i == 1 and stripped == "---":
            in_frontmatter = True
            continue
        if in_frontmatter:
            if stripped in ("---", "..."):
                in_frontmatter = False
            continue
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_fence = not in_fence
            continue
        if in_fence or EMDASH not in line:
            continue
        if _emdash_is_formatting(line):
            continue
        hits.append(
            f"{label}:{i}: BLOCK EMDASH: Em dash as a grammatical break. "
            f"saw {line.strip()[:70]!r}. "
            "Fix: use a period, comma, or colon. Formatting dashes "
            "(headings, tables, list labels) are fine."
        )
    return hits


def _blank(line: str) -> str:
    """Same length, same newlines, no words. Offsets must survive masking so a
    hit still reports the real line number and the real snippet."""
    return re.sub(r"[^\n]", " ", line)


def mask_non_prose(text: str) -> str:
    """Blank the spans that quote rather than assert.

    Found 2026-08-19: the pack's own `SENIOR-CRAFT-FLOOR.md` fails this linter.
    Its negative-control section tells you to plant "Additionally, this pivotal
    landscape" in a README to prove `craft (voice)` goes red, and the linter
    read the instruction as the offence. A rule that cannot survive being
    documented gets the documentation weakened instead of the rule.

    scan_emdash already skipped frontmatter and fenced blocks. The RULES loop
    did not, so the two halves of one linter disagreed about what counted as
    prose. This is that skip, shared, plus inline code spans.

    Note the deliberate hole: slop inside backticks is not flagged. A code span
    is an explicit quotation, which is exactly the distinction being drawn, and
    fenced blocks were already exempt on the same reasoning.
    """
    out: list[str] = []
    in_fence = False
    in_frontmatter = False
    for i, line in enumerate(text.splitlines(keepends=True), 1):
        stripped = line.strip()
        if i == 1 and stripped == "---":
            in_frontmatter = True
            out.append(_blank(line))
            continue
        if in_frontmatter:
            if stripped in ("---", "..."):
                in_frontmatter = False
            out.append(_blank(line))
            continue
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_fence = not in_fence
            out.append(_blank(line))
            continue
        if in_fence:
            out.append(_blank(line))
            continue
        out.append(re.sub(r"`[^`\n]*`", lambda m: " " * len(m.group(0)), line))
    return "".join(out)


def scan_text(label: str, text: str, *, fail_on_warn: bool) -> list[str]:
    hits: list[str] = []
    # Match against masked text so quotations do not read as assertions, but
    # report from the original: masking preserves every offset.
    masked = mask_non_prose(text)
    for rid, sev, pat, what, fix in RULES:
        if sev == "WARN" and not fail_on_warn:
            continue
        for m in pat.finditer(masked):
            line_no = text[: m.start()].count("\n") + 1
            snippet = text[m.start() : m.end()].replace("\n", " ")[:80]
            hits.append(
                f"{label}:{line_no}: {sev} {rid}: {what}. saw {snippet!r}. Fix: {fix}"
            )
    hits.extend(scan_emdash(label, text))
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
    total = 0

    def expect(label: str, text: str, want_hit: bool) -> None:
        nonlocal bad, total
        total += 1
        hits = scan_text(label, text, fail_on_warn=True)
        got = bool(hits)
        ok = got == want_hit
        print(f"  {'ok' if ok else 'FAIL'} {label} want_hit={want_hit} got={got}")
        if not ok:
            bad += 1
            for h in hits[:3]:
                print(f"    {h}")

    expect("nc-vocab", "Additionally, this pivotal landscape is crucial.", True)
    # Mention, not use. Every one of these carries the same banned words as the
    # line above, which must stay red.
    expect(
        "ok-vocab-in-fence",
        "Plant this:\n\n```\nAdditionally, this pivotal landscape is crucial.\n```\n",
        False,
    )
    expect(
        "ok-vocab-in-code-span",
        "Plant `Additionally, this pivotal landscape` in a README to prove it goes red.",
        False,
    )
    expect(
        "ok-vocab-in-frontmatter",
        "---\ntitle: Additionally the pivotal landscape\n---\n\nClean prose here.\n",
        False,
    )
    expect(
        "nc-vocab-after-a-fence-closes",
        "```\ncode\n```\n\nAdditionally, this pivotal landscape is crucial.\n",
        True,
    )
    expect(
        "nc-vocab-outside-backticks",
        "Run `make check`. Additionally, this pivotal landscape is crucial.",
        True,
    )
    expect("nc-chat", "I hope this helps! Let me know if you need anything.", True)
    expect("nc-emdash", "Ship the floor — then unlock egress.", True)
    # Grammatical breaks: still blocked.
    expect("nc-emdash-paired", "The floor — not the judge — decides.", True)
    expect(
        "nc-emdash-longbullet",
        "- The floor is CI on someone else's machine, and it only binds once "
        "it is required — which is a settings flip.",
        True,
    )
    # Formatting: allowed.
    expect("ok-emdash-heading", "# Artifact Index — volume 2", False)
    expect("ok-emdash-table", "| 2026-08-18 | path | what — detail | LIVE |", False)
    expect("ok-emdash-bold", "**Floor** — deterministic, non-bypassable", False)
    expect("ok-emdash-list", "- gitleaks — secrets, working tree and history", False)
    expect("ok-emdash-link", "- [OPEN NOW](open.md) — read this first", False)
    expect("nc-trailer", "Co-Authored-By: Cursor <cursor@example.com>", True)
    expect(
        "clean",
        "Require PR plus floor checks before merge. Author: Landen Stecker.",
        False,
    )
    print(f"\n{total - bad}/{total} selftest cases correct")
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
        print(
            "voice_lint: nothing to scan (pass --commits and/or --prose/--paths)",
            file=sys.stderr,
        )
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
