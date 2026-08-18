#!/usr/bin/env python3
"""comment_craft.py — block narration comments in changed Python.

Seniors write *why* and *invariant* comments. Agent dumps write play-by-play
(\"This function loads the config\", \"Import necessary modules\", \"Loop through
the list\"). This gate fails those shapes in the diff hunk.

Exit 0 = clean. Exit 2 = hit(s) or measurement failure.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

EXIT_FAIL = 2

NARRATION = [
    (
        "NARRATE-FN",
        re.compile(
            r"#\s*This (function|method|class|script|module|code|file)\b",
            re.I,
        ),
        "Narration comment naming the construct",
        "Delete, or state the invariant / non-obvious why",
    ),
    (
        "NARRATE-IMPORT",
        re.compile(r"#\s*(Import|Imports|Bring in|Load the)\b", re.I),
        "Narration of an import",
        "Delete; imports are self-explanatory",
    ),
    (
        "NARRATE-LOOP",
        re.compile(r"#\s*(Loop|Iterate|Go through|For each)\b", re.I),
        "Play-by-play loop comment",
        "Delete, or name the invariant being preserved",
    ),
    (
        "NARRATE-RETURN",
        re.compile(r"#\s*(Return|Returns|Now return)\b", re.I),
        "Narration of a return",
        "Delete",
    ),
    (
        "TODO-AGENT",
        re.compile(r"#\s*(TODO|FIXME)\s*\((claude|cursor|gpt|copilot)\)", re.I),
        "Agent-tagged TODO",
        "Own it as Landen or delete",
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
        print(f"comment_craft: measurement failure: {exc}", file=sys.stderr)
        raise SystemExit(EXIT_FAIL) from exc
    if r.returncode not in (0, 1):
        print(f"comment_craft: git failed: {r.stderr}", file=sys.stderr)
        raise SystemExit(EXIT_FAIL)
    return r.stdout or ""


def added_comment_lines(diff: str) -> list[tuple[str, int, str]]:
    """Return (path, new_line_no, line) for added comment/doc lines."""
    path = ""
    new_line = 0
    out: list[tuple[str, int, str]] = []
    for raw in diff.splitlines():
        if raw.startswith("+++ b/"):
            path = raw[6:]
            new_line = 0
            continue
        if raw.startswith("@@"):
            # @@ -a,b +c,d @@
            m = re.search(r"\+(\d+)", raw)
            new_line = int(m.group(1)) - 1 if m else 0
            continue
        if not path or path == "/dev/null":
            continue
        if not path.endswith(".py"):
            if raw.startswith("+"):
                new_line += 1
            elif raw.startswith("-"):
                pass
            else:
                new_line += 1
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            new_line += 1
            line = raw[1:]
            stripped = line.lstrip()
            if stripped.startswith(("#", '"""', "'''")):
                out.append((path, new_line, line))
        elif raw.startswith("-"):
            continue
        else:
            new_line += 1
    return out


def scan_diff(diff: str) -> list[str]:
    hits: list[str] = []
    for path, line_no, line in added_comment_lines(diff):
        for rid, pat, what, fix in NARRATION:
            if pat.search(line):
                hits.append(
                    f"{path}:{line_no}: BLOCK {rid}: {what} — {line.strip()!r}. Fix: {fix}"
                )
    return hits


def selftest() -> int:
    sample = """\
diff --git a/foo.py b/foo.py
--- a/foo.py
+++ b/foo.py
@@ -1,3 +1,6 @@
+# This function loads the config
+def load():
+    # Loop through keys
+    return 1
+# Fail closed when mode is unknown — invariant
"""
    hits = scan_diff(sample)
    # Expect NARRATE-FN and NARRATE-LOOP; emdash line is not a narration rule here
    ok = any("NARRATE-FN" in h for h in hits) and any("NARRATE-LOOP" in h for h in hits)
    clean = scan_diff(
        """\
diff --git a/foo.py b/foo.py
--- a/foo.py
+++ b/foo.py
@@ -1,2 +1,3 @@
+# Fail closed when mode is unknown.
 def load():
     return 1
"""
    )
    bad = 0
    print(f"  {'ok' if ok else 'FAIL'} narration hits ({len(hits)})")
    if not ok:
        bad += 1
    print(f"  {'ok' if not clean else 'FAIL'} clean why-comment")
    if clean:
        bad += 1
        print(clean)
    print(f"\n{2 - bad}/2 selftest cases correct")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--base", default="origin/main")
    ap.add_argument("--head", default="HEAD")
    args = ap.parse_args()
    if args.selftest:
        return selftest()

    diff = _run(["git", "diff", f"{args.base}...{args.head}"])
    if not diff.strip():
        diff = _run(["git", "diff", f"{args.base}..{args.head}"])
    if not diff.strip():
        diff = _run(["git", "diff", "HEAD~1", "HEAD"])
    hits = scan_diff(diff)
    for h in hits:
        print(h, file=sys.stderr)
    if hits:
        print(f"comment_craft: {len(hits)} hit(s)", file=sys.stderr)
        return EXIT_FAIL
    print("comment_craft: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
