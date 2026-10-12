#!/usr/bin/env python3
"""Fail on private names and personal paths in text headed for a public repo.

Two pattern sources:

* Built-in shapes: Windows and POSIX user-home paths, and private IPv4 ranges.
  Same shapes as .gitleaks.toml, repeated here so the commit-message check and
  the pre-commit check do not depend on a gitleaks install.
* A denylist of names (machines, agents, people, hosts). The list never lives in
  the tree, because publishing it would be the leak. It is read from the
  LEAK_DENYLIST environment variable (one pattern per line) or, locally, from
  the untracked file .git/info/leak-denylist. A line is a case-insensitive
  whole-word literal; prefix it with "re:" for a raw regex. Blank lines and
  lines starting with "#" are skipped.

Modes:

  --staged            lines the staged change adds (pre-commit)
  --ci --base B       lines added in B..HEAD plus the commit messages in B..HEAD
  --tree              every tracked file at HEAD (reports counts by file)
  FILE ...            the named files

Output names file and line only. The matched text is never printed, so a CI log
cannot republish what the scan exists to stop.

Exit 0 = clean. Exit 1 = hit, or no denylist configured in --ci mode (fail
closed: a scan with no list would pass everything). Exit 2 = usage or git error.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ENV_VAR = "LEAK_DENYLIST"
LOCAL_FILE = "leak-denylist"

_OCTET = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
BUILTIN: list[tuple[str, re.Pattern[str]]] = [
    (
        "windows-user-home-path",
        re.compile(r"(?i)\b[A-Z]:\\{1,2}Users\\{1,2}[^\\/\s\"'`]+"),
    ),
    ("posix-home-path", re.compile(r"/home/[A-Za-z0-9._-]+/")),
    (
        "private-ipv4",
        re.compile(
            r"\b(?:10\." + _OCTET + r"|172\.(?:1[6-9]|2\d|3[01])|192\.168"
            r"|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7]))"
            r"\." + _OCTET + r"\." + _OCTET + r"\b"
        ),
    ),
]


def _git(*args: str, check: bool = True) -> str:
    r = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if check and r.returncode != 0:
        print(
            f"leak scan: git {' '.join(args)} failed: {r.stderr.strip()}",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return r.stdout


def _compile_line(line: str) -> re.Pattern[str]:
    if line.startswith("re:"):
        return re.compile(line[3:], re.I)
    return re.compile(r"(?<!\w)" + re.escape(line) + r"(?!\w)", re.I)


def load_denylist() -> list[re.Pattern[str]] | None:
    """Patterns from the env var, else the untracked local file. None = not configured."""
    raw = os.environ.get(ENV_VAR)
    if raw is None or not raw.strip():
        common = _git("rev-parse", "--git-common-dir", check=False).strip()
        path = Path(common) / "info" / LOCAL_FILE if common else None
        if path is None or not path.is_file():
            return None
        raw = path.read_text(encoding="utf-8")
    lines = [ln.strip() for ln in raw.splitlines()]
    pats = [_compile_line(ln) for ln in lines if ln and not ln.startswith("#")]
    return pats or None


def scan_text(text: str, names: list[re.Pattern[str]]) -> list[tuple[int, str]]:
    """(line number, rule label) per hit. Labels never contain the matched text."""
    hits: list[tuple[int, str]] = []
    for n, line in enumerate(text.splitlines(), 1):
        for label, pat in BUILTIN:
            if pat.search(line):
                hits.append((n, label))
        for i, pat in enumerate(names, 1):
            if pat.search(line):
                hits.append((n, f"denylist entry {i}"))
    return hits


def _tree() -> list[tuple[str, str]]:
    out = []
    for path in _git("ls-files", "-z").split("\0"):
        p = Path(path)
        if path and p.is_file():
            data = p.read_bytes()
            if b"\0" not in data[:8192]:
                out.append((path, data.decode("utf-8", errors="replace")))
    return out


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def _added_lines(*diff_args: str) -> list[tuple[str, str]]:
    """Added lines only, placed at their real line numbers (other lines left blank).

    Scanning whole files would fail every edit to a file that already carries a
    known hit, so pre-commit and CI judge only what the change adds.
    """
    diff = _git(
        "diff", "--unified=0", "--no-color", "--no-ext-diff", "--no-renames", *diff_args
    )
    by_file: dict[str, dict[int, str]] = {}
    current = None
    lineno = 0
    for line in diff.splitlines():
        if line.startswith("+++ "):
            current = line[6:] if line.startswith("+++ b/") else None
        elif m := _HUNK.match(line):
            lineno = int(m.group(1))
        elif current and line.startswith("+"):
            by_file.setdefault(current, {})[lineno] = line[1:]
            lineno += 1
    out = []
    for path, added in by_file.items():
        rows = [""] * max(added)
        for n, text in added.items():
            rows[n - 1] = text
        out.append((path, "\n".join(rows)))
    return out


def _messages(base: str, head: str) -> list[tuple[str, str]]:
    out = []
    for sha in _git("rev-list", f"{base}..{head}").split():
        out.append(
            (f"commit {sha[:12]} message", _git("log", "-1", "--format=%B", sha))
        )
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true")
    mode.add_argument("--ci", action="store_true")
    mode.add_argument("--tree", action="store_true")
    ap.add_argument("--base", help="base ref for --ci")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("files", nargs="*")
    a = ap.parse_args(argv)

    names = load_denylist()
    if names is None:
        if a.ci:
            print(
                f"leak scan: denylist not configured ({ENV_VAR} is empty); failing closed"
            )
            return 1
        print(
            f"leak scan: no denylist configured ({ENV_VAR} or .git/info/{LOCAL_FILE}); "
            "checking built-in path and address shapes only",
            file=sys.stderr,
        )
        names = []

    if a.ci:
        if not a.base:
            ap.error("--ci needs --base")
        targets = _added_lines(f"{a.base}..{a.head}") + _messages(a.base, a.head)
    elif a.staged:
        targets = _added_lines("--cached")
    elif a.tree:
        targets = _tree()
    else:
        targets = [
            (f, Path(f).read_text(encoding="utf-8", errors="replace")) for f in a.files
        ]

    total = 0
    per_file: Counter[str] = Counter()
    for where, text in targets:
        for n, label in scan_text(text, names):
            total += 1
            per_file[where] += 1
            if not a.tree:
                print(f"{where}:{n}: {label}")
    if a.tree:
        for where, count in sorted(per_file.items()):
            print(f"{count}\t{where}")
    print(
        f"leak scan: {total} hit(s) in {len(per_file)} file(s), {len(targets)} scanned"
    )
    return 1 if total else 0


if __name__ == "__main__":
    raise SystemExit(main())
