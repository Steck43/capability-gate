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
  substring, so a name glued to other text ("NameReview") still matches;
  prefix it with "re:" for a raw regex, for example word boundaries on a name
  that is also part of common words. Blank lines and lines starting with "#"
  are skipped, and so is the line "zqxwvk" in any case: the same list feeds
  another repository's scan, which needs that fixed canary, and it names
  nothing private. A list holding only the canary counts as not configured.

Modes:

  --staged            lines the staged change adds (pre-commit)
  --ci --base B       lines each commit in B..HEAD adds, judged commit by commit
                      so a name added and later removed is still caught, plus
                      those commits' messages
  --text LABEL        text on stdin (for example a pull request title and body)
  --tree              every tracked file at HEAD (reports counts by file)
  FILE ...            the named files

Output names file and line only. The matched text is never printed, so a CI log
cannot republish what the scan exists to stop. File names are scanned too, and a
path that matches any rule is shown only as "file #" and a tag keyed with a
fresh random key each run, so a list of candidate names cannot confirm a tag
offline; git's own error text (which can quote a path) is never printed.

Exit 0 = clean. Exit 1 = hit, or no denylist configured in --ci mode (fail
closed: a scan with no list would pass everything). Exit 2 = usage or git
error, including a diff header this script cannot parse, so an unreadable file
name fails instead of being skipped.

Known gaps: text in encodings other than UTF-8 (UTF-16 diffs as binary),
binary file contents, "~" and environment-variable home paths,
forward-slash Windows paths, IP addresses written in other forms, and anything
committed with --no-verify before CI runs.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ENV_VAR = "LEAK_DENYLIST"
CANARY = "zqxwvk"
LOCAL_FILE = "leak-denylist"

_OCTET = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
BUILTIN: list[tuple[str, re.Pattern[str]]] = [
    (
        "windows-user-home-path",
        re.compile(r"(?i)\b[A-Z]:\\{1,2}Users\\{1,2}[^\\/\s\"'`]+"),
    ),
    ("posix-home-path", re.compile(r"/home/[A-Za-z0-9._-]+")),
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
        # git's message can quote a path or a ref; print only what ran and how.
        verb = next((a for a in args if not a.startswith("-") and "=" not in a), "")
        print(f"leak scan: git {verb} failed (exit {r.returncode})", file=sys.stderr)
        raise SystemExit(2)
    return r.stdout


def _compile_line(line: str) -> re.Pattern[str]:
    if line.startswith("re:"):
        return re.compile(line[3:], re.I)
    return re.compile(re.escape(line), re.I)


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
    pats = [
        _compile_line(ln)
        for ln in lines
        if ln and not ln.startswith("#") and ln.casefold() != CANARY
    ]
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


# A fresh key each run: a printed tag names the same file within one run's
# output, and nobody holding a list of candidate names can recompute it.
_RUN_KEY = os.urandom(16)


def _digest(text: str) -> str:
    data = text.encode("utf-8", "replace")
    return "#" + hmac.new(_RUN_KEY, data, hashlib.sha256).hexdigest()[:12]


def _shown(where: str, names: list[re.Pattern[str]]) -> str:
    """The label to print: a path that matches any rule is shown only as a hash."""
    path, sep, rest = where.partition(" @ ")
    if scan_text(path, names):
        return f"file {_digest(path)}{sep}{rest}"
    return where


def _paths(*diff_args: str) -> list[str]:
    """Every path a diff touches, text or binary, so each file name is scanned."""
    out = _git(
        "-c",
        "core.quotepath=false",
        "diff",
        "--name-only",
        "-z",
        "--no-renames",
        *diff_args,
    )
    return [p for p in out.split("\0") if p]


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
_C_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13}


def _unquote(name: str) -> str:
    """Undo git's C-style quoting of a path: octal bytes and backslash escapes."""
    if not (name.startswith('"') and name.endswith('"')):
        return name
    raw = name[1:-1]
    out = bytearray()
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch != "\\":
            out += ch.encode("utf-8")
            i += 1
        elif raw[i + 1 : i + 4].isdigit() and len(raw[i + 1 : i + 4]) == 3:
            out.append(int(raw[i + 1 : i + 4], 8))
            i += 4
        else:
            nxt = raw[i + 1]
            out.append(_C_ESCAPES.get(nxt, ord(nxt)))
            i += 2
    return out.decode("utf-8", errors="replace")


def _target(header: str) -> str | None:
    """Path from a '+++ ' header line; None for /dev/null. Unparseable exits 2."""
    name = _unquote(header[4:].rstrip("\t"))
    if name == "/dev/null":
        return None
    if not name.startswith("b/"):
        print(f"leak scan: cannot parse diff header {_digest(header)}", file=sys.stderr)
        raise SystemExit(2)
    return name[2:]


def _added_lines(*diff_args: str) -> list[tuple[str, str]]:
    """Added lines only, placed at their real line numbers (other lines left blank).

    Scanning whole files would fail every edit to a file that already carries a
    known hit, so pre-commit and CI judge only what the change adds.
    """
    diff = _git(
        "-c",
        "core.quotepath=false",
        "diff",
        "--unified=0",
        "--no-color",
        "--no-ext-diff",
        "--no-renames",
        *diff_args,
    )
    by_file: dict[str, dict[int, str]] = {}
    current = None
    lineno = 0
    # A file header is only the block between "diff --git" and the first "@@".
    # After that every "+" line is content, even one whose text starts "++ b/".
    in_header = False
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            in_header, current = True, None
        elif in_header and line.startswith("+++ "):
            current = _target(line)
        elif m := _HUNK.match(line):
            in_header = False
            lineno = int(m.group(1))
        elif in_header:
            continue
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


_EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def _per_commit(base: str, head: str) -> list[tuple[str, str]]:
    """Added lines of each commit on its own, against its first parent."""
    out = []
    for row in _git("rev-list", "--parents", f"{base}..{head}").splitlines():
        sha, *parents = row.split()
        args = (
            [f"{sha}^!"]
            if len(parents) == 1
            else [parents[0] if parents else _EMPTY_TREE, sha]
        )
        out += [(f"{path} @ {sha[:12]}", text) for path, text in _added_lines(*args)]
    return out


def _per_commit_paths(base: str, head: str) -> list[str]:
    out = []
    for row in _git("rev-list", "--parents", f"{base}..{head}").splitlines():
        sha, *parents = row.split()
        args = (
            [f"{sha}^!"]
            if len(parents) == 1
            else [parents[0] if parents else _EMPTY_TREE, sha]
        )
        out += [f"{path} @ {sha[:12]}" for path in _paths(*args)]
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
    mode.add_argument("--text", metavar="LABEL")
    ap.add_argument("--base", help="base ref for --ci")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("files", nargs="*")
    a = ap.parse_args(argv)

    names = load_denylist()
    if names is None:
        if a.ci or a.text:
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

    paths: list[str] = []
    if a.ci:
        if not a.base:
            ap.error("--ci needs --base")
        targets = _per_commit(a.base, a.head) + _messages(a.base, a.head)
        paths = _per_commit_paths(a.base, a.head)
    elif a.text:
        targets = [(a.text, sys.stdin.read())]
    elif a.staged:
        targets = _added_lines("--cached")
        paths = _paths("--cached")
    elif a.tree:
        targets = _tree()
        paths = [p for p in _git("ls-files", "-z").split("\0") if p]
    else:
        targets = []
        for f in a.files:
            # Judge and show the name as the repository sees it, not the
            # absolute path of the working copy on this machine.
            rel = os.path.relpath(f)
            where = f if rel.startswith("..") else Path(rel).as_posix()
            try:
                targets.append(
                    (where, Path(f).read_text(encoding="utf-8", errors="replace"))
                )
            except OSError as exc:
                print(
                    f"leak scan: cannot read file {_digest(f)} ({type(exc).__name__})",
                    file=sys.stderr,
                )
                return 2
        paths = [where for where, _text in targets]

    total = 0
    per_file: Counter[str] = Counter()
    found: list[tuple[str, int, str]] = []
    for where in paths:
        for _n, label in scan_text(where.partition(" @ ")[0], names):
            found.append((where, 0, f"file name, {label}"))
    for where, text in targets:
        found += [(where, n, label) for n, label in scan_text(text, names)]
    for where, n, label in found:
        total += 1
        shown = _shown(where, names)
        per_file[shown] += 1
        if not a.tree:
            print(f"{shown}:{n}: {label}")
    if a.tree:
        for where, count in sorted(per_file.items()):
            print(f"{count}\t{where}")
    print(
        f"leak scan: {total} hit(s) in {len(per_file)} file(s), {len(targets)} scanned"
    )
    return 1 if total else 0


if __name__ == "__main__":
    raise SystemExit(main())
