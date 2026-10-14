#!/usr/bin/env python3
"""Fail on private names and personal paths in text headed for a public repo.

Pattern sources:

* Built-in shapes: user-home paths (Windows with either slash, POSIX, macOS,
  WSL mounts and WSL network paths) and private IPv4 ranges. The same shapes
  are in .gitleaks.toml, repeated here so the commit-message check and the
  pre-commit check do not depend on a gitleaks install.
* Style shapes that must not reach public text: em and en dashes, and AI
  authorship trailers.
* A denylist of names (machines, agents, people, hosts, folder names). The
  list never lives in the tree, because publishing it would be the leak. It is
  read from the LEAK_DENYLIST environment variable (one pattern per line) or,
  locally, from the untracked file .git/info/leak-denylist. A line is a
  case-insensitive substring, so a name glued to other text ("NameReview")
  still matches; prefix it with "re:" for a raw regex, for example word
  boundaries on a name that is also part of common words. Blank lines and lines
  starting with "#" are skipped.

Each line is also checked with adjacent string literals joined ("C:" + "..."
or "Ze" "ta" on one line), so a value split across literals still matches.
Files that start with a UTF-16 byte-order mark are decoded and scanned whole,
since git diffs them as binary. The names of new files are scanned as text.

Modes:

  --staged            lines and new file names the staged change adds
                      (pre-commit)
  --ci --base B       lines and new file names each commit in B..HEAD adds,
                      judged commit by commit so a name added and later
                      removed is still caught, plus those commits' messages
  --text LABEL        text on stdin (for example a pull request title and body)
  --tree              every tracked file at HEAD (reports counts by file)
  FILE ...            the named files

Output names file and line only. The matched text is never printed, so a CI log
cannot republish what the scan exists to stop.

Exit 0 = clean. Exit 1 = hit, or no denylist configured in --ci or --text mode
(fail closed: a scan with no list would pass everything). Exit 2 = usage or git
error, including a diff header this script cannot parse, so an unreadable file
name fails instead of being skipped. Exit 3 = an empty --ci range, which would
otherwise pass having read nothing.

Known gaps: "~" and environment-variable home paths, IP addresses written in
other forms, binary files other than UTF-16 text, values split across lines or
built through variables, and anything committed with --no-verify before CI
runs.
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import subprocess
import sys
from collections import Counter
from urllib.parse import unquote
from pathlib import Path

ENV_VAR = "LEAK_DENYLIST"
LOCAL_FILE = "leak-denylist"

_OCTET = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
_SEG = r"[^\\/\s\"'`]+"
BUILTIN: list[tuple[str, re.Pattern[str]]] = [
    (
        "windows-user-home-path",
        re.compile(r"(?i)\b[A-Z]:(?:\\{1,2}|/)Users(?:\\{1,2}|/)" + _SEG),
    ),
    ("posix-home-path", re.compile(r"/home/[A-Za-z0-9._-]+")),
    ("macos-user-home-path", re.compile(r"(?<![\w.:/])/Users/[A-Za-z0-9._-]+")),
    ("wsl-mount-home-path", re.compile(r"(?i)/mnt/[a-z]/Users/" + _SEG)),
    (
        "wsl-network-home-path",
        re.compile(
            r"(?i)\\{2,4}wsl(?:\$|\.localhost)\\{1,2}[^\\\s]+\\{1,2}home\\{1,2}" + _SEG
        ),
    ),
    (
        "private-ipv4",
        re.compile(
            r"\b(?:10\." + _OCTET + r"|172\.(?:1[6-9]|2\d|3[01])|192\.168"
            r"|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7]))"
            r"\." + _OCTET + r"\." + _OCTET + r"\b"
        ),
    ),
    ("em-dash", re.compile(chr(0x2014))),
    ("en-dash", re.compile(chr(0x2013))),
    (
        "ai-trailer",
        re.compile(
            r"(?i)co-authored-b[y]:.*\b(claude|cursor|copilot|gpt|gemini|assistant"
            r"|anthropic|openai)\b|generat[e]d (with|by) .*\b(claude|cursor|copilot)\b"
            r"|claude\.ai/code/session"
        ),
    ),
]
# A closing quote, an optional "+", and an opening quote of the same kind.
_JOIN = re.compile(r"(['\"])\s*\+?\s*\1")


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


def _git_bytes(*args: str) -> bytes:
    r = subprocess.run(["git", *args], capture_output=True, check=False)
    if r.returncode != 0:
        print(f"leak scan: git {' '.join(args)} failed", file=sys.stderr)
        raise SystemExit(2)
    return r.stdout


def _decode(data: bytes) -> tuple[str | None, bool]:
    """(text, is UTF-16). Text is None for a binary file this scan cannot read."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="replace"), True
    if b"\0" in data[:8192]:
        return None, False
    return data.decode("utf-8-sig", errors="replace"), False


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
    pats = [_compile_line(ln) for ln in lines if ln and not ln.startswith("#")]
    return pats or None


def _labels(line: str, names: list[re.Pattern[str]]) -> list[str]:
    out = [label for label, pat in BUILTIN if pat.search(line)]
    out += [f"denylist entry {i}" for i, pat in enumerate(names, 1) if pat.search(line)]
    return out


def _views(line: str) -> list[str]:
    """Plain text plus the encodings a line can hide a name in."""
    found = [line]
    unescaped = re.sub(
        r"\\u([0-9a-fA-F]{4})", lambda match: chr(int(match.group(1), 16)), line
    )
    if unescaped != line:
        found.append(unescaped)
    decoded = unquote(line)
    if decoded != line:
        found.append(decoded)
    for blob in re.findall(r"[A-Za-z0-9+/]{4,}={0,2}", line):
        if len(blob) < 8:
            continue
        try:
            raw = base64.b64decode(blob, validate=True)
            text = raw.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if text.isprintable() and text not in found:
            found.append(text)
    return found


def scan_text(text: str, names: list[re.Pattern[str]]) -> list[tuple[int, str]]:
    """(line number, rule label) per hit. Labels never contain the matched text."""
    hits: list[tuple[int, str]] = []
    for n, line in enumerate(text.splitlines(), 1):
        seen: set[str] = set()
        for view in _views(line):
            raw = _labels(view, names)
            hits += [(n, label) for label in raw if label not in seen]
            seen.update(raw)
            joined = _JOIN.sub("", view)
            if joined != view:
                hits += [
                    (n, f"{label} (split string)")
                    for label in _labels(joined, names)
                    if label not in seen and f"{label} (split string)" not in seen
                ]
                seen.update(
                    f"{label} (split string)" for label in _labels(joined, names)
                )
    return hits


def _tree() -> list[tuple[str, str]]:
    out = []
    for path in _git("ls-files", "-z").split("\0"):
        p = Path(path)
        if path and p.is_file():
            text, wide = _decode(p.read_bytes())
            if text is not None:
                out.append((f"{path} (UTF-16)" if wide else path, text))
    return out


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_BINARY = re.compile(r"^Binary files (.+) and (.+) differ$")
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
    return _b_path(header[4:].rstrip("\t"), header)


def _b_path(name: str, context: str) -> str | None:
    name = _unquote(name)
    if name == "/dev/null":
        return None
    if not name.startswith("b/"):
        print(f"leak scan: cannot parse diff header {context!r}", file=sys.stderr)
        raise SystemExit(2)
    return name[2:]


def _added_lines(rev: str, *diff_args: str) -> list[tuple[str, str]]:
    """Added lines only, placed at their real line numbers (other lines left blank).

    Scanning whole files would fail every edit to a file that already carries a
    known hit, so pre-commit and CI judge only what the change adds. A file git
    reports as binary is read from rev ("" for the index) and scanned whole when
    it is UTF-16 text.
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
    out = []
    current = None
    lineno = 0
    in_hunk = False
    saw_old = False
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            in_hunk = False
            saw_old = False
            current = None
            continue
        if line.startswith("--- ") and not in_hunk:
            saw_old = True
            continue
        if line.startswith("+++ ") and not in_hunk and saw_old:
            current = _target(line)
            saw_old = False
            continue
        if m := _BINARY.match(line):
            path = _b_path(m.group(2), line)
            if path is not None:
                text, wide = _decode(_git_bytes("show", f"{rev}:{path}"))
                if text is not None and wide:
                    out.append((f"{path} (UTF-16)", text))
        elif m := _HUNK.match(line):
            in_hunk = True
            saw_old = False
            lineno = int(m.group(1))
        elif current and in_hunk and line.startswith("+"):
            # Inside a hunk, one leading "+" is the diff marker. Text that
            # itself starts with "++" is content, not the next file header.
            by_file.setdefault(current, {})[lineno] = line[1:]
            lineno += 1
    for path, added in by_file.items():
        rows = [""] * max(added)
        for n, text in added.items():
            rows[n - 1] = text
        out.append((path, "\n".join(rows)))
    return out


def _new_names(*diff_args: str) -> list[str]:
    names = _git(
        "-c",
        "core.quotepath=false",
        "diff",
        "--name-only",
        "--no-renames",
        "--diff-filter=A",
        "-z",
        *diff_args,
    )
    return [n for n in names.split("\0") if n]


_EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def _per_commit(base: str, head: str) -> list[tuple[str, str]]:
    """Added lines and new file names of each commit on its own, against its first parent."""
    out = []
    for row in _git("rev-list", "--parents", f"{base}..{head}").splitlines():
        sha, *parents = row.split()
        args = (
            [f"{sha}^!"]
            if len(parents) == 1
            else [parents[0] if parents else _EMPTY_TREE, sha]
        )
        out += [(f"{p} @ {sha[:12]}", t) for p, t in _added_lines(sha, *args)]
        out += [(f"{p} @ {sha[:12]} (file name)", p) for p in _new_names(*args)]
    return out


def _messages(base: str, head: str) -> list[tuple[str, str]]:
    out = []
    for sha in _git("rev-list", f"{base}..{head}").split():
        out.append(
            (f"commit {sha[:12]} message", _git("log", "-1", "--format=%B", sha))
        )
    return out


def _read_file(f: str) -> tuple[str, str] | None:
    text, wide = _decode(Path(f).read_bytes())
    if text is None:
        return None
    return (f"{f} (UTF-16)" if wide else f, text)


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
            "checking built-in shapes only",
            file=sys.stderr,
        )
        names = []

    if a.ci:
        if not a.base:
            ap.error("--ci needs --base")
        count = _git("rev-list", "--count", f"{a.base}..{a.head}").strip()
        if count == "0":
            print(f"leak scan: empty range {a.base}..{a.head}; nothing to scan")
            return 3
        targets = _per_commit(a.base, a.head) + _messages(a.base, a.head)
    elif a.text:
        targets = [(a.text, sys.stdin.read())]
    elif a.staged:
        targets = _added_lines("", "--cached")
        targets += [(f"{p} (file name)", p) for p in _new_names("--cached")]
    elif a.tree:
        targets = _tree()
    else:
        targets = [t for t in map(_read_file, a.files) if t is not None]

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
