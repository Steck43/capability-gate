#!/usr/bin/env python3
"""Fail on private names and personal paths in text headed for a public repo.

Pattern sources:

* Built-in shapes: user-home paths (Windows with any number of backslashes or
  forward slashes, POSIX, macOS, WSL mounts, WSL network paths, "~user" and
  home-variable forms such as $HOME, %USERPROFILE% and $env:USERPROFILE),
  private and link-local IPv4, and private and link-local IPv6. The path and
  IPv4 shapes are also in .gitleaks.toml, repeated here so the commit-message
  check and the pre-commit check do not depend on a gitleaks install.
* Style shapes that must not reach public text: em and en dashes, and AI
  authorship trailers.
* A denylist of names (machines, agents, people, hosts, folder names). The
  list never lives in the tree, because publishing it would be the leak. It is
  read from the LEAK_DENYLIST environment variable (one pattern per line) or,
  locally, from the untracked file .git/info/leak-denylist. A line is a
  case-insensitive substring after normalisation, so a name glued to other
  text ("NameReview") still matches; prefix it with "re:" for a raw regex, for
  example word boundaries on a name that is also part of common words. Blank
  lines and lines starting with "#" are skipped.

Every line is read in every form a reader could decode from it, and each form
is normalised (NFKC, so fullwidth letters become ASCII; invisible format
characters such as zero-width joiners removed; Cyrillic and Greek look-alikes
folded to Latin) before matching:

* percent-encoding (repeated, so double-encoded text is read), backslash
  escapes (\\uXXXX, \\UXXXXXXXX, \\xXX, \\n, \\t, \\r) and HTML entities, applied
  in any order until nothing changes;
* base64 (standard and URL-safe, padded or not, from 4 characters) and hex
  tokens, decoded when the result is mostly printable text, two levels deep;
* adjacent string literals on one line joined ("C:" + "..." or "Ze" "ta"),
  and a value split across two lines by a closing and opening quote or a
  backslash line continuation.

Bytes are read as UTF-8 text when they are valid UTF-8 with no NUL byte (a
UTF-16 or UTF-32 byte-order mark never is). Anything else (UTF-16 or UTF-32 with or
without a byte-order mark, binary files) is read whole in every decoding: UTF-8
and latin-1, UTF-16 and UTF-32 in both byte orders at every alignment, and with
NUL bytes removed.

Modes:

  --staged            what the staged change adds (pre-commit)
  --ci --base B       what each commit in B..HEAD adds, judged commit by
                      commit so a name added and later removed is still
                      caught, plus those commits' messages
  --text LABEL        text on stdin (for example a pull request title and body)
  --tree              every tracked file at HEAD (reports counts by file)
  FILE ...            the named files

"What a change adds" is the added lines of every text file, read from a diff
that ignores the repository's attributes (--text, --no-textconv,
--no-ext-diff), so a binary, -diff or textconv attribute cannot hide a line;
the names of new files; and, for a file that is not plain UTF-8 text, every
hit in the new version that the old version did not already have.

Output names file and line only. The matched text is never printed, so a CI log
cannot republish what the scan exists to stop.

Exit 0 = clean. Exit 1 = hit, or no denylist configured in --ci or --text mode
(fail closed: a scan with no list would pass everything). Exit 2 = usage or git
error, including a diff header this script cannot parse, so an unreadable file
name fails instead of being skipped. Exit 3 = an empty --ci range, which would
otherwise pass having read nothing.

Known gaps: IPv4 written as one integer or in octal, IPv6 other than fc00::/7
and fe80::/10, values built through variables or split across more than two
lines, encodings other than those listed (for example ROT13 or reversed text),
a hit a binary file already carried before the change, and anything committed
with --no-verify before CI runs.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import html
import os
import re
import subprocess
import sys
import unicodedata
from collections import Counter
from pathlib import Path
from urllib.parse import unquote

ENV_VAR = "LEAK_DENYLIST"
LOCAL_FILE = "leak-denylist"

_OCTET = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
_SEG = r"[^\\/\s\"'`]+"
_SEPS = r"(?:\\+|/+)"
BUILTIN: list[tuple[str, re.Pattern[str]]] = [
    (
        "windows-user-home-path",
        re.compile(r"(?i)\b[A-Z]:" + _SEPS + r"Users" + _SEPS + _SEG),
    ),
    ("posix-home-path", re.compile(r"/home/[A-Za-z0-9._-]+")),
    ("macos-user-home-path", re.compile(r"(?<![\w.:/])/Users/[A-Za-z0-9._-]+")),
    ("wsl-mount-home-path", re.compile(r"(?i)/mnt/[a-z]/Users/" + _SEG)),
    (
        "wsl-network-path",
        re.compile(r"(?i)(?:\\{2,}|/{2,})wsl(?:\$|\.localhost)(?:\\+|/+)"),
    ),
    ("tilde-user-path", re.compile(r"(?<![\w~])~[A-Za-z][A-Za-z0-9._-]*" + _SEPS)),
    (
        "home-variable-path",
        re.compile(
            r"(?i)(?:\$HOME(?!\w)|\$\{HOME\}|%USERPROFILE%|%HOMEPATH%"
            r"|\$env:USERPROFILE(?!\w)|\$env:HOMEPATH(?!\w)|\$\{env:USERPROFILE\})"
            + _SEPS
        ),
    ),
    (
        "private-ipv4",
        re.compile(
            r"\b(?:10\." + _OCTET + r"|172\.(?:1[6-9]|2\d|3[01])|192\.168"
            r"|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])|169\.254)"
            r"\." + _OCTET + r"\." + _OCTET + r"\b"
        ),
    ),
    (
        "private-ipv6",
        re.compile(
            r"(?i)(?<![0-9a-f:])(?:f[cd][0-9a-f]{2}|fe[89ab][0-9a-f]):[0-9a-f:]*[0-9a-f]"
            r"(?![0-9a-f])"
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
# The same across a line break, or a backslash line continuation.
_CONTINUE = re.compile(r"(['\"])\s*\\?\s*\+?\s*\n\s*\+?\s*\1|\\\n\s*")

# Latin look-alikes from Cyrillic and Greek, folded before matching.
_CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "і": "i",
        "ј": "j",
        "ѕ": "s",
        "к": "k",
        "в": "b",
        "м": "m",
        "н": "h",
        "т": "t",
        "А": "A",
        "В": "B",
        "Е": "E",
        "К": "K",
        "М": "M",
        "Н": "H",
        "О": "O",
        "Р": "P",
        "С": "C",
        "Т": "T",
        "Х": "X",
        "ο": "o",
        "α": "a",
        "ρ": "p",
        "κ": "k",
        "ν": "v",
        "Ο": "O",
    }
)
_ESC = re.compile(
    r"\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})|\\x([0-9a-fA-F]{2})|\\([ntr])"
)
_SIMPLE_ESC = {"n": "\n", "t": "\t", "r": "\r"}
_B64 = re.compile(r"[A-Za-z0-9+/_-]{4,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){3,}")
MAX_ROUNDS = 4
MAX_DEPTH = 2


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


# --------------------------------------------------------------------- text views


def normalise(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return text.translate(_CONFUSABLES)


def _unescape(text: str) -> str:
    def one(match: re.Match[str]) -> str:
        if match.group(4):
            return _SIMPLE_ESC[match.group(4)]
        code = int(match.group(1) or match.group(2) or match.group(3), 16)
        return chr(code) if code <= 0x10FFFF else match.group(0)

    return _ESC.sub(one, text)


_DECODERS = (unquote, _unescape, html.unescape)


def _closure(seed: str) -> list[str]:
    """``seed`` and every text the decoders reach from it, in any order."""
    seen = {seed}
    out = [seed]
    frontier = [seed]
    for _ in range(MAX_ROUNDS):
        later = []
        for form in frontier:
            for decode in _DECODERS:
                found = normalise(decode(form))
                if found not in seen:
                    seen.add(found)
                    out.append(found)
                    later.append(found)
        frontier = later
    return out


def _printable(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if text and sum(ch.isprintable() for ch in text) >= 0.9 * len(text):
        return text
    return None


def _decoded_tokens(text: str) -> list[str]:
    out: list[str] = []
    for token in _B64.findall(text):
        body = token.rstrip("=")
        for decode in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                found = _printable(decode(body + "=" * (-len(body) % 4)))
            except (binascii.Error, ValueError):
                continue
            if found:
                out.append(found)
    for token in _HEX.findall(text):
        found = _printable(bytes.fromhex(token))
        if found:
            out.append(found)
    return out


def _views(line: str, depth: int = 0) -> list[str]:
    """The line and every decoded, normalised form of it."""
    forms = _closure(normalise(line))
    if depth < MAX_DEPTH:
        for form in list(forms):
            for decoded in _decoded_tokens(form):
                forms += [f for f in _views(decoded, depth + 1) if f not in forms]
    return [line] + [f for f in forms if f != line]


def _compile_line(line: str) -> re.Pattern[str]:
    if line.startswith("re:"):
        return re.compile(line[3:], re.I)
    return re.compile(re.escape(normalise(line)), re.I)


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


def _labels(text: str, names: list[re.Pattern[str]]) -> set[str]:
    out = {label for label, pat in BUILTIN if pat.search(text)}
    out |= {f"denylist entry {i}" for i, pat in enumerate(names, 1) if pat.search(text)}
    return out


def _line_labels(line: str, names: list[re.Pattern[str]]) -> tuple[set[str], set[str]]:
    """(labels found in some view, labels found only once literals are joined)."""
    plain: set[str] = set()
    joined: set[str] = set()
    for view in _views(line):
        plain |= _labels(view, names)
        glued = _JOIN.sub("", view)
        if glued != view:
            joined |= _labels(glued, names)
    return plain, joined - plain


def scan_text(text: str, names: list[re.Pattern[str]]) -> list[tuple[int, str]]:
    """(line number, rule label) per hit. Labels never contain the matched text."""
    hits: list[tuple[int, str]] = []
    lines = text.splitlines()
    found: list[set[str]] = []
    for n, line in enumerate(lines, 1):
        plain, joined = _line_labels(line, names)
        hits += [(n, label) for label in sorted(plain)]
        hits += [(n, f"{label} (split string)") for label in sorted(joined)]
        found.append(plain | joined)
    for i in range(len(lines) - 1):
        if not lines[i].strip() or not lines[i + 1].strip():
            continue
        pair = lines[i] + "\n" + lines[i + 1]
        glued = _CONTINUE.sub("", pair)
        if glued == pair:
            continue
        plain, joined = _line_labels(glued, names)
        across = (plain | joined) - found[i] - found[i + 1]
        hits += [(i + 1, f"{label} (split across lines)") for label in sorted(across)]
    return hits


# -------------------------------------------------------------------- byte views


def is_plain_text(data: bytes) -> bool:
    if b"\0" in data:
        return False
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def decodings(data: bytes) -> list[str]:
    """Every text a reader could get from these bytes. Nothing is skipped."""
    out = [data.decode("utf-8", "replace"), data.decode("latin-1")]
    for enc, width in (
        ("utf-16-le", 2),
        ("utf-16-be", 2),
        ("utf-32-le", 4),
        ("utf-32-be", 4),
    ):
        for shift in range(width):
            chunk = data[shift:]
            chunk = chunk[: len(chunk) - len(chunk) % width]
            out.append(chunk.decode(enc, "replace"))
    if b"\0" in data:
        out.append(data.replace(b"\0", b"").decode("latin-1"))
    return out


def scan_bytes(data: bytes, names: list[re.Pattern[str]]) -> set[str]:
    """Labels found in any decoding of ``data`` (no line numbers)."""
    labels: set[str] = set()
    for text in decodings(data):
        labels |= {label for _, label in scan_text(text, names)}
    return labels


def _byte_label(path: str, data: bytes) -> str:
    wide = data.startswith((b"\xff\xfe", b"\xfe\xff"))
    return f"{path} (UTF-16)" if wide else f"{path} (not UTF-8 text)"


# Each target is (where, text) for line-by-line text, or (where, set of labels)
# for a file read whole in every decoding.
Target = tuple[str, "str | set[str]"]


def _tree() -> list[Target]:
    out: list[Target] = []
    for path in _git("ls-files", "-z").split("\0"):
        p = Path(path)
        if path and p.is_file():
            out.append(_read_file(path))
    return out


# --------------------------------------------------------------------- git diffs

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_C_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13}
_ZERO = "0" * 40
# Diff options that make git ignore attributes and drivers that could hide a
# line: binary or -diff attributes, textconv filters, external diff programs.
_RAW_DIFF = ("--text", "--no-textconv", "--no-ext-diff", "--no-renames", "--no-color")


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


def _changed(*diff_args: str) -> list[tuple[str, str, str]]:
    """(path, old blob, new blob) for every file the diff adds or changes."""
    raw = _git(
        "-c",
        "core.quotepath=false",
        "diff",
        "--raw",
        "-z",
        "--no-abbrev",
        *_RAW_DIFF,
        *diff_args,
    )
    parts = raw.split("\0")
    out = []
    i = 0
    while i < len(parts) - 1:
        meta = parts[i].split()
        if not meta:
            i += 1
            continue
        if len(meta) < 5 or not meta[0].startswith(":"):
            print("leak scan: cannot parse the raw diff", file=sys.stderr)
            raise SystemExit(2)
        old, new, status = meta[2], meta[3], meta[4]
        path = parts[i + 1]
        i += 2
        if status[0] in "D" or new == _ZERO:
            continue
        out.append((path, old, new))
    return out


def _blob(sha: str) -> bytes:
    return b"" if sha == _ZERO else _git_bytes("cat-file", "blob", sha)


def _added_lines(*diff_args: str) -> list[Target]:
    """Added text lines at their real line numbers, plus non-text files read whole.

    Scanning whole text files would fail every edit to a file that already
    carries a known hit, so pre-commit and CI judge only what the change adds.
    A file whose new version is not plain UTF-8 text is read in every decoding,
    and only hits its old version did not have count.
    """
    out: list[Target] = []
    wide: set[str] = set()
    for path, old, new in _changed(*diff_args):
        data = _blob(new)
        if not is_plain_text(data):
            wide.add(path)
            fresh = scan_bytes(data, _NAMES) - scan_bytes(_blob(old), _NAMES)
            out.append((_byte_label(path, data), fresh))
    diff = _git(
        "-c", "core.quotepath=false", "diff", "--unified=0", *_RAW_DIFF, *diff_args
    )
    by_file: dict[str, dict[int, str]] = {}
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
        if m := _HUNK.match(line):
            in_hunk = True
            saw_old = False
            lineno = int(m.group(1))
        elif current and in_hunk and line.startswith("+"):
            # Inside a hunk, one leading "+" is the diff marker. Text that
            # itself starts with "++" is content, not the next file header.
            if current not in wide:
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


def _per_commit(base: str, head: str) -> list[Target]:
    """What each commit adds on its own, against its first parent."""
    out: list[Target] = []
    for row in _git("rev-list", "--parents", f"{base}..{head}").splitlines():
        sha, *parents = row.split()
        args = (
            [f"{sha}^!"]
            if len(parents) == 1
            else [parents[0] if parents else _EMPTY_TREE, sha]
        )
        out += [(f"{p} @ {sha[:12]}", t) for p, t in _added_lines(*args)]
        out += [(f"{p} @ {sha[:12]} (file name)", p) for p in _new_names(*args)]
    return out


def _messages(base: str, head: str) -> list[Target]:
    out: list[Target] = []
    for sha in _git("rev-list", f"{base}..{head}").split():
        out.append(
            (f"commit {sha[:12]} message", _git("log", "-1", "--format=%B", sha))
        )
    return out


def _read_file(f: str) -> Target:
    data = Path(f).read_bytes()
    if is_plain_text(data):
        return (f, data.decode("utf-8-sig"))
    return (_byte_label(f, data), scan_bytes(data, _NAMES))


_NAMES: list[re.Pattern[str]] = []


def main(argv: list[str] | None = None) -> int:
    global _NAMES
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
    _NAMES = names

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
        targets = _added_lines("--cached")
        targets += [(f"{p} (file name)", p) for p in _new_names("--cached")]
    elif a.tree:
        targets = _tree()
    else:
        targets = [_read_file(f) for f in a.files]

    total = 0
    per_file: Counter[str] = Counter()
    for where, body in targets:
        found = (
            scan_text(body, names)
            if isinstance(body, str)
            else [(1, label) for label in sorted(body)]
        )
        for n, label in found:
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
