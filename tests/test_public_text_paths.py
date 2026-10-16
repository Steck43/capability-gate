"""Public text cites no path that exists only in a private repository.

Receipts and raw artifacts that live outside this repository are named as
private, with their digests, never by a path a reader cannot open. Every
tracked file is read in each text view a reader could get from its bytes (UTF-8
with NUL bytes dropped, and UTF-16 when a byte-order mark or a NUL byte says it
may be). Each line is decoded until it stops changing: HTML entities, URL
encoding, NFKC, format characters dropped, slash look-alikes and Cyrillic
letters that look like the folder name's letters folded, backslashes and JSON
escaped slashes as slashes, string prefixes, triple quotes and brackets around
a lone literal dropped, os.path.join and .joinpath calls, literals joined by a
Path "/" and two adjacent string literals joined. A left operand anchored to
this checkout (this file's own path through Path(__file__) or os.path.dirname,
ROOT, or a name the file binds once to one of those) is replaced by its literal
tail, judged against ROOT like any relative path; it is a runtime value once it
climbs above the checkout. Any other name, attribute, call, subscript or
bracketed expression joined in front of a literal that reaches the folder name
(by a join call, a Path "/" or a "+") is a runtime value, so the path is not
one in this checkout. Then every receipts folder (any letter case, with or
without a trailing slash) is judged by the whole path before it:

- nothing before it, or a folder path that exists inside this checkout: home;
- a leading slash, a drive letter, or any ".." step: another tree, even when
  it would land on this checkout's own receipts folder;
- a URL with any scheme but http or https (file, vscode, ssh, ...), with or
  without slashes, and a drive-relative path: a path outside the checkout;
- a GitHub blob, tree or raw URL: home only when it points into this
  repository, judged by the path after the ref; any other code forge, known by
  its host or by its URL shape on any host: another repository;
- any other web URL: not a repository path, not judged.

The file names no private folder: a foreign path is refused because its folder
does not exist here, not because it is listed.
"""

from __future__ import annotations

import codecs
import hashlib
import html
import re
import subprocess
import unicodedata
from pathlib import Path
from urllib.parse import unquote

import pytest

ROOT = Path(__file__).resolve().parents[1]
THIS_REPO = ("steck43", "capability-gate")
# The text before a receipts folder, back to the start of the token it sits in.
# The folder name needs no trailing slash; a longer word is not the folder.
_BEFORE_RECEIPTS = re.compile(r"([^\s`'\"()<>\[\]{}|,;=*]*?)receipts(?![\w-])", re.I)
_GITHUB = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/([\w.-]+)/([\w.-]+)/(?:blob|tree|raw)/[^/]+/(.*)$",
    re.I,
)
_RAW = re.compile(
    r"^(?:https?://)?raw\.githubusercontent\.com/([\w.-]+)/([\w.-]+)/[^/]+/(.*)$", re.I
)
# Code forges other than GitHub: this repository lives only on GitHub, so a forge
# URL that reaches a receipts folder points into another repository.
_FORGES = ("gitlab.com", "bitbucket.org", "codeberg.org", "git.sr.ht", "gitea.com")
# Letters from other scripts that look like the Latin letters of the folder
# name (r, e, c, i, p, t, s), as HEX:LETTER pairs: every pair in Unicode's
# confusables.txt 18.0.0 (UTS #39, (c) Unicode, Inc., Unicode License v3) whose
# skeleton is one of those letters, as isolation-layer's public surface scan
# folds them (its capital-I look-alikes fold to I), less the code points NFKC
# already turns into ASCII. A test pins the list.
_FOLDER_CONFUSABLES = (
    "A1:i FE:p 131:i 196:I 1A6:R 1BD:s 1BF:p 1C0:I 1DD:e 24C:R 268:i 269:i "
    "26A:i 27D:r 27E:r 280:r 395:E 399:I 3A1:P 3A4:T 3B5:e 3B9:i 3C1:p 3F1:p "
    "3F2:c 3F8:p 3F9:C 405:S 406:I 415:E 420:P 421:C 422:T 433:r 435:e 440:p "
    "441:c 442:t 454:e 455:s 456:i 4BD:e 4C0:I 54F:S 582:i 7E0:T D1F:s 1004:c "
    "105A:c 10BD:S 10FD:S 13A1:R 13A2:T 13A5:i 13AC:E 13D2:R 13D5:S 13DA:S "
    "13DF:C 13E2:P 146D:P 1587:R 16C1:I 1C83:c 1CBD:S 1D04:c 1D07:e 1D09:i "
    "1D18:p 1D1B:t 1D26:r 212E:e 22A4:T 22FF:E 2373:i 2374:p 27D9:T 2C85:r "
    "2C92:I 2C93:i 2CA2:P 2CA3:p 2CA4:C 2CA5:c 2CA6:T 2CCE:P 2CCF:p 2D39:E "
    "3112:T 4E05:T A4D1:P A4D4:T A4DA:C A4E2:S A4E3:R A4F0:E A4F2:I A50B:T "
    "A576:S A5CB:E A647:i A731:s A7AE:I A7FE:I AB32:e AB47:r AB48:r AB75:i "
    "AB81:r ABAA:s ABAF:c 10286:E 10295:P 10296:S 10297:T 102A2:C 102B1:T "
    "10302:C 10309:I 10315:T 10415:C 10420:S 1043D:c 10448:s 104B4:R 1051B:C "
    "10926:I 118A6:E 118AE:E 118BC:T 118C1:s 118C3:i 118E9:C 118F2:C 16A19:r "
    "16AD6:S 16F0A:T 16F35:R 16F3A:S 1CCD8:C 1CCDA:E 1CCE5:P 1CCE7:R 1CCE8:S "
    "1CCE9:T 1D134:c 1D216:R 1D373:T 1D6A4:i 1D6AC:E 1D6B8:P 1D6BB:T 1D6CA:i "
    "1D6D2:p 1D6E0:p 1D6E6:E 1D6F2:P 1D6F5:T 1D704:i 1D70C:p 1D71A:p 1D720:E "
    "1D72C:P 1D72F:T 1D73E:i 1D746:p 1D754:p 1D75A:E 1D766:P 1D769:T 1D778:i "
    "1D780:p 1D78E:p 1D794:E 1D7A0:P 1D7A3:T 1D7B2:i 1D7BA:p 1D7C8:p 1DF81:E "
    "1F74C:C 1F768:T"
)
# Look-alikes that table leaves out, and slash look-alikes NFKC keeps.
_FOLD_EXTRA = "3C4:t 2215:/ 2044:/ 29F8:/"
_FOLD = str.maketrans(
    {
        chr(int(code, 16)): letter
        for code, letter in (
            pair.split(":")
            for pair in (_FOLDER_CONFUSABLES + " " + _FOLD_EXTRA).split()
        )
    }
)
# A path built from a runtime value is not a path in this checkout. Its unknown
# part becomes this marker, which no checkout path can hold (it starts with ..).
_RUNTIME = "../runtime"
_FOLDER = "rece" + "ipts"
_JOIN_CALL = re.compile(
    r"(?:(?:os\.path|posixpath|ntpath)\.join|\.joinpath)\(((?:[^()]|\([^()]*\))*)\)"
)
# A Path "/" operator, or a "+", whose left operand is a name, attribute, call,
# subscript or anything closed by a bracket, and whose right operand is a
# literal that reaches the folder name.
_RUNTIME_LEFT = re.compile(
    r"""(?:[A-Za-z_][\w.]*(?:\[[^\[\]]*\])*|[)\]])\s*[/+]\s*(["'])(?=[^"'\n]*receipts)""",
    re.I,
)
_LITERAL = re.compile(r"""["']([^"']*)["']""")
_LITERAL_PLUS = re.compile(r"""(["'])\s*\+\s*(["'])""")
# A string prefix (raw, unicode, bytes, f-string) is dropped, a triple quote reads
# as one quote, a literal alone in brackets is unwrapped, and literals joined by a
# Path "/" read as one literal.
_PREFIX = re.compile(r"""(?<![\w"'])[rRbBuUfF]{1,2}(?=["'])""")
_BRACKETED = re.compile(r"""(?<![\w)\]])\(\s*((["'])[^"'\n]*\2)\s*\)""")
_LITERAL_SLASH = re.compile(r"""(["'])([^"'\n]*)\1\s*/\s*(["'])([^"'\n]*)\3""")
_PATH_JOIN = re.compile(
    r"((?:os\.path|posixpath|ntpath)\.join)\(((?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)"
)

# A left operand anchored to this checkout: this file's own path (Path(__file__)
# or os.path.dirname of it, with .resolve(), .parent and .parents[n]), ROOT, or
# a name the same file binds once to one of those. Its literal tail is judged
# against ROOT the way any relative path is; an anchor that climbs above the
# checkout is a runtime value.
_FILE_ANCHOR = (
    r"(?:Path\(\s*__file__\s*\)|(?:os\.path\.(?:dirname|abspath|realpath)\(\s*)+"
    r"__file__\s*\)+)(?:\.resolve\(\)|\.absolute\(\)|\.parent\b|\.parents\[\d+\])*"
)
_DEFAULT_REL = "tests/test_x.py"
_OUTSIDE = "outside_checkout"


def _anchor_tail(expr: str, rel: str) -> str | None:
    """ "" for this file's own path while it stays inside the checkout, None once
    it climbs above it."""
    level = len(rel.split("/"))
    level -= expr.count("dirname(")
    for step in re.findall(r"\.parent\b|\.parents\[(\d+)\]", expr):
        level -= int(step) + 1 if step else 1
    return "" if level >= 0 else None


def _anchors(names: dict[str, str | None]) -> re.Pattern[str]:
    alts = [_FILE_ANCHOR] + [rf"\b{re.escape(n)}\b(?![\w.(\[])" for n in names]
    return re.compile("(" + "|".join(alts) + ")")


def _resolve(expr: str, names: dict[str, str | None], rel: str) -> str | None:
    return names[expr] if expr in names else _anchor_tail(expr, rel)


def _anchored(text: str, names: dict[str, str | None], rel: str) -> str:
    """Each anchored left operand replaced by its tail as a literal, or by a
    runtime name when it is above the checkout."""
    rx = _anchors(names)

    def slash(m: re.Match[str]) -> str:
        tail = _resolve(m.group(1), names, rel)
        if tail is None:
            return _OUTSIDE + m.group(2)
        return f'"{tail}" / ' if tail else ""

    def joinpath(m: re.Match[str]) -> str:
        tail = _resolve(m.group(1), names, rel)
        if tail is None:
            return _OUTSIDE + ".joinpath("
        return f'os.path.join("{tail}", ' if tail else "os.path.join("

    def join_args(m: re.Match[str]) -> str:
        kept = []
        for arg in _args(m.group(2)):
            if rx.fullmatch(arg):
                tail = _resolve(arg, names, rel)
                if tail is None:
                    kept.append(_OUTSIDE)
                elif tail:
                    kept.append(f'"{tail}"')
                continue
            kept.append(arg)
        return m.group(1) + "(" + ", ".join(kept) + ")"

    text = re.sub(rx.pattern + r"(\s*/\s*)(?=[\"'])", slash, text)
    text = re.sub(rx.pattern + r"\.joinpath\(", joinpath, text)
    return _PATH_JOIN.sub(join_args, text)


_ASSIGN = re.compile(r"^\s*([A-Za-z_]\w*)\s*(?::[^=]*)?=(?!=)\s*(.*?)\s*$")
# Any place a name is bound: assignment and annotation, walrus, for and with
# targets, imports, global and nonlocal, def and class.
_BOUND = re.compile(
    r"(?:^|[;,(]|\bfor|\bas|\bglobal|\bnonlocal|\bdef|\bclass|\bimport)\s*"
    r"([A-Za-z_]\w*)\s*(?::[^=\n]*)?(?:=(?!=)|:=|\bin\b|[,)(:]|$)"
)
_TAIL = re.compile(r"""\s*/\s*["']([^"']*)["']""")


def _bindings(text: str, rel: str) -> dict[str, str | None]:
    """Names the file binds exactly once, by plain assignment, to an anchored
    path and an optional literal tail, mapped to that tail (None above the
    checkout). ROOT is the checkout root unless the file binds it otherwise."""
    lines = [_plain(line) for line in text.split("\n")]
    count: dict[str, int] = {}
    for line in lines:
        for name in _BOUND.findall(line):
            count[name] = count.get(name, 0) + 1
    names: dict[str, str | None] = {"ROOT": ""}
    for _ in range(5):
        changed = False
        rx = _anchors(names)
        for line in lines:
            m = _ASSIGN.match(line)
            if not m:
                continue
            name, rhs = m.groups()
            head = rx.match(rhs)
            rest = rhs[head.end() :] if head else rhs
            once = count.get(name, 0) == 1
            only_literals = "".join(m.group(0) for m in _TAIL.finditer(rest)) == rest
            if head is None or not once or not only_literals:
                if name in names:
                    del names[name]
                    changed = True
                continue
            base = _resolve(head.group(1), names, rel)
            parts = [base, *_TAIL.findall(rest)] if base is not None else None
            tail = None if parts is None else "/".join(x for x in parts if x)
            if names.get(name, "?") != tail:
                names[name] = tail
                changed = True
        if not changed:
            break
    return names


def _plain(line: str) -> str:
    """A line with string prefixes dropped, triple quotes read as one, and the
    brackets around a lone literal removed."""
    line = _PREFIX.sub("", line.replace('"' * 3, '"').replace("'" * 3, "'"))
    return _BRACKETED.sub(r"\1", line)


def _args(text: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for ch in text:
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
            continue
        depth += (ch == "(") - (ch == ")")
        cur += ch
    return [a.strip() for a in [*out, cur] if a.strip()]


def _joined(match: re.Match[str]) -> str:
    parts = [_RUNTIME] if match.group(0).startswith(".joinpath") else []
    for arg in _args(match.group(1)):
        literal = _LITERAL.fullmatch(arg)
        parts.append(literal.group(1) if literal else _RUNTIME)
    return '"' + "/".join(parts) + '"'


# Default-ignorable code points (Unicode DerivedCoreProperties) that are not
# format characters: fillers, joiners and selectors that render as nothing.
_IGNORABLE = (
    (0x034F, 0x034F),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFFA0, 0xFFA0),
    (0x1BCA0, 0x1BCA3),
    (0xE0000, 0xE0FFF),
)


def _visible(text: str) -> str:
    """Text without format characters, default-ignorables or combining marks,
    so nothing invisible or stacked on a letter can split the folder name."""
    out = []
    for c in unicodedata.normalize("NFD", text):
        cp = ord(c)
        if unicodedata.category(c) in ("Cf", "Mn", "Me"):
            continue
        if any(lo <= cp <= hi for lo, hi in _IGNORABLE):
            continue
        out.append(c)
    return unicodedata.normalize("NFC", "".join(out))


def _decoded(
    line: str, names: dict[str, str | None] | None = None, rel: str = _DEFAULT_REL
) -> str:
    names = {"ROOT": ""} if names is None else names
    text = line
    for _ in range(6):
        nxt = html.unescape(unquote(text.replace("\\/", "/")))
        # Folded before NFKC too: NFKC turns some look-alikes (a lunate sigma)
        # into letters that no longer look like the Latin one.
        nxt = unicodedata.normalize("NFKC", nxt.translate(_FOLD))
        nxt = _visible(nxt)
        nxt = _plain(nxt.translate(_FOLD).replace("\\", "/"))
        nxt = _anchored(nxt, names, rel)
        while (collapsed := _LITERAL_SLASH.sub(r'"\2/\4"', nxt)) != nxt:
            nxt = collapsed
        nxt = _RUNTIME_LEFT.sub(lambda m: m.group(1) + _RUNTIME + "/", nxt)
        nxt = _LITERAL_PLUS.sub("", _JOIN_CALL.sub(_joined, nxt))
        if nxt == text:
            break
        text = nxt
    return text


# Code forge URL shapes on any host: GitLab ("/-/blob/", "/-/tree/", "/-/raw/"),
# Gitea and Forgejo ("/src/branch/", "/src/commit/", "/src/tag/"), and Bitbucket
# ("/src/" or "/raw/" followed by a commit).
_FORGE_SHAPE = re.compile(
    r"/-/(?:blob|tree|raw)/|/src/(?:branch|commit|tag)/|/(?:src|raw)/[0-9a-f]{7,40}/",
    re.I,
)


def _foreign_url(prefix: str) -> bool | str:
    """True or False for a URL; the repository path after the ref for a URL
    into this repository on GitHub, to be judged like any other path."""
    scheme, sep, rest = prefix.partition("://")
    if not sep:
        scheme, rest = "https", prefix
    if scheme.lower() not in ("http", "https"):
        return True  # file, vscode, ssh and the rest: a path outside the checkout
    m = _GITHUB.match("https://" + rest) or _RAW.match("https://" + rest)
    if m is not None:
        owner, repo, path = m.groups()
        if (owner.lower(), repo.lower().removesuffix(".git")) != THIS_REPO:
            return True
        return path
    host = rest.split("/", 1)[0].lower()
    if "github" in host or any(host == f or host.endswith("." + f) for f in _FORGES):
        return True
    if _FORGE_SHAPE.search("/" + rest.split("/", 1)[-1]):
        return True  # a self-hosted forge: another repository
    return False  # another web site: not a repository path


# A URL scheme or a drive letter with its colon, at the start of the prefix.
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def _foreign_prefix(prefix: str) -> bool:
    if "://" not in prefix and _SCHEME.match(prefix):
        return True  # file:, vscode:, a drive-relative C: and the like
    if "://" in prefix or prefix.lower().startswith(("github.com/", "www.github")):
        verdict = _foreign_url(prefix)
        if isinstance(verdict, bool):
            return verdict
        prefix = verdict
    if prefix and not prefix.endswith("/"):
        return False  # another word that ends in "receipts", not the folder
    if prefix.startswith("/") or re.match(r"^[A-Za-z]:", prefix):
        return True
    parts = [p for p in prefix.split("/") if p not in ("", ".")]
    if ".." in parts:
        return True
    return not ROOT.joinpath(*parts, _FOLDER).is_dir()


def _foreign(
    line: str, names: dict[str, str | None] | None = None, rel: str = _DEFAULT_REL
) -> bool:
    return any(
        _foreign_prefix(m.group(1))
        for m in _BEFORE_RECEIPTS.finditer(_decoded(line, names, rel))
    )


def _hits(text: str, rel: str) -> list[int]:
    """Line numbers in one text view of a tracked file that cite a foreign path."""
    names = _bindings(text, rel)
    lines = text.split("\n")
    return [n for n, line in enumerate(lines, 1) if _foreign(line, names, rel)]


def _text_views(data: bytes) -> list[str]:
    """Every text a reader could get from the bytes: UTF-8 with NUL bytes
    dropped, and UTF-16 when a byte-order mark or a NUL byte says it may be."""
    views = [data.replace(b"\0", b"").decode("utf-8", errors="replace")]
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        views.append(data.decode("utf-16", errors="replace"))
    if b"\0" in data:
        even = data[: len(data) // 2 * 2]
        views += [
            even.decode(enc, errors="replace") for enc in ("utf-16-le", "utf-16-be")
        ]
    return views


def test_tracked_text_cites_no_private_repository_path() -> None:
    listed = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
    )
    found = []
    for rel in filter(None, listed.stdout.decode("utf-8").split("\0")):
        path = ROOT / rel
        if not path.is_file():
            continue
        for view in _text_views(path.read_bytes()):
            found += [f"{rel}:{n}" for n in _hits(view, rel)]
    assert sorted(set(found)) == []


def test_a_receipt_path_into_another_tree_is_caught() -> None:
    assert _foreign(f"raw artifact `elsewhere/{_R}/raw/x.json`")
    assert not _foreign("see `receipts/A1-KILL-SWITCH-2026-10-09.md`")
    assert not _foreign("https://example.invalid/receipts/x")


# Built from parts so this file's own lines never cite a foreign tree.
_R = "rece" + "ipts"

_FOREIGN = [
    pytest.param(f"../x/{_R}/y.md", id="parent-relative"),
    pytest.param(f"other/x/{_R}/y.md", id="nested-relative"),
    pytest.param(f"see `/srv/x/{_R}/y.md`", id="absolute"),
    pytest.param(f"C:/x/{_R}/y.md", id="drive-slash"),
    pytest.param("C:\\x\\" + _R + "\\y.md", id="drive-backslash"),
    pytest.param(f"elsewhere/{_R.capitalize()}/y.md", id="capitalised"),
    pytest.param(f"elsewhere/{_R.upper()}/y.md", id="upper-case"),
    pytest.param("elsewhere\\/" + _R + "\\/y.md", id="json-escaped-slash"),
    pytest.param(f"elsewhere%2F{_R}%2Fy.md", id="url-encoded"),
    pytest.param(f"elsewhere%252F{_R}%252Fy.md", id="url-encoded-twice"),
    pytest.param(f"../{_R}/y.md", id="parent-receipts-outside-checkout"),
    pytest.param(
        f"https://github.com/someone/other/blob/main/{_R}/y.md", id="github-blob"
    ),
    pytest.param(
        f"https://github.com/someone/other/tree/main/docs/{_R}/", id="github-tree"
    ),
    pytest.param(
        f"https://raw.githubusercontent.com/someone/other/main/{_R}/y.md",
        id="github-raw",
    ),
]


@pytest.mark.parametrize("line", _FOREIGN)
def test_every_spelling_of_a_foreign_receipt_path_is_caught(line: str) -> None:
    assert _foreign(line)


_HOME = [
    pytest.param(f"see `{_R}/A1-KILL-SWITCH-2026-10-09.md`", id="own-tree"),
    pytest.param(f"./{_R}/raw/x.json", id="dot-slash"),
    pytest.param(f"https://example.invalid/{_R}/x", id="other-site-url"),
    pytest.param(
        f"https://github.com/Steck43/capability-gate/blob/main/{_R}/x.md",
        id="this-repo-on-github",
    ),
    pytest.param(f"my{_R}/x", id="other-word"),
]


@pytest.mark.parametrize("line", _HOME)
def test_this_repositorys_own_receipt_paths_pass(line: str) -> None:
    assert not _foreign(line)


@pytest.mark.parametrize(
    "name",
    [
        "ci.yml",
        "ci.yaml",
        "x.toml",
        "x.cfg",
        "x.sh",
        "nb.ipynb",
        "x.pyi",
        "x.jsonl",
        "README.MD",
        "NOTES.TXT",
        "Makefile",
        "LICENSE",
    ],
)
def test_every_tracked_text_file_is_read(name: str) -> None:
    assert any("plain text" in view for view in _text_views(b"plain text\n"))


def test_a_binary_file_raises_no_false_hit() -> None:
    data = b"\x89PNG\r\n\x1a\n\0\0\0"
    assert not any(_foreign(ln) for v in _text_views(data) for ln in v.split("\n"))


# --- every non-web scheme is a local path; every spelling of the folder counts ---

_FOREIGN_MORE = [
    pytest.param(f"file:///C:/x/{_R}/y.md", id="file-url-drive"),
    pytest.param(f"file:///srv/x/{_R}/y.md", id="file-url-posix"),
    pytest.param(f"file://host/share/{_R}/y.md", id="file-url-host"),
    pytest.param(f"vscode://file/C:/x/{_R}/y.md", id="vscode-url"),
    pytest.param(f"ssh://git@host/x/{_R}/y.md", id="ssh-url"),
    pytest.param(f"elsewhere\uff0f{_R}\uff0fy.md", id="fullwidth-slash"),
    pytest.param(f"elsewhere\u2215{_R}\u2215y.md", id="division-slash"),
    pytest.param(f"elsewhere/{_R[:3]}\u200b{_R[3:]}/y.md", id="zero-width-inside"),
    pytest.param(f"elsewhere/{_R.replace('e', chr(0x435))}/y.md", id="cyrillic-e"),
    pytest.param(f"elsewhere&#47;{_R}&#47;y.md", id="html-entity"),
    pytest.param(f"elsewhere/{_R}", id="no-trailing-slash"),
    pytest.param(f"see elsewhere/{_R}.", id="no-trailing-slash-sentence"),
    pytest.param(f'os.path.join("elsewhere", "{_R}", "y.md")', id="os-path-join"),
    pytest.param(f'"elsewhere/" + "{_R}/y.md"', id="literal-concatenation"),
    pytest.param(
        f"https://gitlab.com/someone/other/-/blob/main/{_R}/y.md", id="gitlab"
    ),
    pytest.param(
        f"https://bitbucket.org/someone/other/src/main/{_R}/y.md", id="bitbucket"
    ),
    pytest.param(
        f"https://codeberg.org/someone/other/src/branch/main/{_R}/y.md", id="codeberg"
    ),
]


@pytest.mark.parametrize("line", _FOREIGN_MORE)
def test_every_scheme_and_spelling_of_a_foreign_receipt_path_is_caught(
    line: str,
) -> None:
    assert _foreign(line)


@pytest.mark.parametrize(
    "line",
    [
        pytest.param(f"https://example.invalid/{_R}/x", id="web-url-elsewhere"),
        pytest.param(f"http://example.invalid/a/{_R}/x", id="plain-http"),
        pytest.param(f"the {_R} folder holds proofs", id="word-in-prose"),
        pytest.param(f"{_R}/A1-KILL-SWITCH-2026-10-09.md", id="own-tree"),
    ],
)
def test_web_urls_and_prose_stay_clean(line: str) -> None:
    assert not _foreign(line)


@pytest.mark.parametrize(
    ("data", "label"),
    [
        pytest.param(
            b"\0" + f"elsewhere/{_R}/y.md\n".encode(), "nul-first", id="nul-first"
        ),
        pytest.param(
            f"elsewhere/{_R}/y.md\n".encode("utf-16"), "utf-16-bom", id="utf-16-bom"
        ),
        pytest.param(
            f"elsewhere/{_R}/y.md\n".encode("utf-16-le"), "utf-16-le", id="utf-16-le"
        ),
        pytest.param(
            f"elsewhere/{_R}/y.md\n".encode("utf-16-be"), "utf-16-be", id="utf-16-be"
        ),
    ],
)
def test_a_file_that_is_not_plain_utf8_is_still_read(data: bytes, label: str) -> None:
    assert any(
        _foreign(line) for view in _text_views(data) for line in view.split("\n")
    ), label


# Cases where only one rule decides: each path would land on a receipts folder
# that exists, or the name only appears in one text view.


@pytest.mark.parametrize(
    "line",
    [
        pytest.param(f"../{ROOT.name}/{_R}/y.md", id="dotdot-back-into-checkout"),
        pytest.param(f"/{_R}/y.md", id="absolute-root-receipts"),
    ],
)
def test_a_path_that_lands_on_this_checkouts_receipts_is_still_foreign(
    line: str,
) -> None:
    assert ROOT.joinpath(_R).is_dir()
    assert _foreign(line)


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(
            f"elsewhere/{_R[:4]}\0{_R[4:]}/y.md\n".encode(), id="nul-inside-name"
        ),
        pytest.param(
            f"elsewhere/{_R.replace('e', chr(0x435))}/y.md\n".encode("utf-16-le"),
            id="utf-16-non-ascii",
        ),
    ],
)
def test_a_name_only_one_text_view_shows_is_still_read(data: bytes) -> None:
    assert any(_foreign(ln) for v in _text_views(data) for ln in v.split("\n"))


# --- look-alike letters in the folder name ------------------------------------


def _swap(old: str, new: str) -> str:
    return _R.replace(old, new)


_LOOKALIKE_NAMES = [
    pytest.param(_swap("r", "ʀ"), id="small-capital-r"),
    pytest.param(_swap("e", "ᴇ"), id="small-capital-e"),
    pytest.param(_swap("c", "ᴄ"), id="small-capital-c"),
    pytest.param(_swap("i", "ɪ"), id="small-capital-i"),
    pytest.param(_swap("p", "ᴘ"), id="small-capital-p"),
    pytest.param(_swap("t", "ᴛ"), id="small-capital-t"),
    pytest.param(_swap("s", "ꜱ"), id="small-capital-s"),
    pytest.param(_swap("i", "ι"), id="greek-iota"),
    pytest.param(_swap("p", "ρ"), id="greek-rho"),
    pytest.param(_swap("e", "ε"), id="greek-epsilon"),
    pytest.param(_swap("t", "τ"), id="greek-tau"),
    pytest.param(_R.upper().replace("E", "Ε"), id="greek-capital-epsilon"),
    pytest.param(_R.upper().replace("I", "Ι"), id="greek-capital-iota"),
    pytest.param(_R.upper().replace("P", "Ρ"), id="greek-capital-rho"),
    pytest.param(_R.upper().replace("T", "Τ"), id="greek-capital-tau"),
    pytest.param(_R.upper().replace("T", "Т"), id="cyrillic-capital-te"),
]


@pytest.mark.parametrize("name", _LOOKALIKE_NAMES)
def test_a_look_alike_letter_in_the_folder_name_never_hides_it(name: str) -> None:
    assert _foreign(f"elsewhere/{name}/y.md")


@pytest.mark.parametrize(
    "line",
    [
        pytest.param("ειρηνη is a word", id="greek-word"),
        pytest.param("ᴇᴄʀ alone", id="small-capitals-alone"),
    ],
)
def test_look_alike_letters_outside_the_folder_name_stay_clean(line: str) -> None:
    assert not _foreign(line)


# --- invisible and combining characters inside the folder name -----------------

_INSIDE = [
    pytest.param("͏", id="combining-grapheme-joiner"),
    pytest.param("ㅤ", id="hangul-filler"),
    pytest.param("ﾠ", id="halfwidth-hangul-filler"),
    pytest.param("ᅟ", id="hangul-choseong-filler"),
    pytest.param("ᅠ", id="hangul-jungseong-filler"),
    pytest.param("̇", id="combining-dot-above"),
    pytest.param("́", id="combining-acute"),
    pytest.param("⃝", id="combining-enclosing-circle"),
    pytest.param("️", id="variation-selector"),
    pytest.param("᠎", id="mongolian-vowel-separator"),
]


@pytest.mark.parametrize("mark", _INSIDE)
def test_an_invisible_or_combining_character_inside_the_name_never_hides_it(
    mark: str,
) -> None:
    assert _foreign(f"elsewhere/{_R[:4]}{mark}{_R[4:]}/y.md")


def test_a_combining_mark_on_another_word_stays_clean() -> None:
    assert not _foreign("café and naïve prose")


# --- a path built from a runtime value is not a path in this checkout -------------

_RUNTIME_JOINS = [
    pytest.param(f'base / "{_R}" / "y.md"', id="path-operator-variable"),
    pytest.param(f'Path(home) / "{_R}"', id="path-operator-call"),
    pytest.param(f'cfg.root / "{_R}/y.md"', id="path-operator-attribute"),
    pytest.param(f'os.path.join(base, "{_R}", "y.md")', id="os-path-join-variable"),
    pytest.param(
        f'os.path.join("docs", base, "{_R}")', id="os-path-join-middle-variable"
    ),
    pytest.param(f'os.path.join(get_root(), "{_R}")', id="os-path-join-call"),
    pytest.param(f'root.joinpath("{_R}", "y.md")', id="joinpath-variable"),
    pytest.param(f'base + "{_R}/y.md"', id="concat-variable-first"),
    pytest.param(f'"/x/" + base + "{_R}/y.md"', id="concat-variable-middle"),
]


@pytest.mark.parametrize("line", _RUNTIME_JOINS)
def test_a_receipt_path_joined_onto_a_runtime_value_is_foreign(line: str) -> None:
    assert _foreign(line)


@pytest.mark.parametrize(
    "line",
    [
        pytest.param(f'os.path.join("{_R}", "y.md")', id="join-starting-at-the-folder"),
        pytest.param(f'"{_R}/" + name', id="variable-after-the-folder"),
        pytest.param("total = a / b + c", id="arithmetic"),
    ],
)
def test_a_join_that_starts_at_this_checkouts_folder_stays_clean(line: str) -> None:
    assert not _foreign(line)


# --- a self-hosted forge is known by its URL shape, not its host -------------------

_FORGE_SHAPES = [
    pytest.param(
        f"https://git.example.invalid/team/repo/-/blob/main/{_R}/y.md", id="gitlab-blob"
    ),
    pytest.param(
        f"https://git.example.invalid/team/repo/-/tree/main/{_R}", id="gitlab-tree"
    ),
    pytest.param(
        f"https://git.example.invalid/team/repo/-/raw/main/{_R}/y.md", id="gitlab-raw"
    ),
    pytest.param(
        f"https://code.example.invalid/team/repo/src/branch/main/{_R}/y.md",
        id="gitea-branch",
    ),
    pytest.param(
        f"https://code.example.invalid/team/repo/src/commit/0123abcd/{_R}/y.md",
        id="gitea-commit",
    ),
    pytest.param(
        f"https://code.example.invalid/team/repo/src/tag/v1/{_R}/y.md", id="gitea-tag"
    ),
    pytest.param(
        f"https://bb.example.invalid/team/repo/src/0123abcd4567/{_R}/y.md",
        id="bitbucket-commit",
    ),
    pytest.param(
        f"https://bb.example.invalid/team/repo/raw/0123abcd4567/{_R}/y.md",
        id="bitbucket-raw",
    ),
]


@pytest.mark.parametrize("line", _FORGE_SHAPES)
def test_a_self_hosted_forge_url_points_into_another_repository(line: str) -> None:
    assert _foreign(line)


@pytest.mark.parametrize(
    "line",
    [
        pytest.param(
            f"https://docs.example.invalid/src/guide/{_R}/x", id="src-word-on-a-site"
        ),
        pytest.param(
            f"https://example.invalid/blob/{_R}/x", id="blob-word-without-dash"
        ),
    ],
)
def test_a_web_url_without_a_forge_shape_stays_clean(line: str) -> None:
    assert not _foreign(line)


# --- a scheme right before the folder name is never this checkout -------------------

_SCHEME_FORMS = [
    pytest.param(f"file:{_R}/y.md", id="file-no-slashes"),
    pytest.param(f"file:./{_R}/y.md", id="file-dot-slash"),
    pytest.param(f"vscode://{_R}/y.md", id="vscode-folder-first"),
    pytest.param(f"file://{_R}/y.md", id="file-folder-as-host"),
    pytest.param(f"vscode:{_R}/y.md", id="vscode-no-slashes"),
    pytest.param(f"C:{_R}/y.md", id="drive-relative"),
]


@pytest.mark.parametrize("line", _SCHEME_FORMS)
def test_a_scheme_right_before_the_folder_name_is_foreign(line: str) -> None:
    assert _foreign(line)


@pytest.mark.parametrize(
    "line",
    [
        pytest.param(
            f"note: {_R}/A1-KILL-SWITCH-2026-10-09.md", id="label-colon-space"
        ),
        pytest.param(f"https://example.invalid/{_R}/x", id="web-url"),
    ],
)
def test_a_colon_label_before_this_checkouts_folder_stays_clean(line: str) -> None:
    assert not _foreign(line)


# --- a left operand anchored to this checkout is home; any other runtime value ----
# --- is foreign, however the literal after it is spelled ---------------------------

_ANCHORED_HOME = [
    pytest.param(
        f'assert (Path(__file__).parent / "{_R}" / "K94.md").is_file()',
        id="file-parent",
    ),
    pytest.param(f'Path(__file__).parents[1] / "{_R}" / "X.md"', id="file-parents"),
    pytest.param(f'Path(__file__).resolve().parent / "{_R}"', id="file-resolve-parent"),
    pytest.param(f'ROOT / "{_R}" / "x.md"', id="root"),
    pytest.param(
        f'os.path.join(os.path.dirname(__file__), "{_R}", "y.md")',
        id="join-dirname-file",
    ),
    pytest.param(
        f'Path(__file__).parent.joinpath("{_R}", "y.md")', id="joinpath-on-file"
    ),
]


@pytest.mark.parametrize("line", _ANCHORED_HOME)
def test_a_path_anchored_to_this_checkout_is_home(line: str) -> None:
    assert not _foreign(line)


def test_a_name_bound_to_this_checkout_in_the_same_file_is_home() -> None:
    text = (
        "HERE = Path(__file__).resolve().parents[1]\n"
        "TOP: Path = HERE\n"
        f"a = HERE / '{_R}' / 'y.md'\n"
        f"b = TOP / '{_R}' / 'y.md'\n"
    )
    assert _hits(text, "tests/test_zqxwvk.py") == []


def test_a_bound_name_keeps_its_tail_and_a_rebound_name_is_not_an_anchor() -> None:
    text = (
        "HERE = Path(__file__).resolve().parents[1]\n"
        "DOCS = HERE / 'docs'\n"
        f"a = DOCS / '{_R}'\n"
        "TWICE = Path(__file__).parent\n"
        "TWICE = get_root()\n"
        f"b = TWICE / '{_R}'\n"
        "LOOPED = Path(__file__).parent\n"
        "for LOOPED in dirs:\n"
        f"    c = LOOPED / '{_R}'\n"
        "OPENED = Path(__file__).parent\n"
        "with mount() as OPENED:\n"
        f"    d = OPENED / '{_R}'\n"
    )
    assert _hits(text, "tests/test_zqxwvk.py") == [3, 6, 9, 12]


def test_a_name_bound_to_a_runtime_value_stays_foreign() -> None:
    text = f"HERE = get_root()\na = HERE / '{_R}' / 'y.md'\n"
    assert _hits(text, "tests/test_zqxwvk.py") == [2]


@pytest.mark.parametrize(
    "line",
    [
        pytest.param(f'Path(__file__).parents[5] / "{_R}"', id="parents-above-root"),
        pytest.param(
            f'Path(__file__).parent.parent.parent / "{_R}"',
            id="parent-chain-above-root",
        ),
        pytest.param(f'ROOT / ".." / "{_R}"', id="root-then-parent-step"),
        pytest.param(f'ROOT / "elsewhere" / "{_R}"', id="root-then-missing-folder"),
    ],
)
def test_an_anchor_that_leaves_the_checkout_is_foreign(line: str) -> None:
    assert _hits(line + "\n", "tests/test_zqxwvk.py") == [1]


_RUNTIME_SHAPES = [
    pytest.param(f'base / "x" / "{_R}" / "y.md"', id="through-an-intermediate-literal"),
    pytest.param(f'base / "x/{_R}/y.md"', id="literal-holding-the-folder-later"),
    pytest.param(
        f'base / "./{_R}/y.md"', id="literal-that-names-this-checkouts-folder"
    ),
    pytest.param(f'base / r"{_R}"', id="raw-literal"),
    pytest.param(f'base / u"{_R}"', id="unicode-literal"),
    pytest.param(f'base / b"{_R}"', id="bytes-literal"),
    pytest.param(f'base / rb"{_R}"', id="raw-bytes-literal"),
    pytest.param(f'base / f"{_R}/{{name}}"', id="f-string"),
    pytest.param(f'base / """{_R}"""', id="triple-quoted"),
    pytest.param(f"base / '''{_R}'''", id="triple-single-quoted"),
    pytest.param(f'base / ("{_R}")', id="parenthesised-literal"),
    pytest.param(f'dirs[0] / "{_R}"', id="subscript-left"),
    pytest.param(f'cfg["root"] / "{_R}"', id="string-subscript-left"),
    pytest.param(f'(a or b) / "{_R}"', id="parenthesised-left"),
    pytest.param(f'get_root(cfg(x)) / "{_R}"', id="nested-call-left"),
    pytest.param(f'base + r"{_R}/y.md"', id="concat-raw-literal"),
]


@pytest.mark.parametrize("line", _RUNTIME_SHAPES)
def test_every_join_shape_onto_a_runtime_value_is_foreign(line: str) -> None:
    assert _foreign(line)


@pytest.mark.parametrize(
    "line",
    [
        pytest.param(f'r"{_R}/y.md"', id="raw-literal-alone"),
        pytest.param(f'("{_R}") / name', id="parenthesised-folder-first"),
        pytest.param("x = rows[0] / 2", id="subscript-arithmetic"),
    ],
)
def test_a_literal_that_starts_at_this_checkouts_folder_stays_clean(line: str) -> None:
    assert not _foreign(line)


# --- every look-alike Unicode's confusables data gives for the folder's letters ---

_MORE_LOOKALIKES = [
    pytest.param(_swap("c", "ϲ"), id="greek-lunate-sigma"),
    pytest.param(_R.upper().replace("C", "Ϲ"), id="greek-capital-lunate-sigma"),
    pytest.param(_swap("i", "ɩ"), id="latin-iota"),
    pytest.param(_swap("t", "т"), id="cyrillic-te"),
    pytest.param(_swap("r", "ɽ"), id="r-with-tail"),
    pytest.param(_swap("r", "ɾ"), id="r-with-fishhook"),
    pytest.param(_swap("e", "ǝ"), id="turned-e"),
    pytest.param(_swap("e", "є"), id="cyrillic-ukrainian-ie"),
    pytest.param(_R.upper().replace("R", "Ꭱ"), id="cherokee-letter-e"),
]


@pytest.mark.parametrize("name", _MORE_LOOKALIKES)
def test_every_confusable_for_the_folder_letters_is_folded(name: str) -> None:
    assert _foreign(f"elsewhere/{name}/y.md")


def test_the_fold_covers_every_confusable_of_the_folder_letters() -> None:
    pairs = [p.split(":") for p in _FOLDER_CONFUSABLES.split()]
    assert len(pairs) == FOLDER_CONFUSABLE_PAIRS
    digest = hashlib.sha256(_FOLDER_CONFUSABLES.encode()).hexdigest()
    assert digest == FOLDER_CONFUSABLES_SHA256, digest
    # Read the way _decoded reads a line: folded, NFKC, folded again.
    missing = [
        code
        for code, letter in pairs
        if unicodedata.normalize("NFKC", chr(int(code, 16)).translate(_FOLD))
        .translate(_FOLD)
        .casefold()
        != letter.casefold()
    ]
    assert missing == []


FOLDER_CONFUSABLE_PAIRS = 182
FOLDER_CONFUSABLES_SHA256 = (
    "ab0abcd7b3b4811670700e74e0df9862ab6e2800bed3dceca752dc001e2fea1c"
)
