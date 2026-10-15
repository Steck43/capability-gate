"""Public text cites no path that exists only in a private repository.

Receipts and raw artifacts that live outside this repository are named as
private, with their digests, never by a path a reader cannot open. Every
tracked file is read in each text view a reader could get from its bytes (UTF-8
with NUL bytes dropped, and UTF-16 when a byte-order mark or a NUL byte says it
may be). Each line is decoded until it stops changing: HTML entities, URL
encoding, NFKC, format characters dropped, slash look-alikes and Cyrillic
letters that look like the folder name's letters folded, backslashes and JSON
escaped slashes as slashes, os.path.join calls and two adjacent string
literals joined. Then every receipts folder (any letter case, with or without a
trailing slash) is judged by the whole path before it:

- nothing before it, or a folder path that exists inside this checkout: home;
- a leading slash, a drive letter, or any ".." step: another tree, even when
  it would land on this checkout's own receipts folder;
- a URL with any scheme but http or https (file, vscode, ssh, ...): a path
  outside the checkout;
- a GitHub blob, tree or raw URL: home only when it points into this
  repository, judged by the path after the ref; any other code forge: another
  repository;
- any other web URL: not a repository path, not judged.

The file names no private folder: a foreign path is refused because its folder
does not exist here, not because it is listed.
"""

from __future__ import annotations

import codecs
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
# Slash look-alikes NFKC keeps, and Cyrillic letters that look like the Latin
# letters of the folder name.
_FOLD = str.maketrans(
    {
        "∕": "/",
        "⁄": "/",
        "⧸": "/",
        "е": "e",
        "Е": "E",
        "с": "c",
        "С": "C",
        "р": "p",
        "Р": "P",
        "і": "i",
        "І": "I",
        "ѕ": "s",
        "Ѕ": "S",
    }
)
_JOIN_CALL = re.compile(r"(?:os\.path|posixpath|ntpath)\.join\(([^()]*)\)")
_LITERAL = re.compile(r"""["']([^"']*)["']""")
_LITERAL_PLUS = re.compile(r"""(["'])\s*\+\s*(["'])""")


def _joined(match: re.Match[str]) -> str:
    return '"' + "/".join(_LITERAL.findall(match.group(1))) + '"'


def _decoded(line: str) -> str:
    text = line
    for _ in range(6):
        nxt = html.unescape(unquote(text.replace("\\/", "/")))
        nxt = unicodedata.normalize("NFKC", nxt)
        nxt = "".join(c for c in nxt if unicodedata.category(c) != "Cf")
        nxt = nxt.translate(_FOLD).replace("\\", "/")
        nxt = _LITERAL_PLUS.sub("", _JOIN_CALL.sub(_joined, nxt))
        if nxt == text:
            break
        text = nxt
    return text


def _foreign_url(prefix: str) -> bool | str:
    """True or False for a URL; the repository path after the ref for a URL
    into this repository on GitHub, to be judged like any other path."""
    scheme, _, rest = prefix.partition("://")
    if not rest:
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
    return False  # another web site: not a repository path


def _foreign_prefix(prefix: str) -> bool:
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
    return not ROOT.joinpath(*parts, "receipts").is_dir()


def _foreign(line: str) -> bool:
    return any(
        _foreign_prefix(m.group(1)) for m in _BEFORE_RECEIPTS.finditer(_decoded(line))
    )


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
            for n, line in enumerate(view.split("\n"), 1):
                if _foreign(line):
                    found.append(f"{rel}:{n}")
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
