"""Public text cites no path that exists only in a private repository.

Receipts and raw artifacts that live outside this repository are named as
private, with their digests, never by a path a reader cannot open. Every
tracked text file is read (any extension, or none). Each line is decoded first:
backslashes become slashes, a JSON-escaped slash is a slash, and URL encoding is
undone until the line stops changing. Then every path that reaches a receipts
folder (in any letter case) is judged by the whole path before it:

- nothing before it, or a folder path that exists inside this checkout: home;
- a leading slash, a drive letter, or any ".." step: another tree, even when it
  would land on a receipts folder outside the checkout;
- a GitHub blob, tree or raw URL: home only when it points into this
  repository, judged by the path after the ref;
- any other URL: not a repository path, not judged.

The file names no private folder: a foreign path is refused because its folder
does not exist here, not because it is listed.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from urllib.parse import unquote

import pytest

ROOT = Path(__file__).resolve().parents[1]
THIS_REPO = ("steck43", "capability-gate")
# The text before a receipts folder, back to the start of the token it sits in.
_BEFORE_RECEIPTS = re.compile(r"([^\s`'\"()<>\[\]{}|,;=*]*?)receipts/", re.I)
_GITHUB = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/([\w.-]+)/([\w.-]+)/(?:blob|tree|raw)/[^/]+/(.*)$",
    re.I,
)
_RAW = re.compile(
    r"^(?:https?://)?raw\.githubusercontent\.com/([\w.-]+)/([\w.-]+)/[^/]+/(.*)$", re.I
)


def _decoded(line: str) -> str:
    text = line
    for _ in range(4):
        nxt = unquote(text.replace("\\/", "/")).replace("\\", "/")
        if nxt == text:
            break
        text = nxt
    return text


def _foreign_prefix(prefix: str) -> bool:
    if "://" in prefix or prefix.lower().startswith(("github.com/", "www.github")):
        m = _GITHUB.match(prefix) or _RAW.match(prefix)
        if m is None:
            return "github" in prefix.lower()
        owner, repo, rest = m.groups()
        if (owner.lower(), repo.lower().removesuffix(".git")) != THIS_REPO:
            return True
        prefix = rest
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


def _is_read(name: str, data: bytes) -> bool:
    """Every tracked file is read unless its bytes say it is binary."""
    return b"\0" not in data[:8192]


def test_tracked_text_cites_no_private_repository_path() -> None:
    listed = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
    )
    found = []
    for rel in filter(None, listed.stdout.decode("utf-8").split("\0")):
        path = ROOT / rel
        if not path.is_file():
            continue
        data = path.read_bytes()
        if not _is_read(rel, data):
            continue
        text = data.decode("utf-8", errors="replace")
        for n, line in enumerate(text.split("\n"), 1):
            if _foreign(line):
                found.append(f"{rel}:{n}")
    assert found == []


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
    assert _is_read(name, b"plain text\n")


def test_a_binary_file_is_not_read_as_text() -> None:
    assert not _is_read("x.png", b"\x89PNG\r\n\x1a\n\0\0\0")
