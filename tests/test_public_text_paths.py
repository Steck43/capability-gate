"""Public text cites no path that exists only in a private repository.

Receipts and raw artifacts that live outside this repository are named as
private, with their digests, never by a path a reader cannot open. A path of
the form <folder>/receipts/... whose folder does not exist here points into
another repository's receipt tree, so it is refused without this file naming
any such folder.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
# Every tracked text form a reader can open, code and metadata included.
TEXT_GLOBS = ("*.md", "*.txt", "*.rst", "*.py", "*.json", "*.cff")
FOREIGN_RECEIPTS = re.compile(r"(?<![\w./-])([\w.-]+)/receipts/")


def _foreign(line: str) -> bool:
    return any(
        not (ROOT / m.group(1) / "receipts").is_dir()
        for m in FOREIGN_RECEIPTS.finditer(line)
    )


def test_tracked_text_cites_no_private_repository_path() -> None:
    listed = subprocess.run(
        ["git", "ls-files", "-z", *TEXT_GLOBS],
        cwd=ROOT,
        capture_output=True,
        check=True,
    )
    found = []
    for rel in filter(None, listed.stdout.decode("utf-8").split("\0")):
        text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
        for n, line in enumerate(text.splitlines(), 1):
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
