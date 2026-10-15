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
    # Split so this file's own line does not cite a foreign tree.
    assert _foreign("raw artifact `elsewhere" + "/receipts/raw/x.json`")
    assert not _foreign("see `receipts/A1-KILL-SWITCH-2026-10-09.md`")
    assert not _foreign("https://example.invalid/receipts/x")
