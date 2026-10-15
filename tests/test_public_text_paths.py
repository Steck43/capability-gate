"""Public text cites no path that exists only in a private repository.

Receipts and raw artifacts that live outside this repository are named as
private, with their digests, never by a path a reader cannot open.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Layout prefixes of the private estate repository's receipt tree.
PRIVATE_PREFIXES = ("wsl/receipts/",)
# Every tracked text form a reader can open, code and metadata included.
TEXT_GLOBS = ("*.md", "*.txt", "*.rst", "*.py", "*.json", "*.cff")


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
            if any(prefix in line for prefix in PRIVATE_PREFIXES):
                found.append(f"{rel}:{n}")
    assert found == []
