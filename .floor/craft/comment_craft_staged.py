#!/usr/bin/env python3
"""pre-commit entry: scan staged diff for narration comments."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

# Allow running from roof root with .floor/craft layout.
HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from comment_craft import scan_diff  # noqa: E402


def main() -> int:
    diff = (
        subprocess.run(
            ["git", "diff", "--cached", "-U3"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        ).stdout
        or ""
    )
    hits = scan_diff(diff)
    for h in hits:
        print(h, file=sys.stderr)
    if hits:
        print(f"comment_craft_staged: {len(hits)} hit(s)", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
