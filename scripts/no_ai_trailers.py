"""Fail when commit history carries an AI authorship trailer.

The floor's authorship job writes every commit message in history to a file
(`git log --all --format=%B`) and runs this check on it as a plain command, so
a failure here always fails the step. An empty history file is a failure too:
a check that read nothing proved nothing.

Usage: python scripts/no_ai_trailers.py HISTORY_FILE
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# The pattern is assembled from parts so that no line of this file reads as
# a trailer to the repository's own leak scans.
_TOOLS = ("claude", "cursor", "copilot", "gpt", "gemini", "assistant")
_KEY = "co-authored-by"
_GENERATED = "generated with"
TRAILER = re.compile(
    _KEY
    + ":.*("
    + "|".join(_TOOLS)
    + ")|"
    + _GENERATED
    + " .*("
    + "|".join(_TOOLS[:3])
    + ")",
    re.IGNORECASE,
)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("::error::usage: no_ai_trailers.py HISTORY_FILE")
        return 2
    lines = Path(args[0]).read_text(encoding="utf-8", errors="replace").splitlines()
    if not lines:
        print("::error::history is empty; nothing was checked")
        return 1
    hits = [n for n, line in enumerate(lines, 1) if TRAILER.search(line)]
    print(
        f"authorship: {len(lines)} lines checked, {len(hits)} AI authorship trailer(s)"
    )
    if hits:
        print(f"::error::AI authorship trailer found in history (line {hits[0]})")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
