#!/usr/bin/env python3
"""Block AI authorship trailers in commit messages.

WHY THIS IS CUSTOM
Secret scanners, linters and formatters are solved problems with maintained
upstream tools, and this floor delegates to them. Authorship is not solved,
because it is a policy question specific to this estate: Landen's public
argument is that he built and verified this work, and a machine co-author
trailer on the containment plane undercuts it at exactly the wrong moment.

WHY IT EXISTS AT ALL
On 2026-08-18 a publish gate found six `Co-authored-by: Cursor` trailers across
three repositories - aegis-atoms, aegis-bootstrap and isolation-layer-review -
after three separate campaign documents had asserted there were none. Two of
those documents were written by seats that had "checked."

Runs at commit-msg, so it stops the trailer before it is ever in history, where
removing it costs a rewrite instead of an edit.

Exit 0 = clean. Exit 1 = trailer present, commit blocked.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Deliberately broad on the co-author line and narrow elsewhere. A false
# positive here costs one `--no-verify`; a false negative costs a history
# rewrite on a public repo.
PATTERNS = [
    (
        re.compile(
            r"^\s*co-authored-by:.*"
            r"(claude|cursor|copilot|gpt|chatgpt|gemini|assistant|\bbot\b|\bai\b)",
            re.I | re.M,
        ),
        "AI co-author trailer",
    ),
    (
        re.compile(
            r"generated with .{0,40}(claude|cursor|copilot|chatgpt|gemini)", re.I
        ),
        "generated-with attribution",
    ),
    (re.compile(r"\U0001F916"), "robot emoji (🤖) - reads as AI attribution"),
    (
        re.compile(
            r"^\s*(assisted|authored)[- ]by:.*"
            r"(claude|cursor|copilot|gpt|gemini)",
            re.I | re.M,
        ),
        "AI assistance trailer",
    ),
]


def check(text: str) -> list[str]:
    hits = []
    for rx, label in PATTERNS:
        m = rx.search(text)
        if m:
            hits.append(f"{label}: {m.group(0).strip()[:90]}")
    return hits


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: no_ai_trailer.py <commit-msg-file>", file=sys.stderr)
        return 2
    path = Path(argv[1])
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        # Do not fail open. An unreadable message is not a clean message.
        print(f"no-ai-trailer: cannot read {path}: {exc}", file=sys.stderr)
        return 1

    # Ignore the comment block git appends; it is not part of the message.
    body = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )

    hits = check(body)
    if not hits:
        return 0

    print("BLOCKED: AI authorship trailer in commit message.\n", file=sys.stderr)
    for h in hits:
        print(f"  {h}", file=sys.stderr)
    print(
        "\nCommits in this estate are authored by Landen Stecker. The work is his;\n"
        "the tooling is not a co-author. Remove the trailer and commit again.\n"
        "\nIf you believe this is a false positive, fix the pattern in\n"
        ".githooks/no_ai_trailer.py rather than bypassing with --no-verify -\n"
        "a bypass leaves no record and the next person hits the same wall.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
