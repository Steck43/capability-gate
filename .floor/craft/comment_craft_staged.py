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


def main() -> int:
    # Imported here rather than at module level because it only resolves after
    # the sys.path insert above. At module level it needs a `noqa: E402`, and a
    # suppression is a claim about which rules a roof enables: capability-gate
    # reported RUF100 on that exact directive because E402 is not enabled in
    # its config, so the shipped file linted clean on four roofs and red on the
    # fifth. A local import needs no suppression and is right everywhere.
    from comment_craft import scan_diff

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
