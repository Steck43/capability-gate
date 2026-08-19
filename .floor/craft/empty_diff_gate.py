#!/usr/bin/env python3
"""empty_diff_gate.py — a commit range with zero file changes must fail.

changelog_gate.py exits 0 when no user-facing paths are in range (skip).
That skip is not a BREAK. This job is the named empty-diff BREAK:

  workflow job: craft (empty-diff)
  python:       .floor/craft/empty_diff_gate.py

Exit 0 = range has at least one path. Exit 2 = empty diff or measurement failure.
"""

from __future__ import annotations

import argparse
import subprocess
import sys

EXIT_FAIL = 2


def _run(cmd: list[str]) -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError as exc:
        print(f"empty_diff_gate: measurement failure: {exc}", file=sys.stderr)
        raise SystemExit(EXIT_FAIL) from exc
    return r.returncode, r.stdout or "", r.stderr or ""


def changed_files(base: str, head: str) -> list[str]:
    rc, out, err = _run(["git", "diff", "--name-only", f"{base}...{head}"])
    if rc != 0:
        rc, out, err = _run(["git", "diff", "--name-only", f"{base}..{head}"])
    if rc != 0:
        print(f"empty_diff_gate: cannot list changed files: {err}", file=sys.stderr)
        raise SystemExit(EXIT_FAIL)
    return [line.strip() for line in out.splitlines() if line.strip()]


def selftest() -> int:
    print("ok empty_diff_gate selftest (no git range)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--base", default="origin/main")
    ap.add_argument("--head", default="HEAD")
    args = ap.parse_args()
    if args.selftest:
        return selftest()

    files = changed_files(args.base, args.head)
    if not files:
        print(
            "empty_diff_gate: FAIL empty diff "
            f"({args.base}...{args.head}). changelog_gate skip-green is not this job.",
            file=sys.stderr,
        )
        return EXIT_FAIL
    print(f"empty_diff_gate: ok ({len(files)} paths)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
