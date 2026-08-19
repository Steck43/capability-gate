#!/usr/bin/env python3
"""empty_diff_gate.py — a commit range with zero file changes must fail.

changelog_gate.py exits 0 when no user-facing paths are in range (skip).
That skip is not a BREAK. This job is the named empty-diff BREAK:

  workflow job: craft (empty-diff)
  python:       .floor/craft/empty_diff_gate.py

Scope: pull requests only. On push, schedule and workflow_dispatch there is no
meaningful base — BASE resolves to origin/main, which on a push to main is head, so
the range is empty by definition rather than by defect. The workflow guards this job
with `if: github.event_name == 'pull_request'` for that reason. Not-applicable and
violated are different states, and a gate that cannot tell them apart goes red on
everything, which is as useless as green on nothing.

Exit 0 = range has at least one path. Exit 2 = empty diff or measurement failure.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
import sys
import tempfile

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


def changed_files(base: str, head: str) -> tuple[list[str], str]:
    """Return (paths, range_actually_used).

    Three-dot is tried first and two-dot is the fallback. The caller reports which one
    produced the answer, because naming a range that was not used misleads exactly the
    person reading a failure.
    """
    rng = f"{base}...{head}"
    rc, out, err = _run(["git", "diff", "--name-only", rng])
    if rc != 0:
        rng = f"{base}..{head}"
        rc, out, err = _run(["git", "diff", "--name-only", rng])
    if rc != 0:
        print(f"empty_diff_gate: cannot list changed files: {err}", file=sys.stderr)
        raise SystemExit(EXIT_FAIL)
    return [line.strip() for line in out.splitlines() if line.strip()], rng


def selftest() -> int:
    """Forced-red and must-not-fire cases against a throwaway repository.

    A gate whose selftest only prints ok is the shape this gate exists to catch. It has
    to be made to fail on purpose, and it has to stay quiet when a range legitimately
    contains changes.
    """
    failures = 0
    with tempfile.TemporaryDirectory() as repo:
        def git(*args: str) -> tuple[int, str, str]:
            return _run(["git", "-C", repo, *args])

        git("init", "-q", "-b", "main")
        git("config", "user.email", "selftest@local")
        git("config", "user.name", "selftest")
        pathlib.Path(repo, "a.txt").write_text("one" + os.linesep, encoding="utf-8")
        git("add", "-A")
        git("commit", "-q", "-m", "base")
        base = git("rev-parse", "HEAD")[1].strip()

        pathlib.Path(repo, "b.txt").write_text("two" + os.linesep, encoding="utf-8")
        git("add", "-A")
        git("commit", "-q", "-m", "change")
        head = git("rev-parse", "HEAD")[1].strip()

        cwd = os.getcwd()
        try:
            os.chdir(repo)

            files, rng = changed_files(base, "HEAD")
            ok = bool(files)
            failures += 0 if ok else 1
            print(f"  {'ok  ' if ok else 'FAIL'} must-not-fire: real change reports "
                  f"{len(files)} path(s) [{rng}]")

            files, rng = changed_files(head, "HEAD")
            red = not files
            failures += 0 if red else 1
            print(f"  {'ok  ' if red else 'FAIL'} forced-red: base==head reports empty "
                  f"[{rng}], gate returns {EXIT_FAIL}")
        finally:
            os.chdir(cwd)

    print(f"\n{2 - failures}/2 selftest cases correct")
    return 0 if failures == 0 else EXIT_FAIL


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--base", default="origin/main")
    ap.add_argument("--head", default="HEAD")
    args = ap.parse_args()
    if args.selftest:
        return selftest()

    files, rng = changed_files(args.base, args.head)
    if not files:
        print(
            "empty_diff_gate: FAIL empty diff "
            f"({rng}). changelog_gate skip-green is not this job.",
            file=sys.stderr,
        )
        return EXIT_FAIL
    print(f"empty_diff_gate: ok ({len(files)} paths, {rng})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
