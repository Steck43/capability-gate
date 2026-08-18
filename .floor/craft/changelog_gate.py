#!/usr/bin/env python3
"""changelog_gate.py — user-facing diffs must carry a CHANGELOG delta.

Keep a Changelog shape is checked when CHANGELOG.md exists. Absence of any
CHANGELOG file while user-facing paths change is a fail.

Exit 0 = ok. Exit 2 = mismatch or measurement failure.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

EXIT_FAIL = 2

USER_FACING = re.compile(
    r"^(src/|lib/|app/|capability_gate\.py|__init__\.py|tools/|"
    r"\.github/workflows/|pyproject\.toml|setup\.py|README)",
    re.I,
)
CHANGELOG_NAMES = ("CHANGELOG.md", "CHANGELOG", "CHANGES.md", "HISTORY.md")
KEEP_A_CHANGELOG = re.compile(
    r"^##\s+(\[?[0-9]+\.[0-9].*\]?|\[Unreleased\]|Unreleased)",
    re.I | re.M,
)


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
        print(f"changelog_gate: measurement failure: {exc}", file=sys.stderr)
        raise SystemExit(EXIT_FAIL) from exc
    return r.returncode, r.stdout or "", r.stderr or ""


def changed_files(base: str, head: str) -> list[str]:
    rc, out, err = _run(["git", "diff", "--name-only", f"{base}...{head}"])
    if rc != 0:
        rc, out, err = _run(["git", "diff", "--name-only", f"{base}..{head}"])
    if rc != 0:
        # Unborn / shallow: fall back to files changed vs empty tree of HEAD~0 staged
        rc, out, err = _run(["git", "diff", "--name-only", "HEAD~1", "HEAD"])
    if rc != 0 and not out.strip():
        print(f"changelog_gate: cannot list changed files: {err}", file=sys.stderr)
        raise SystemExit(EXIT_FAIL)
    return [line.strip() for line in out.splitlines() if line.strip()]


def find_changelog(root: Path) -> Path | None:
    for name in CHANGELOG_NAMES:
        p = root / name
        if p.is_file():
            return p
    return None


def selftest() -> int:
    bad = 0
    # Unit-level: KEEP_A_CHANGELOG
    ok_text = "## [Unreleased]\n\n### Added\n\n- Floor craft jobs\n"
    if not KEEP_A_CHANGELOG.search(ok_text):
        print("FAIL keep-a-changelog header")
        bad += 1
    else:
        print("ok keep-a-changelog header")
    if USER_FACING.search("src/foo.py") and not USER_FACING.search("tests/test_x.py"):
        print("ok user-facing matcher")
    else:
        print("FAIL user-facing matcher")
        bad += 1
    print(f"\n{2 - bad}/2 selftest cases correct")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--base", default="origin/main")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument(
        "--allow-missing-on",
        nargs="*",
        default=["docs/", "tests/", ".githooks/", ".pre-commit"],
        help="path prefixes that do not alone require a changelog (unused when any user-facing hit)",
    )
    args = ap.parse_args()
    if args.selftest:
        return selftest()

    root = Path.cwd()
    files = changed_files(args.base, args.head)
    user = [f for f in files if USER_FACING.search(f)]
    if not user:
        print("changelog_gate: no user-facing paths in range; skip")
        return 0

    cl = find_changelog(root)
    if cl is None:
        print(
            "changelog_gate: user-facing changes without a CHANGELOG.md "
            f"(touched: {', '.join(user[:8])}{'…' if len(user) > 8 else ''}). "
            "Add Keep a Changelog file and an Unreleased entry.",
            file=sys.stderr,
        )
        return EXIT_FAIL

    cl_changed = any(
        Path(f).name in CHANGELOG_NAMES or f.endswith(n)
        for f in files
        for n in CHANGELOG_NAMES
    )
    # Also accept path equal to changelog relative
    cl_rel = str(cl.relative_to(root)).replace("\\", "/")
    if cl_rel in files or any(f.replace("\\", "/") == cl_rel for f in files):
        cl_changed = True
    if not cl_changed:
        print(
            f"changelog_gate: {cl_rel} must change when user-facing files change "
            f"({', '.join(user[:5])}).",
            file=sys.stderr,
        )
        return EXIT_FAIL

    text = cl.read_text(encoding="utf-8")
    if not KEEP_A_CHANGELOG.search(text):
        print(
            f"changelog_gate: {cl_rel} missing Keep a Changelog section "
            "(## [Unreleased] or ## [x.y.z]).",
            file=sys.stderr,
        )
        return EXIT_FAIL

    print(f"changelog_gate: ok ({cl_rel} updated with user-facing changes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
