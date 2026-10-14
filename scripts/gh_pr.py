#!/usr/bin/env python3
"""Run `gh pr create` or `gh pr edit` only after its title and body pass the leak scan.

usage: python scripts/gh_pr.py create|edit [gh pr arguments ...]

The title (--title / -t), body (--body / -b), and body file (--body-file / -F,
or "-" for stdin) are read and checked with the same rules as
scripts/leak_denylist_scan.py. Any hit, or no denylist configured, stops the
call before gh runs, so a pull request never opens with text that CI would
only flag afterwards. The arguments are then passed to gh unchanged.

GH_PR_GH names the gh executable (default "gh"); a path ending in .py runs
under this Python, which is how the tests stand in a fake gh.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import leak_denylist_scan as scan  # noqa: E402

_TEXT = {"--title": "title", "-t": "title", "--body": "body", "-b": "body"}
_FILE = {"--body-file", "-F"}
_REFUSE = {
    "--fill",
    "--fill-first",
    "--fill-verbose",
    "--editor",
    "-T",
    "--web",
    "--template",
}
_ATTACHED = (("-t", "title", False), ("-b", "body", False), ("-F", "body file", True))


class _Bypass(Exception):
    def __init__(self, flag: str) -> None:
        self.flag = flag


def _pieces(args: list[str]) -> tuple[list[tuple[str, str]], list[str]]:
    """(label, text) pairs to scan, and args with any stdin body made concrete."""
    out: list[tuple[str, str]] = []
    passed: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        flag, eq, inline = arg.partition("=")
        if flag in _REFUSE:
            raise _Bypass(flag)
        attached = False
        for short, label, is_file in _ATTACHED:
            if (
                arg.startswith(short)
                and len(arg) > len(short)
                and not arg.startswith("--")
                and not eq
            ):
                value = arg[len(short) :]
                text = Path(value).read_text(encoding="utf-8") if is_file else value
                out.append((label, text))
                passed.append(arg)
                attached = True
                break
        if attached:
            i += 1
            continue
        if flag in _TEXT or flag in _FILE:
            value = inline if eq else (args[i + 1] if i + 1 < len(args) else "")
            if flag in _FILE:
                text = (
                    sys.stdin.read()
                    if value == "-"
                    else Path(value).read_text(encoding="utf-8")
                )
                out.append(("body file", text))
                if value == "-":
                    passed += ["--body", text]
                    i += 1 if eq else 2
                    continue
            else:
                out.append((_TEXT[flag], value))
            passed += [arg] if eq else [arg, value]
            i += 1 if eq else 2
            continue
        passed.append(arg)
        i += 1
    return out, passed


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in ("create", "edit"):
        print(
            "gh_pr: this wrapper covers `pr create` and `pr edit` only", file=sys.stderr
        )
        return 2
    names = scan.load_denylist()
    if names is None:
        print("gh_pr: denylist not configured; refusing to send text unchecked")
        return 1
    try:
        pieces, passed = _pieces(argv)
    except _Bypass as exc:
        print(f"gh_pr: {exc.flag} composes text outside the scan; gh was not called")
        return 2
    hits = [
        (label, n, rule)
        for label, text in pieces
        for n, rule in scan.scan_text(text, names)
    ]
    for label, n, rule in hits:
        print(f"gh_pr: pull request {label}:{n}: {rule}")
    if hits:
        print(f"gh_pr: {len(hits)} hit(s); gh was not called")
        return 1
    gh = os.environ.get("GH_PR_GH", "gh")
    cmd = [sys.executable, gh] if gh.endswith(".py") else [gh]
    return subprocess.run([*cmd, "pr", *passed], check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
