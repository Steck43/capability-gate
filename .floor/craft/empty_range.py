"""Scheduled empty-range skip. Unresolvable BASE stays 3.

CLI for floor.yml: python .floor/craft/empty_range.py --base SHA --head SHA --event NAME
"""

from __future__ import annotations

import argparse

SKIP_EVENTS = frozenset({"schedule", "workflow_dispatch"})


def blocked_exit(
    *,
    base_resolves: bool,
    base_sha: str | None,
    head_sha: str | None,
    event_name: str,
) -> int:
    """Return the craft job exit code for a BASE/HEAD pair."""
    if not base_resolves or not base_sha or not head_sha:
        return 3
    if base_sha == head_sha and event_name in SKIP_EVENTS:
        return 0
    if base_sha == head_sha:
        return 3
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Empty-range exit for craft jobs")
    parser.add_argument("--base", default="")
    parser.add_argument("--head", default="")
    parser.add_argument("--event", default="")
    parser.add_argument(
        "--base-resolves",
        action="store_true",
        default=True,
        help="BASE was already verified by the workflow",
    )
    args = parser.parse_args(argv)
    return blocked_exit(
        base_resolves=bool(args.base) and bool(args.head),
        base_sha=args.base or None,
        head_sha=args.head or None,
        event_name=args.event,
    )


if __name__ == "__main__":
    raise SystemExit(main())
