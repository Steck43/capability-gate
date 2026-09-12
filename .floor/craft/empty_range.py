"""Scheduled empty-range skip. Unresolvable BASE stays 3."""

from __future__ import annotations

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
