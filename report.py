#!/usr/bin/env python3
"""Read-only analysis of capability-gate decision logs for the observe study.

Ingests capability-gate.jsonl and prints the review rig: grant gaps first,
then frequency tables, would-have-denied counts, session/day breakdowns, and
the candidate enforce allowlist distilled from actual use.
"""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml
except ImportError:  # pragma: no cover - yaml is available in Hermes venv
    yaml = None  # type: ignore


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def _load_granted_tools(allowlist_path: Path | None) -> set[str]:
    if allowlist_path is None or not allowlist_path.is_file() or yaml is None:
        return set()
    data = yaml.safe_load(allowlist_path.read_text(encoding="utf-8")) or {}
    skills = data.get("skills") or {}
    star = skills.get("*") or {}
    tools = star.get("tools") or []
    return {str(t) for t in tools}


def _path_prefix(path: str, depth: int = 3) -> str:
    norm = os.path.normpath(path)
    parts = [p for p in norm.split(os.sep) if p]
    if not parts:
        return norm
    return os.sep.join(parts[: min(depth, len(parts))])


def _day_key(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


def _collect_paths(entry: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for p in entry.get("paths") or []:
        if isinstance(p, str) and p:
            paths.append(p)
    summary = entry.get("arg_summary") or {}
    for p in (summary.get("paths") or {}).values():
        if isinstance(p, str) and p:
            paths.append(p)
    return paths


def analyze(
    entries: Iterable[dict[str, Any]],
    granted_tools: set[str],
) -> dict[str, Any]:
    entries = list(entries)
    tool_counts: Counter[str] = Counter()
    path_counts: Counter[str] = Counter()
    prefix_counts: Counter[tuple[str, str]] = Counter()
    deny_reasons: Counter[str] = Counter()
    session_counts: Counter[str] = Counter()
    day_counts: Counter[str] = Counter()
    used_tools: set[str] = set()
    used_but_not_granted: Counter[str] = Counter()
    candidate_pairs: Counter[tuple[str, str]] = Counter()

    for row in entries:
        tool = str(row.get("tool") or "")
        if tool:
            tool_counts[tool] += 1
            used_tools.add(tool)
            if granted_tools and tool not in granted_tools:
                used_but_not_granted[tool] += 1

        for path in _collect_paths(row):
            path_counts[path] += 1
            prefix = _path_prefix(path)
            candidate_pairs[(tool, prefix)] += 1
            prefix_counts[(tool, prefix)] += 1

        if row.get("verdict") == "deny":
            deny_reasons[str(row.get("reason") or "unknown")] += 1

        sid = row.get("session_id")
        if sid:
            session_counts[str(sid)] += 1
        ts = row.get("ts")
        if isinstance(ts, (int, float)):
            day_counts[_day_key(ts)] += 1

    return {
        "total": len(entries),
        "granted_tools": sorted(granted_tools),
        "used_but_not_granted": used_but_not_granted,
        "tool_counts": tool_counts,
        "path_counts": path_counts,
        "prefix_counts": prefix_counts,
        "deny_reasons": deny_reasons,
        "session_counts": session_counts,
        "day_counts": day_counts,
        "candidate_pairs": candidate_pairs,
        "used_tools": sorted(used_tools),
    }


def format_report(stats: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("capability-gate observe study report")
    lines.append("=" * 40)
    lines.append(f"entries: {stats['total']}")
    lines.append("")

    lines.append("USED BUT NOT GRANTED (headline — decide before enforce)")
    lines.append("-" * 40)
    gap = stats["used_but_not_granted"]
    if not gap:
        lines.append("  (none — every observed tool is in the current grant list)")
    else:
        for tool, count in gap.most_common():
            lines.append(f"  {tool}: {count}")
    lines.append("")
    lines.append(
        f"current grant ({len(stats['granted_tools'])} tools): "
        + ", ".join(stats["granted_tools"]) or "(none parsed)"
    )
    lines.append("")

    lines.append("tool frequency")
    for tool, count in stats["tool_counts"].most_common():
        lines.append(f"  {tool}: {count}")
    lines.append("")

    lines.append("path frequency (top 20)")
    for path, count in stats["path_counts"].most_common(20):
        lines.append(f"  {count:4d}  {path}")
    lines.append("")

    lines.append("would-have-denied (verdict=deny) by reason")
    if not stats["deny_reasons"]:
        lines.append("  (none)")
    else:
        for reason, count in stats["deny_reasons"].most_common():
            lines.append(f"  {count:4d}  {reason}")
    lines.append("")

    lines.append("per-session breakdown (top 15)")
    for sid, count in stats["session_counts"].most_common(15):
        lines.append(f"  {sid}: {count}")
    lines.append("")

    lines.append("per-day breakdown")
    for day, count in sorted(stats["day_counts"].items()):
        lines.append(f"  {day}: {count}")
    lines.append("")

    lines.append("candidate enforce allowlist (tool, path-prefix) — top 30")
    for (tool, prefix), count in stats["candidate_pairs"].most_common(30):
        lines.append(f"  {count:4d}  {tool}  {prefix}")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--log",
        type=Path,
        default=Path(os.path.expanduser("~/.hermes/logs/capability-gate.jsonl")),
        help="Path to capability-gate.jsonl",
    )
    parser.add_argument(
        "--allowlist",
        type=Path,
        default=None,
        help="Live allowlist.yaml for grant-gap analysis (default: sibling allowlist.yaml)",
    )
    args = parser.parse_args(argv)

    allowlist = args.allowlist
    if allowlist is None:
        allowlist = Path(__file__).resolve().parent / "allowlist.yaml"

    entries = _load_jsonl(args.log)
    granted = _load_granted_tools(allowlist)
    stats = analyze(entries, granted)
    print(format_report(stats))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
