"""Tests for report.py using a synthetic log fixture."""

import json

import report

FIXTURE = [
    {
        "ts": 1780000000.0,
        "mode": "observe",
        "verdict": "allow",
        "reason": "allowed by policy",
        "skill": "*",
        "tool": "write_file",
        "paths": ["/home/landen/.hermes/notes/a.md"],
        "enforced": False,
        "session_id": "s1",
        "arg_summary": {
            "keys": ["path", "content"],
            "paths": {"path": "/home/landen/.hermes/notes/a.md"},
            "content_lengths": {"content": 12},
        },
    },
    {
        "ts": 1780000100.0,
        "mode": "observe",
        "verdict": "deny",
        "reason": "tool 'browser_navigate' not granted to '*'",
        "skill": "*",
        "tool": "browser_navigate",
        "paths": [],
        "enforced": False,
        "session_id": "s1",
    },
    {
        "ts": 1780864000.0,
        "mode": "observe",
        "verdict": "allow",
        "reason": "allowed by policy",
        "skill": "*",
        "tool": "read_file",
        "paths": ["/home/landen/.hermes/research/x.md"],
        "enforced": False,
        "session_id": "s2",
    },
]


def test_analyze_grant_gap_and_denies(tmp_path):
    log = tmp_path / "capability-gate.jsonl"
    with log.open("w", encoding="utf-8") as fh:
        for row in FIXTURE:
            fh.write(json.dumps(row) + "\n")

    allowlist = tmp_path / "allowlist.yaml"
    allowlist.write_text(
        "skills:\n  '*':\n    tools: [read_file, write_file, web_search]\n",
        encoding="utf-8",
    )

    entries = report._load_jsonl(log)
    granted = report._load_granted_tools(allowlist)
    stats = report.analyze(entries, granted)

    assert stats["total"] == 3
    assert stats["used_but_not_granted"]["browser_navigate"] == 1
    assert stats["deny_reasons"]["tool 'browser_navigate' not granted to '*'"] == 1
    assert stats["session_counts"]["s1"] == 2
    assert len(stats["day_counts"]) >= 1


def test_format_report_headlines_grant_gap():
    stats = report.analyze(FIXTURE, {"read_file", "write_file", "web_search"})
    text = report.format_report(stats)
    assert "USED BUT NOT GRANTED" in text
    assert "browser_navigate" in text
