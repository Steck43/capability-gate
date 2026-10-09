"""G-3 / G-report-star-only: report verifies the log and reads every skill grant."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

import report as report_mod
from capability_gate import Gate, load_policy


def _write_allowlist(path: Path, skills: dict) -> None:
    path.write_text(yaml.safe_dump({"skills": skills}), encoding="utf-8")


def test_report_refuses_truncated_log(tmp_path) -> None:
    log = tmp_path / "g.jsonl"
    g = Gate(
        load_policy({"skills": {"s": {"tools": ["read_file"], "paths": ["/**"]}}}),
        log_path=str(log),
    )
    for _ in range(3):
        g.evaluate("s", "write_file", ["/x"])
    lines = log.read_text(encoding="utf-8").splitlines(True)
    log.write_text("".join(lines[:1]), encoding="utf-8")
    with pytest.raises(ValueError, match="witness"):
        report_mod._load_jsonl(log)


def test_report_reads_unlabeled_grants(tmp_path) -> None:
    allow = tmp_path / "allowlist.yaml"
    _write_allowlist(
        allow,
        {
            "UNLABELED": {"tools": ["write_file", "read_file"], "paths": ["/**"]},
            "coder": {"tools": ["terminal"], "paths": ["/**"]},
        },
    )
    granted = report_mod._load_granted_tools(allow)
    assert granted == {"write_file", "read_file", "terminal"}


def test_star_only_allowlist_still_loads_star(tmp_path) -> None:
    allow = tmp_path / "allowlist.yaml"
    _write_allowlist(allow, {"*": {"tools": ["web_search"], "paths": ["/**"]}})
    assert report_mod._load_granted_tools(allow) == {"web_search"}


def test_forged_parent_rejected(tmp_path) -> None:
    log = tmp_path / "g.jsonl"
    g = Gate(
        load_policy({"skills": {"s": {"tools": ["read_file"], "paths": ["/**"]}}}),
        log_path=str(log),
    )
    g.evaluate("s", "write_file", ["/x"])
    g.evaluate("s", "write_file", ["/y"])
    lines = log.read_text(encoding="utf-8").splitlines(True)
    first = json.loads(lines[0])
    first["reason"] = "forged"
    lines[0] = json.dumps(first, sort_keys=True) + "\n"
    log.write_text("".join(lines), encoding="utf-8")
    with pytest.raises(ValueError, match="hash chain|witness"):
        report_mod._load_jsonl(log)
