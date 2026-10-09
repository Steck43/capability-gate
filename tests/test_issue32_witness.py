"""Issue #32: truncation and log deletion fail closed via head witness."""

from __future__ import annotations

import os
import tempfile

import capability_gate as cg
import pytest


def _mk(dirpath: str) -> cg.Gate:
    pol = cg.load_policy(
        {"skills": {"s": {"tools": ["read_file"], "paths": [dirpath + "/**"]}}}
    )
    return cg.Gate(pol, os.path.join(dirpath, "g.jsonl"))


def test_untouched_log_passes() -> None:
    d = tempfile.mkdtemp()
    g = _mk(d)
    log = os.path.join(d, "g.jsonl")
    for _ in range(4):
        g.evaluate("s", "write_file", [d + "/x"])
    assert len(open(log, encoding="utf-8").read().splitlines()) == 4
    head = cg.verify_hash_chain(log)
    assert len(head) == 64
    assert head != "0" * 64


def test_dropping_trailing_lines_fails() -> None:
    d = tempfile.mkdtemp()
    g = _mk(d)
    log = os.path.join(d, "g.jsonl")
    for _ in range(4):
        g.evaluate("s", "write_file", [d + "/x"])
    lines = open(log, encoding="utf-8").read().splitlines(True)
    assert len(lines) == 4
    open(log, "w", encoding="utf-8").writelines(lines[:2])
    with pytest.raises(ValueError, match="witness"):
        cg.verify_hash_chain(log)


def test_deleting_whole_log_fails() -> None:
    d = tempfile.mkdtemp()
    g = _mk(d)
    log = os.path.join(d, "g.jsonl")
    g.evaluate("s", "write_file", [d + "/x"])
    os.remove(log)
    with pytest.raises(ValueError, match="missing but witness"):
        cg.verify_hash_chain(log)
    with pytest.raises(ValueError, match="missing but witness"):
        g.evaluate("s", "write_file", [d + "/x"])
