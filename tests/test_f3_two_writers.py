"""F-3: two writers must not fork the hash chain."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import capability_gate as cg
from capability_gate import Gate, load_policy


def _gate(log: Path) -> Gate:
    return Gate(
        load_policy({"skills": {"s": {"tools": ["read_file"], "paths": ["/**"]}}}),
        log_path=str(log),
    )


def test_threaded_writers_keep_one_chain(tmp_path) -> None:
    log = tmp_path / "g.jsonl"
    g = _gate(log)

    def once(_i: int) -> None:
        g.evaluate("s", "write_file", [str(tmp_path / "x")])

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(once, range(40)))

    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 40
    head = cg.verify_hash_chain(str(log))
    assert len(head) == 64
    witness = cg._read_witness(cg._witness_path(str(log)))
    assert witness["count"] == 40
    assert witness["head"] == head


def test_lock_file_created(tmp_path) -> None:
    log = tmp_path / "g.jsonl"
    g = _gate(log)
    g.evaluate("s", "write_file", [str(tmp_path / "x")])
    assert (tmp_path / "g.jsonl.lock").is_file()
