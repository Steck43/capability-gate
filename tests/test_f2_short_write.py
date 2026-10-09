"""F-2: a short audit-log write fails closed instead of allowing with a torn record."""

from __future__ import annotations

import os

import pytest
from capability_gate import Gate, load_policy


def test_short_write_raises(tmp_path, monkeypatch) -> None:
    log = tmp_path / "g.jsonl"
    g = Gate(
        load_policy({"skills": {"s": {"tools": ["read_file"], "paths": ["/**"]}}}),
        log_path=str(log),
    )

    real_write = os.write

    def short(fd, data):
        if len(data) > 1:
            return real_write(fd, data[: max(1, len(data) // 2)])
        return real_write(fd, data)

    monkeypatch.setattr(os, "write", short)
    with pytest.raises(OSError, match="short audit log write"):
        g.evaluate("s", "write_file", ["/x"])
