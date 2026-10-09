"""H1-1: observe must still record a decision when summarize/log would throw."""

from __future__ import annotations

import json

import capability_gate as cg
from capability_gate import OBSERVE, Gate, Verdict, load_policy


def test_lone_surrogate_in_args_is_logged_in_observe(tmp_path) -> None:
    log = tmp_path / "d.jsonl"
    g = Gate(
        load_policy({"skills": {"s": {"tools": ["write_file"], "paths": ["/**"]}}}),
        log_path=str(log),
        mode=OBSERVE,
    )
    # Lone surrogate used to raise in summarize_args.encode before the try,
    # so evaluate never logged and the adapter fail-opened.
    d = g.evaluate(
        "s",
        "write_file",
        ["/tmp/x"],
        args={"path": "/tmp/x", "content": "\ud800"},
    )
    assert d.verdict in (Verdict.ALLOW, Verdict.DENY)
    assert log.exists()
    assert len(log.read_text(encoding="utf-8").splitlines()) >= 1


def test_summarize_boom_still_logs_deny(tmp_path, monkeypatch) -> None:
    def boom(args):
        raise RuntimeError("summarize broke")

    monkeypatch.setattr(cg, "summarize_args", boom)
    log = tmp_path / "d.jsonl"
    g = Gate(
        load_policy({"skills": {"s": {"tools": ["read_file"], "paths": ["/**"]}}}),
        log_path=str(log),
        mode=OBSERVE,
    )
    d = g.evaluate("s", "read_file", ["/tmp/x"], args={"path": "/tmp/x"})
    assert d.verdict is Verdict.DENY
    assert d.enforced is False
    rec = json.loads(log.read_text(encoding="utf-8").splitlines()[-1])
    assert rec["verdict"] == "deny"
    assert "failing closed" in rec["reason"]
