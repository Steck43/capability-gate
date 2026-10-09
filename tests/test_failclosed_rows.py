"""Fail-closed denials that never reach evaluate() still land in the log.

2026-09-28 incident: nine days of fail-closed denials, 0 rows. Witness update
is required (#32 path already covers chain integrity for evaluate rows).
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest
import yaml


@pytest.fixture
def env_home(tmp_path, monkeypatch):
    home = tmp_path / "hermes"
    (home / "logs").mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(home))
    root = Path(__file__).resolve().parent.parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    return home


def _cfg(home: Path, mode) -> None:
    body = {
        "plugins": {
            "enabled": ["capability-gate"],
            "entries": {"capability-gate": {"mode": mode}},
        }
    }
    (home / "config.yaml").write_text(yaml.safe_dump(body), encoding="utf-8")


def _load():
    init_path = Path(__file__).resolve().parent.parent / "__init__.py"
    name = f"cg_rows_{os.getpid()}_{id(init_path)}"
    spec = importlib.util.spec_from_file_location(name, init_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _use_example_allowlist(mod, monkeypatch) -> None:
    example = Path(mod._HERE) / "allowlist.example.yaml"

    def build(mode: str):
        policy = mod.load_policy(yaml.safe_load(example.read_text(encoding="utf-8")))
        log_path = os.path.join(mod._hermes_home(), "logs", "capability-gate.jsonl")
        return mod.Gate(policy, log_path=log_path, mode=mode)

    monkeypatch.setattr(mod, "_build_gate", build)


def _hook(mod):
    hooks = {}

    class Ctx:
        def register_hook(self, name, fn):
            hooks[name] = fn

    mod.register(Ctx())
    return hooks["pre_tool_call"]


def _rows(home: Path):
    p = home / "logs" / "capability-gate.jsonl"
    if not p.exists():
        return []
    return [
        json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()
    ]


def _witness(home: Path) -> dict:
    p = home / "logs" / "capability-gate.jsonl.witness"
    return json.loads(p.read_text(encoding="utf-8"))


KW = {"session_id": "s-1", "turn_id": "t-1", "tool_call_id": "c-1"}


def test_pre_evaluate_exception_blocks_and_updates_witness(env_home, monkeypatch):
    """Gate.evaluate never runs; the outer fail-closed still writes a row."""
    _cfg(env_home, "enforce")
    mod = _load()
    _use_example_allowlist(mod, monkeypatch)
    hook = _hook(mod)

    def boom(*_a, **_k):
        raise RuntimeError("forced pre-evaluate")

    monkeypatch.setattr(mod.Gate, "evaluate", boom)
    out = hook("terminal", {"command": "ls"}, "task-1", **KW)
    assert out and out["action"] == "block"
    rows = _rows(env_home)
    assert len(rows) == 1
    r = rows[0]
    assert r["verdict"] == "deny" and r["enforced"] is True
    assert "failing closed" in r["reason"] and "forced pre-evaluate" in r["reason"]
    assert r["session_id"] == "s-1" and r["task_id"] == "task-1"
    w = _witness(env_home)
    assert w["count"] == 1 and len(w["head"]) == 64


def test_observe_pre_evaluate_exception_blocks_and_updates_witness(
    env_home, monkeypatch
):
    """H1-1: observe also blocks an unrecorded exception, and still logs it."""
    _cfg(env_home, "observe")
    mod = _load()
    _use_example_allowlist(mod, monkeypatch)
    hook = _hook(mod)

    def boom(*_a, **_k):
        raise RuntimeError("forced observe")

    monkeypatch.setattr(mod.Gate, "evaluate", boom)
    out = hook("terminal", {"command": "ls"}, "task-2", **KW)
    assert out and out["action"] == "block"
    rows = _rows(env_home)
    assert len(rows) == 1
    assert rows[0]["verdict"] == "deny" and "forced observe" in rows[0]["reason"]
    w = _witness(env_home)
    assert w["count"] == 1


def test_unresolved_mode_blocks_and_updates_witness(env_home):
    _cfg(env_home, "enforce")
    mod = _load()
    hook = _hook(mod)
    (env_home / "config.yaml").write_text("", encoding="utf-8")
    out = hook("terminal", {"command": "ls"}, "task-3", **KW)
    assert out and out["action"] == "block"
    rows = _rows(env_home)
    assert len(rows) == 1
    assert rows[0]["reason"].startswith("mode_unresolved_fail_closed")
    assert _witness(env_home)["count"] == 1


def test_failed_load_closed_hook_writes_row_and_witness(env_home, monkeypatch):
    _cfg(env_home, "enforce")
    mod = _load()
    monkeypatch.setattr(
        mod, "_build_gate", lambda mode: (_ for _ in ()).throw(OSError("no allowlist"))
    )
    hook = _hook(mod)
    out = hook("read_file", {"path": "/x"}, "task-4", **KW)
    assert out and out["action"] == "block"
    rows = _rows(env_home)
    assert len(rows) == 1 and "failed to load" in rows[0]["reason"]
    assert _witness(env_home)["count"] == 1


def test_failed_load_observe_passes_and_writes_row(env_home, monkeypatch):
    _cfg(env_home, "observe")
    mod = _load()
    monkeypatch.setattr(
        mod, "_build_gate", lambda mode: (_ for _ in ()).throw(OSError("no allowlist"))
    )
    hook = _hook(mod)
    assert hook("read_file", {"path": "/x"}, "task-5", **KW) is None
    rows = _rows(env_home)
    assert len(rows) == 1 and rows[0]["enforced"] is False
    assert _witness(env_home)["count"] == 1


def test_logging_failure_never_unblocks(env_home, monkeypatch):
    _cfg(env_home, "enforce")
    mod = _load()
    _use_example_allowlist(mod, monkeypatch)
    hook = _hook(mod)

    def boom(*_a, **_k):
        raise RuntimeError("forced")

    monkeypatch.setattr(mod.Gate, "evaluate", boom)
    monkeypatch.setattr(
        mod,
        "record_decision",
        lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")),
    )
    out = hook("terminal", {"command": "ls"}, "task-6", **KW)
    assert out and out["action"] == "block"


def test_healthy_allow_writes_exactly_one_row(env_home, monkeypatch):
    _cfg(env_home, "enforce")
    mod = _load()
    _use_example_allowlist(mod, monkeypatch)
    hook = _hook(mod)
    home = str(env_home)
    # example allowlist grants * read under notes; create an in-grant file.
    notes = env_home / "notes"
    notes.mkdir(exist_ok=True)
    target = notes / "a.md"
    target.write_text("x", encoding="utf-8")
    out = hook("read_file", {"path": str(target)}, "task-ok", **KW)
    # may allow or deny depending on example grants; either way one row only
    _ = out
    assert len(_rows(env_home)) == 1
    assert _witness(env_home)["count"] == 1
