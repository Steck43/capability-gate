"""Smoke tests for the Hermes adapter translation layer (no Hermes runtime)."""

import importlib.util
import os
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

PLUGIN_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(PLUGIN_DIR))


def _load_adapter():
    cg_spec = importlib.util.spec_from_file_location(
        "capability_gate", PLUGIN_DIR / "capability_gate.py"
    )
    cg = importlib.util.module_from_spec(cg_spec)
    sys.modules["capability_gate"] = cg
    cg_spec.loader.exec_module(cg)

    src = (PLUGIN_DIR / "__init__.py").read_text(encoding="utf-8")
    src = src.replace("from .capability_gate import", "from capability_gate import")
    mod = types.ModuleType("adapter_under_test")
    mod.__file__ = str(PLUGIN_DIR / "__init__.py")
    exec(compile(src, str(PLUGIN_DIR / "__init__.py"), "exec"), mod.__dict__)
    return mod, cg


@pytest.fixture()
def adapter():
    mod, _cg = _load_adapter()
    mod._test_mode = "observe"
    return mod


@pytest.fixture()
def register_hook(adapter, tmp_path, monkeypatch):
    home = tmp_path / "hermes"
    (home / "notes").mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(home))

    allowlist = {
        "version": 1,
        "require_approval": ["terminal"],
        "skills": {
            "UNLABELED": {
                "tools": ["read_file", "write_file", "terminal"],
                "paths": [f"{home}/notes/**"],
            }
        },
    }

    def safe_load(src):
        text = src if isinstance(src, str) else src.read()
        if isinstance(text, str) and "capability-gate:" in text:
            return yaml.safe_load(text)
        return allowlist

    yaml_mod = types.ModuleType("yaml")
    yaml_mod.safe_load = safe_load
    monkeypatch.setitem(sys.modules, "yaml", yaml_mod)
    adapter.__dict__["yaml"] = yaml_mod

    def _build(mode):
        (home / "logs").mkdir(exist_ok=True)
        policy = adapter.load_policy(allowlist)
        log_path = str(home / "logs" / "capability-gate.jsonl")
        return adapter.Gate(policy, log_path=log_path, mode=mode)

    monkeypatch.setattr(adapter, "_build_gate", _build)

    def _register(mode="observe"):
        adapter._test_mode = mode
        (home / "config.yaml").write_text(
            "plugins:\n  entries:\n    capability-gate:\n      mode: " + mode + "\n",
            encoding="utf-8",
        )
        ctx = MagicMock()
        adapter.register(ctx)
        return ctx.register_hook.call_args[0][1]

    return _register


def test_allow_returns_none(register_hook):
    hook_fn = register_hook("enforce")
    home = os.environ["HERMES_HOME"]
    assert hook_fn("read_file", {"path": f"{home}/notes/a.md"}, "t1") is None


def test_deny_enforce_blocks(register_hook):
    hook_fn = register_hook("enforce")
    out = hook_fn("read_file", {"path": "/etc/passwd"}, "t2")
    assert out["action"] == "block"
    assert "outside allowlist" in out["message"]


def test_deny_observe_returns_none(register_hook):
    hook_fn = register_hook("observe")
    assert hook_fn("read_file", {"path": "/etc/passwd"}, "t3") is None


def test_ask_enforce_blocks(register_hook):
    hook_fn = register_hook("enforce")
    out = hook_fn("terminal", {"command": "echo hi"}, "t4")
    assert out["action"] == "block"
    assert "Stage 3 not yet wired" in out["message"]


def test_exception_enforce_blocks(register_hook, adapter, monkeypatch):
    hook_fn = register_hook("enforce")
    home = os.environ["HERMES_HOME"]

    def boom(*_a, **_k):
        raise RuntimeError("adapter fault")

    monkeypatch.setattr(adapter.Gate, "evaluate", boom)
    out = hook_fn("read_file", {"path": f"{home}/notes/x.md"}, "t5")
    assert out["action"] == "block"
    assert "failing closed" in out["message"]


def test_exception_observe_blocks(register_hook, adapter, monkeypatch):
    hook_fn = register_hook("observe")

    def boom(*_a, **_k):
        raise RuntimeError("adapter fault")

    monkeypatch.setattr(adapter.Gate, "evaluate", boom)
    out = hook_fn("read_file", {"path": "/x"}, "t6")
    assert out["action"] == "block"
    assert "failing closed" in out["message"]
