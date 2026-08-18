"""E2 Fix2 — mode cannot freeze stale at register()."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

# These three tests drive the real hermes_cli config path. Without a Hermes
# install they raise ModuleNotFoundError rather than skipping, which turned a
# green suite red the moment this file shipped. This is the same guard
# test_adapter.py already uses for the same dependency, so the suite now
# behaves identically with or without Hermes present.
pytest.importorskip(
    "hermes_cli", reason="mode-staleness tests require a Hermes install"
)


@pytest.fixture
def cg_home(tmp_path, monkeypatch):
    home = tmp_path / "hermes"
    home.mkdir()
    (home / "logs").mkdir()
    cfg = {
        "plugins": {
            "enabled": ["capability-gate"],
            "entries": {"capability-gate": {"mode": "observe"}},
        }
    }
    (home / "config.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(home))
    root = Path(__file__).resolve().parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    return home


def _flip_mode(home: Path, mode: str) -> None:
    cfg_path = home / "config.yaml"
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    cfg["plugins"]["entries"]["capability-gate"]["mode"] = mode
    cfg_path.write_text(yaml.safe_dump(cfg), encoding="utf-8")


def test_flip_to_enforce_without_reregister_blocks_deny(cg_home, monkeypatch):
    """Exact E1 fail-open: flip observe→enforce mid-process; deny must block."""
    from hermes_cli import config as hcfg

    def _load():
        return yaml.safe_load((cg_home / "config.yaml").read_text(encoding="utf-8"))

    monkeypatch.setattr(hcfg, "load_config", _load)

    init_path = Path(__file__).resolve().parent / "__init__.py"
    spec = importlib.util.spec_from_file_location(
        "capability_gate_plugin_e2", init_path
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["capability_gate_plugin_e2"] = mod
    import capability_gate  # noqa: F401

    hooks = {}

    class Ctx:
        def register_hook(self, name, fn):
            hooks[name] = fn

    spec.loader.exec_module(mod)
    mod.register(Ctx())
    pre = hooks["pre_tool_call"]

    out = pre("read_file", {"path": "/etc/passwd"}, "task-1")
    assert out is None, out

    _flip_mode(cg_home, "enforce")

    out2 = pre("read_file", {"path": "/etc/passwd"}, "task-2")
    assert out2 is not None, (
        "fail-open: enforce reported but adapter returned None on deny"
    )
    assert out2.get("action") == "block", out2


def test_mode_flip_idempotent_twice(cg_home, monkeypatch):
    """Applying enforce flip twice still blocks (idempotent convergence)."""
    from hermes_cli import config as hcfg

    monkeypatch.setattr(
        hcfg,
        "load_config",
        lambda: yaml.safe_load((cg_home / "config.yaml").read_text(encoding="utf-8")),
    )
    init_path = Path(__file__).resolve().parent / "__init__.py"
    spec = importlib.util.spec_from_file_location(
        "capability_gate_plugin_e2b", init_path
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["capability_gate_plugin_e2b"] = mod
    hooks = {}

    class Ctx:
        def register_hook(self, name, fn):
            hooks[name] = fn

    spec.loader.exec_module(mod)
    mod.register(Ctx())
    pre = hooks["pre_tool_call"]
    _flip_mode(cg_home, "enforce")
    assert pre("read_file", {"path": "/etc/passwd"}, "t1")["action"] == "block"
    _flip_mode(cg_home, "enforce")
    assert pre("read_file", {"path": "/etc/passwd"}, "t2")["action"] == "block"


def test_closed_hook_re_reads_mode_on_flip(cg_home, monkeypatch):
    """Interrogate residual: _build_gate fails under observe; flip to enforce must block."""
    from hermes_cli import config as hcfg

    monkeypatch.setattr(
        hcfg,
        "load_config",
        lambda: yaml.safe_load((cg_home / "config.yaml").read_text(encoding="utf-8")),
    )
    init_path = Path(__file__).resolve().parent / "__init__.py"
    spec = importlib.util.spec_from_file_location(
        "capability_gate_plugin_e2_closed", init_path
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["capability_gate_plugin_e2_closed"] = mod

    hooks = {}

    class Ctx:
        def register_hook(self, name, fn):
            hooks[name] = fn

    spec.loader.exec_module(mod)
    monkeypatch.setattr(
        mod, "_build_gate", lambda mode: (_ for _ in ()).throw(RuntimeError("forced"))
    )
    mod.register(Ctx())
    pre = hooks["pre_tool_call"]
    assert pre("read_file", {"path": "/etc/passwd"}, "t0") is None
    _flip_mode(cg_home, "enforce")
    out = pre("read_file", {"path": "/etc/passwd"}, "t1")
    assert out is not None, "fail-open: _closed froze observe across enforce flip"
    assert out.get("action") == "block", out
