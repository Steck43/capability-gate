"""Shared fixtures for the grind01 tests: drive the registered pre_tool_call hook.

The tests here go through the hook Hermes calls, not through Gate.evaluate, so
a fix that lives only in the adapter is exercised the way a live call meets it.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import yaml

ROOF = Path(__file__).resolve().parents[1]
if str(ROOF) not in sys.path:
    sys.path.insert(0, str(ROOF))

from capability_gate import ENFORCE, Gate, load_policy  # noqa: E402


def load_adapter(tag: str):
    if "capability_gate" not in sys.modules:
        cg_spec = importlib.util.spec_from_file_location(
            "capability_gate", ROOF / "capability_gate.py"
        )
        cg = importlib.util.module_from_spec(cg_spec)
        sys.modules["capability_gate"] = cg
        cg_spec.loader.exec_module(cg)
    name = f"cg_grind01_{tag}_{os.getpid()}"
    spec = importlib.util.spec_from_file_location(name, ROOF / "__init__.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def write_config(home: Path, mode: str = "enforce") -> Path:
    cfg = home / "config.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "plugins": {
                    "enabled": ["capability-gate"],
                    "entries": {"capability-gate": {"mode": mode}},
                }
            }
        ),
        encoding="utf-8",
    )
    return cfg


def hermes_home(tmp_path: Path, monkeypatch, mode: str = "enforce") -> Path:
    home = tmp_path / "hermes"
    (home / "logs").mkdir(parents=True)
    write_config(home, mode)
    monkeypatch.setenv("HERMES_HOME", str(home))
    return home


def register(adapter, home: Path, skills: dict, require_approval=()):
    """Register the real hook with a test policy in place of allowlist.yaml."""
    policy = load_policy({"skills": skills, "require_approval": list(require_approval)})

    def _build_gate(mode: str) -> Gate:
        return Gate(policy, log_path=str(home / "logs" / "gate.jsonl"), mode=ENFORCE)

    adapter._build_gate = _build_gate
    hooks = {}

    class Ctx:
        def register_hook(self, name, fn):
            hooks[name] = fn

    adapter.register(Ctx())
    return hooks["pre_tool_call"]


def blocked(out) -> bool:
    return isinstance(out, dict) and out.get("action") == "block"
