"""E3 — unknown mode resolves to fail-closed block, never observe."""

from __future__ import annotations

import importlib.util
import os
import stat
import sys
from pathlib import Path

import pytest
import yaml

REASON_PREFIX = "mode_unresolved_fail_closed"


@pytest.fixture
def env_home(tmp_path, monkeypatch):
    home = tmp_path / "hermes"
    home.mkdir()
    (home / "logs").mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    root = Path(__file__).resolve().parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    return home


def _write_cfg(home: Path, body) -> None:
    path = home / "config.yaml"
    if isinstance(body, str):
        path.write_text(body, encoding="utf-8")
    else:
        path.write_text(yaml.safe_dump(body), encoding="utf-8")


def _cfg_with_mode(mode):
    return {
        "plugins": {
            "enabled": ["capability-gate"],
            "entries": {"capability-gate": {"mode": mode}},
        }
    }


def _load_adapter():
    init_path = Path(__file__).resolve().parent / "__init__.py"
    name = f"cg_e3_{id(init_path)}_{os.getpid()}"
    spec = importlib.util.spec_from_file_location(name, init_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _register_pre(mod):
    hooks = {}

    class Ctx:
        def register_hook(self, name, fn):
            hooks[name] = fn

    mod.register(Ctx())
    return hooks["pre_tool_call"]


def _deny_call(pre):
    return pre("read_file", {"path": "/etc/passwd"}, "e3-task")


def _assert_fail_closed(out, kind_substr: str | None = None):
    assert out is not None, "fail-open: returned None under unresolved mode"
    assert out.get("action") == "block", out
    msg = str(out.get("message", ""))
    assert REASON_PREFIX in msg, msg
    if kind_substr:
        assert kind_substr in msg, msg


# --- Family: each degradation must fail closed ---


def test_corrupt_config_blocks_with_fail_closed_reason(env_home):
    _write_cfg(env_home, "plugins: [[[[ not yaml")
    pre = _register_pre(_load_adapter())
    _assert_fail_closed(_deny_call(pre), "unparseable")


def test_missing_mode_key_blocks_with_fail_closed_reason(env_home):
    _write_cfg(
        env_home,
        {
            "plugins": {
                "enabled": ["capability-gate"],
                "entries": {"capability-gate": {}},
            }
        },
    )
    pre = _register_pre(_load_adapter())
    _assert_fail_closed(_deny_call(pre), "missing")


def test_empty_file_blocks_with_fail_closed_reason(env_home):
    _write_cfg(env_home, "")
    pre = _register_pre(_load_adapter())
    _assert_fail_closed(_deny_call(pre), "empty")


def test_invalid_mode_value_blocks_with_fail_closed_reason(env_home):
    _write_cfg(env_home, _cfg_with_mode("enforced"))
    pre = _register_pre(_load_adapter())
    _assert_fail_closed(_deny_call(pre), "invalid")


def test_wrong_type_mode_blocks_with_fail_closed_reason(env_home):
    _write_cfg(env_home, _cfg_with_mode(123))
    pre = _register_pre(_load_adapter())
    _assert_fail_closed(_deny_call(pre), "invalid")


def test_unreadable_file_blocks_with_fail_closed_reason(env_home):
    path = env_home / "config.yaml"
    _write_cfg(env_home, _cfg_with_mode("enforce"))
    path.chmod(0)
    try:
        pre = _register_pre(_load_adapter())
        _assert_fail_closed(_deny_call(pre), "unreadable")
    finally:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)


# --- Blast-radius: healthy paths ---


def test_valid_observe_still_returns_none_on_deny(env_home):
    _write_cfg(env_home, _cfg_with_mode("observe"))
    pre = _register_pre(_load_adapter())
    out = _deny_call(pre)
    assert out is None, out


def test_valid_enforce_still_blocks_on_deny(env_home):
    _write_cfg(env_home, _cfg_with_mode("enforce"))
    pre = _register_pre(_load_adapter())
    out = _deny_call(pre)
    assert out is not None and out.get("action") == "block", out
    assert REASON_PREFIX not in str(out.get("message", "")), out


def test_fail_closed_reason_distinct_from_policy_deny(env_home):
    """Unresolved block message must not look like a normal allowlist deny."""
    _write_cfg(env_home, _cfg_with_mode("enforced"))
    pre = _register_pre(_load_adapter())
    unresolved = _deny_call(pre)
    _write_cfg(env_home, _cfg_with_mode("enforce"))
    # re-register fresh adapter after fixing mode
    pre2 = _register_pre(_load_adapter())
    policy = _deny_call(pre2)
    assert REASON_PREFIX in str(unresolved.get("message", ""))
    assert REASON_PREFIX not in str(policy.get("message", ""))
    assert (
        "outside allowlist" in str(policy.get("message", "")).lower()
        or policy.get("action") == "block"
    )


def test_utf8_corrupt_blocks_with_fail_closed_reason(env_home):
    path = env_home / "config.yaml"
    path.write_bytes(b"plugins: \xff\xfe not utf8")
    pre = _register_pre(_load_adapter())
    _assert_fail_closed(_deny_call(pre), "unreadable")


def test_mid_call_flip_observe_to_enforce_does_not_passthrough(env_home, monkeypatch):
    """TOCTOU: resolve observe, flip to enforce before passthrough → must block."""
    _write_cfg(env_home, _cfg_with_mode("observe"))
    mod = _load_adapter()
    pre = _register_pre(mod)
    calls = {"n": 0}
    real = mod.resolve_capability_gate_mode

    def flipping_resolve(home=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return "observe", None
        return "enforce", None

    monkeypatch.setattr(mod, "resolve_capability_gate_mode", flipping_resolve)
    # Force second resolve on observe passthrough path by flipping file too
    out = _deny_call(pre)
    # Restore for cleanliness
    monkeypatch.setattr(mod, "resolve_capability_gate_mode", real)
    assert out is not None and out.get("action") == "block", out


def test_exception_path_reconfirms_mode_before_none(env_home, monkeypatch):
    """Except handler must not None-passthrough if mode flipped to enforce mid-call."""
    _write_cfg(env_home, _cfg_with_mode("observe"))
    mod = _load_adapter()
    pre = _register_pre(mod)
    n = {"c": 0}

    # Break evaluate after first mode resolve by replacing gate.evaluate
    # Access gate via closure is hard; instead make _extract_paths explode after mode set
    # by monkeypatching resolve: 1st observe, 2nd enforce (reconfirm in except or after boom)
    def boom_paths(tool_name, args):
        raise RuntimeError("forced evaluate boom")

    monkeypatch.setattr(mod, "_extract_paths", boom_paths)

    def flipping(home=None):
        n["c"] += 1
        if n["c"] == 1:
            return "observe", None
        return "enforce", None

    monkeypatch.setattr(mod, "resolve_capability_gate_mode", flipping)
    out = _deny_call(pre)
    assert out is not None and out.get("action") == "block", out
