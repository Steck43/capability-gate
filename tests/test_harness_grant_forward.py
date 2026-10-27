"""Harness grant, session, and approval forwarding from host-owned files."""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path

import pytest

import capability_gate as cg
import capability_gate_grants as gr
from adapters.grant_forward import (
    GrantForwardError,
    load_call_kwargs,
    load_grant_config,
)
from capability_gate import Gate, Verdict, load_policy

KEY = b"k" * 32
APPROVAL_KEY = b"a" * 32
SESSION = "session-key-agent-one-0001"


@pytest.fixture
def layout(tmp_path):
    work = tmp_path / "work"
    (work / "a").mkdir(parents=True)
    (work / "a" / "x.txt").write_text("marker\n")
    state = tmp_path / "state"
    state.mkdir()
    key_file = state / "grant.key"
    key_file.write_bytes(KEY)
    appr_file = state / "approval.key"
    appr_file.write_bytes(APPROVAL_KEY)
    cfg_path = state / "grants.json"
    cfg_path.write_text(
        json.dumps(
            {
                "audience": "harness-1",
                "key_file": str(key_file),
                "approval_key_file": str(appr_file),
                "store_path": str(state / "grants-store.json"),
                "ledger_path": str(state / "ledger.json"),
                "approval_nonce_path": None,
                "approvers": ["human:landen"],
            }
        )
    )
    policy = load_policy(
        {
            "skills": {
                "UNLABELED": {
                    "tools": ["read_file"],
                    "paths": [str(work) + "/**"],
                }
            }
        }
    )
    cfg = load_grant_config(str(cfg_path))
    assert cfg is not None
    gate = Gate(policy, str(tmp_path / "log.jsonl"), cg.ENFORCE, grants=cfg)
    ticket = gr.issue(
        cfg,
        principal_id="agent:one",
        skill="UNLABELED",
        tools=("read_file",),
        paths=(str(work) + "/**",),
        session_key=SESSION,
        ttl=600,
    )
    sess = state / "session.json"
    sess.write_text(
        json.dumps(
            {
                "principal_id": "agent:one",
                "grant": ticket,
                "session_key": SESSION,
            }
        )
    )
    return {
        "work": work,
        "cfg_path": cfg_path,
        "sess_path": sess,
        "gate": gate,
        "cfg": cfg,
        "ticket": ticket,
        "target": work / "a" / "x.txt",
    }


def test_host_session_allows_and_model_kwargs_ignored(layout):
    kw = load_call_kwargs(str(layout["sess_path"]))
    d = layout["gate"].evaluate(
        "UNLABELED",
        "read_file",
        [str(layout["target"])],
        args={"path": str(layout["target"])},
        **kw,
    )
    assert d.verdict is Verdict.ALLOW
    # Model-shaped call without host session still DENY on grants Gate.
    d2 = layout["gate"].evaluate(
        "UNLABELED",
        "read_file",
        [str(layout["target"])],
        args={"path": str(layout["target"])},
    )
    assert d2.verdict is Verdict.DENY and "principal" in d2.reason.lower()


def test_hermes_evaluate_calls_forward_kwargs():
    src = (Path(__file__).resolve().parent.parent / "__init__.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(src)
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "pre_tool_call":
            for n in ast.walk(node):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                    if n.func.attr == "evaluate":
                        text = ast.get_source_segment(src, n) or ""
                        hits.append(
                            "_grant_evaluate_kwargs" in text
                            or any(
                                isinstance(k.value, ast.Call)
                                and getattr(getattr(k.value, "func", None), "id", None)
                                == "_grant_evaluate_kwargs"
                                for k in n.keywords
                                if k.arg is None
                            )
                        )
    assert hits and all(hits), hits


def test_cc_pre_uses_grant_kwargs_star():
    src = (
        Path(__file__).resolve().parent.parent / "adapters" / "claude_code_hook.py"
    ).read_text(encoding="utf-8")
    assert "grant_kwargs" in src
    assert "CG_CC_GRANT_CONFIG" in src and "CG_CC_GRANT_SESSION" in src
    assert "load_grant_config" in src


def test_build_gate_passes_grants_kw():
    src = (Path(__file__).resolve().parent.parent / "__init__.py").read_text(
        encoding="utf-8"
    )
    assert "grants=grants" in src
    assert "load_grant_config" in src


def test_missing_session_file_is_legacy_empty_kwargs(tmp_path):
    assert load_call_kwargs(str(tmp_path / "nope.json")) == {}


def test_partial_session_fail_closed(tmp_path):
    p = tmp_path / "sess.json"
    p.write_text(json.dumps({"principal_id": "agent:one"}))
    with pytest.raises(GrantForwardError, match="together"):
        load_call_kwargs(str(p))


def test_malformed_grants_json_is_grant_forward_error(tmp_path):
    p = tmp_path / "grants.json"
    p.write_text("{broken")
    with pytest.raises(GrantForwardError, match="unreadable"):
        load_grant_config(str(p))


def test_bad_utf8_grants_is_grant_forward_error(tmp_path):
    p = tmp_path / "grants.json"
    p.write_bytes(b"\xff\xfe{")
    with pytest.raises(GrantForwardError, match="unreadable"):
        load_grant_config(str(p))


def test_directory_grants_is_grant_forward_error(tmp_path):
    p = tmp_path / "grants.json"
    p.mkdir()
    with pytest.raises(GrantForwardError, match="unreadable"):
        load_grant_config(str(p))


def test_key_file_directory_is_grant_forward_error(tmp_path):
    keydir = tmp_path / "keydir"
    keydir.mkdir()
    p = tmp_path / "grants.json"
    p.write_text(
        json.dumps(
            {
                "audience": "h1",
                "key_file": str(keydir),
                "store_path": str(tmp_path / "store.json"),
                "ledger_path": str(tmp_path / "ledger.json"),
            }
        )
    )
    with pytest.raises(GrantForwardError, match="unreadable|symlink|missing"):
        load_grant_config(str(p))


def test_malformed_session_is_grant_forward_error(tmp_path):
    p = tmp_path / "session.json"
    p.write_text("{broken")
    with pytest.raises(GrantForwardError, match="unreadable"):
        load_call_kwargs(str(p))


def test_hermes_build_gate_malformed_grants_fail_closed(tmp_path, monkeypatch):
    from grind01_util import load_adapter

    home = tmp_path / "hermes"
    (home / "logs").mkdir(parents=True)
    base = home / "capability-gate"
    base.mkdir()
    (base / "grants.json").write_text("{broken")
    monkeypatch.setenv("HERMES_HOME", str(home))
    mod = load_adapter("rtb_w1")
    work = tmp_path / "work"
    work.mkdir()
    policy = load_policy(
        {
            "skills": {
                "UNLABELED": {"tools": ["read_file"], "paths": [str(work) + "/**"]}
            }
        }
    )
    monkeypatch.setattr(mod, "_load_allowlist", lambda _p: policy)
    with pytest.raises(RuntimeError, match="grant config refused"):
        mod._build_gate("enforce")


def test_hermes_session_malformed_fail_closed(tmp_path, monkeypatch):
    from grind01_util import load_adapter

    home = tmp_path / "hermes"
    (home / "logs").mkdir(parents=True)
    base = home / "capability-gate"
    base.mkdir()
    (base / "session.json").write_text("{broken")
    monkeypatch.setenv("HERMES_HOME", str(home))
    mod = load_adapter("rtb_w1_sess")
    with pytest.raises(RuntimeError, match="grant session refused"):
        mod._grant_evaluate_kwargs()


def test_hermes_build_gate_bad_utf8_and_dir_fail_closed(tmp_path, monkeypatch):
    from grind01_util import load_adapter

    home = tmp_path / "hermes"
    (home / "logs").mkdir(parents=True)
    base = home / "capability-gate"
    base.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    mod = load_adapter("rtb_w1_sib")
    work = tmp_path / "work"
    work.mkdir()
    policy = load_policy(
        {
            "skills": {
                "UNLABELED": {"tools": ["read_file"], "paths": [str(work) + "/**"]}
            }
        }
    )
    monkeypatch.setattr(mod, "_load_allowlist", lambda _p: policy)
    (base / "grants.json").write_bytes(b"\xff\xfe{")
    with pytest.raises(RuntimeError, match="grant config refused"):
        mod._build_gate("enforce")
    (base / "grants.json").unlink()
    (base / "grants.json").mkdir()
    with pytest.raises(RuntimeError, match="grant config refused"):
        mod._build_gate("enforce")


def test_hermes_pre_tool_call_malformed_grants_blocks(tmp_path, monkeypatch):
    from grind01_util import load_adapter, write_config

    home = tmp_path / "hermes"
    (home / "logs").mkdir(parents=True)
    base = home / "capability-gate"
    base.mkdir()
    (base / "grants.json").write_text("{broken")
    write_config(home)
    monkeypatch.setenv("HERMES_HOME", str(home))
    mod = load_adapter("rtb_w1_pre")
    work = tmp_path / "work"
    (work / "a").mkdir(parents=True)
    tgt = work / "a" / "x.txt"
    tgt.write_text("marker\n")
    policy = load_policy(
        {
            "skills": {
                "UNLABELED": {"tools": ["read_file"], "paths": [str(work) + "/**"]}
            }
        }
    )
    monkeypatch.setattr(mod, "_load_allowlist", lambda _p: policy)
    hooks = {}

    class Ctx:
        def register_hook(self, name, fn):
            hooks[name] = fn

        def __getattr__(self, _n):
            return lambda *a, **k: None

    mod.register(Ctx())
    out = hooks["pre_tool_call"](
        tool_name="read_file", args={"path": str(tgt)}, task_id="t1"
    )
    assert isinstance(out, dict) and out.get("action") == "block", out


def test_gf_l1_hermes_gate_dir_missing_grants_fail_closed(tmp_path, monkeypatch):
    """capability-gate/ present without grants.json must refuse (GF-L1)."""
    from grind01_util import load_adapter

    home = tmp_path / "hermes"
    (home / "logs").mkdir(parents=True)
    (home / "capability-gate").mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    mod = load_adapter("rtb_w1_legacy")
    work = tmp_path / "work"
    work.mkdir()
    policy = load_policy(
        {
            "skills": {
                "UNLABELED": {"tools": ["read_file"], "paths": [str(work) + "/**"]}
            }
        }
    )
    monkeypatch.setattr(mod, "_load_allowlist", lambda _p: policy)
    with pytest.raises(RuntimeError, match="grant config refused"):
        mod._build_gate("enforce")


def test_hermes_never_configured_stays_legacy(tmp_path, monkeypatch):
    """No capability-gate/ dir → legacy grants=None (never opted in)."""
    from grind01_util import load_adapter

    home = tmp_path / "hermes"
    (home / "logs").mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(home))
    mod = load_adapter("rtb_w1_never")
    work = tmp_path / "work"
    work.mkdir()
    policy = load_policy(
        {
            "skills": {
                "UNLABELED": {"tools": ["read_file"], "paths": [str(work) + "/**"]}
            }
        }
    )
    monkeypatch.setattr(mod, "_load_allowlist", lambda _p: policy)
    g = mod._build_gate("enforce")
    assert g._grants is None


def test_gf_l1_missing_config_required_refuses(tmp_path):
    missing = tmp_path / "gone-grants.json"
    with pytest.raises(GrantForwardError, match="missing grant file"):
        load_grant_config(str(missing), required=True)
    assert load_grant_config(str(missing), required=False) is None


def test_gf_l1_missing_session_required_refuses(tmp_path):
    missing = tmp_path / "gone-session.json"
    with pytest.raises(GrantForwardError, match="missing session file"):
        load_call_kwargs(str(missing), required=True)
    assert load_call_kwargs(str(missing), required=False) == {}


def test_gf_l1_cc_env_set_missing_file_denies(tmp_path, monkeypatch):
    """CG_CC_GRANT_CONFIG set but file gone must deny (not legacy allow)."""
    import json
    import subprocess
    import sys

    import yaml

    work = tmp_path / "work"
    work.mkdir()
    tgt = work / "x.txt"
    tgt.write_text("marker\n", encoding="utf-8")
    allow = tmp_path / "allow.yaml"
    allow.write_text(
        yaml.safe_dump(
            {
                "skills": {
                    "UNLABELED": {
                        "tools": ["Read"],
                        "paths": [str(work) + "/**"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    missing = tmp_path / "no-such-grants.json"
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "cwd": str(work),
        "tool_input": {"file_path": str(tgt)},
    }
    env = dict(
        os.environ,
        CG_CC_GRANT_CONFIG=str(missing),
        CG_CC_ALLOWLIST=str(allow),
        CG_CC_LOG=str(tmp_path / "cc.jsonl"),
    )
    env.pop("CG_CC_GRANT_SESSION", None)
    r = subprocess.run(
        [sys.executable, str(Path("adapters/claude_code_hook.py").resolve())],
        input=json.dumps(event),
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        cwd=str(Path.cwd()),
        check=False,
    )
    out = (r.stdout + r.stderr).lower()
    assert r.returncode == 2 or "deny" in out, (r.returncode, r.stdout, r.stderr)
