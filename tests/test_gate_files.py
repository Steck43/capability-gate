"""The gate's own files: read only when they are what they claim, never written.

Before this, ``config.yaml`` and the allowlist were read through symlinks and
loaded whatever their owner or mode. If ``config.yaml`` was a link to a file
inside a write grant, a granted write to that file could flip the gate to
observe, and later off-grant writes went through (G-2, config half). Now:

- config and allowlist are opened without following a symlink, must be regular
  files owned by the current user, and must not be writable by group or others;
- a write tool aimed at the gate's config, allowlist, decision log or plugin
  folder is denied whatever the grant says.

Not covered here, named in the README: a hardlink to the config (same inode,
no link to see), a symlink in a parent folder, and the Windows owner and ACL
check.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import types
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

from grind01_util import (  # noqa: E402
    ROOF,
    blocked,
    hermes_home,
    load_adapter,
    register,
    write_config,
)

POSIX = os.name != "nt"
needs_posix = pytest.mark.skipif(not POSIX, reason="owner and mode bits are POSIX")


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _link_or_skip(target: Path, link: Path) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"OS refused the symlink: {exc}")


@pytest.fixture
def env(tmp_path, monkeypatch):
    home = hermes_home(tmp_path, monkeypatch)
    grant = (tmp_path / "grant").resolve()
    grant.mkdir()
    adapter = load_adapter("p3")
    return types.SimpleNamespace(tmp=tmp_path, home=home, grant=grant, adapter=adapter)


def _pre(env, roots):
    skills = {
        "UNLABELED": {
            "tools": ["read_file", "write_file", "patch"],
            "paths": [str(Path(r).resolve() / "**") for r in roots],
        }
    }
    return register(env.adapter, env.home, skills)


def _write_like_the_tool(pre, path: Path, content: str) -> object:
    """Ask the hook; perform the write only if it allows, as Hermes would."""
    out = pre("write_file", {"path": str(path), "content": content}, "p3")
    if out is None:
        path.write_text(content, encoding="utf-8")
    return out


# --- G-2, config half -------------------------------------------------------


def test_linked_config_into_a_grant_cannot_flip_the_gate(env) -> None:
    real = env.grant / "gate-config.yaml"
    write_config(env.grant, "enforce").rename(real)
    (env.home / "config.yaml").unlink()
    _link_or_skip(real, env.home / "config.yaml")
    before = _sha(real)
    pre = _pre(env, [env.grant])
    flip = yaml.safe_dump(
        {"plugins": {"entries": {"capability-gate": {"mode": "observe"}}}}
    )
    assert blocked(_write_like_the_tool(pre, real, flip))
    assert _sha(real) == before
    mode, unresolved = env.adapter.resolve_capability_gate_mode()
    assert mode == "enforce"
    assert unresolved and "untrusted" in unresolved
    # Still enforcing: an off-grant write is blocked too.
    assert blocked(_write_like_the_tool(pre, env.tmp / "off.txt", "x"))


def test_write_to_real_config_inside_a_grant_denied(env) -> None:
    cfg = env.home / "config.yaml"
    before = _sha(cfg)
    pre = _pre(env, [env.home])
    out = _write_like_the_tool(pre, cfg, "plugins: {}\n")
    assert blocked(out)
    assert "own" in out["message"]
    assert _sha(cfg) == before
    assert env.adapter.resolve_capability_gate_mode() == ("enforce", None)
    # In-grant work that is not a gate file still runs.
    assert pre("read_file", {"path": str(env.home / "notes.md")}, "p3") is None


def test_write_to_decision_log_denied(env) -> None:
    pre = _pre(env, [env.home])
    log = env.home / "logs" / "capability-gate.jsonl"
    assert blocked(pre("write_file", {"path": str(log), "content": ""}, "p3"))


def test_patch_header_into_plugin_folder_denied(env) -> None:
    pre = _pre(env, [ROOF])
    body = f"*** Begin Patch\n*** Update File: {ROOF / 'allowlist.example.yaml'}\n+x\n*** End Patch"
    assert blocked(pre("patch", {"mode": "patch", "patch": body}, "p3"))


# --- how the files are opened ----------------------------------------------


@needs_posix
@pytest.mark.parametrize("mode", [0o664, 0o666])
def test_group_or_world_writable_config_refused(env, mode) -> None:
    os.chmod(env.home / "config.yaml", mode)
    got, unresolved = env.adapter.resolve_capability_gate_mode()
    assert got == "enforce" and unresolved and "untrusted" in unresolved


@needs_posix
def test_config_0644_still_loads(env) -> None:
    os.chmod(env.home / "config.yaml", 0o644)
    assert env.adapter.resolve_capability_gate_mode() == ("enforce", None)


@needs_posix
def test_config_owned_by_someone_else_refused(env, monkeypatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(env.home).st_uid + 1)
    got, unresolved = env.adapter.resolve_capability_gate_mode()
    assert got == "enforce" and unresolved and "untrusted" in unresolved


def _allowlist(path: Path) -> Path:
    path.write_text(
        yaml.safe_dump(
            {"skills": {"UNLABELED": {"tools": ["read_file"], "paths": []}}}
        ),
        encoding="utf-8",
    )
    return path


@needs_posix
def test_allowlist_modes(env) -> None:
    al = _allowlist(env.tmp / "allowlist.yaml")
    os.chmod(al, 0o644)
    env.adapter._load_allowlist(str(al))
    for bad in (0o664, 0o666):
        os.chmod(al, bad)
        with pytest.raises(env.adapter.UntrustedFile):
            env.adapter._load_allowlist(str(al))


def test_linked_allowlist_refused(env) -> None:
    real = _allowlist(env.tmp / "real-allowlist.yaml")
    link = env.tmp / "allowlist.yaml"
    _link_or_skip(real, link)
    with pytest.raises(env.adapter.UntrustedFile):
        env.adapter._load_allowlist(str(link))


def test_refused_allowlist_blocks_in_enforce(env, monkeypatch) -> None:
    def broken(mode):
        raise env.adapter.UntrustedFile("allowlist is a symlink")

    monkeypatch.setattr(env.adapter, "_build_gate", broken)
    hooks = {}

    class Ctx:
        def register_hook(self, name, fn):
            hooks[name] = fn

    env.adapter.register(Ctx())
    assert blocked(hooks["pre_tool_call"]("read_file", {"path": "/etc/hosts"}, "p3"))


def test_owned_0600_config_loads_and_logs(env) -> None:
    # Negative control: a normal config loads and a normal call is decided.
    if POSIX:
        os.chmod(env.home / "config.yaml", 0o600)
    pre = _pre(env, [env.grant])
    assert pre("read_file", {"path": str(env.grant / "a.md")}, "p3") is None
    rec = json.loads(
        (env.home / "logs" / "gate.jsonl").read_text(encoding="utf-8").splitlines()[-1]
    )
    assert rec["verdict"] == "allow"
    assert stat.S_ISREG(os.stat(env.home / "config.yaml").st_mode)
