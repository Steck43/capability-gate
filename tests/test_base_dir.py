"""A relative path is checked in the folder Hermes will write it to.

The gate used to resolve a relative path against the process working
directory. Hermes resolves it against the task's live terminal folder, a
registered session folder, or ``$TERMINAL_CWD`` before it falls back to the
process folder (``tools/file_tools.py`` ``_resolve_base_dir``). When those
differ, an in-grant check could approve an off-grant write. The adapter now asks
Hermes's own resolver, through the module Hermes has already loaded, and denies
a relative path when no base folder can be had.

These tests stand in for that module with a small fake that honours
``$TERMINAL_CWD``; the end-to-end run against the real runtime is in the
grind01 evidence file.
"""

from __future__ import annotations

import json
import os
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from grind01_util import blocked, hermes_home, load_adapter, register  # noqa: E402

from capability_gate import ENFORCE, Gate, Verdict, load_policy  # noqa: E402

HERMES_MODULE = "tools.file_tools"


def _fake_hermes(monkeypatch, resolver=None) -> None:
    def _resolve_base_dir(task_id="default", *, container_paths=None):
        cwd = os.environ.get("TERMINAL_CWD", "")
        return Path(cwd) if os.path.isabs(cwd) else Path(os.getcwd())

    mod = types.ModuleType(HERMES_MODULE)
    mod._resolve_base_dir = resolver or _resolve_base_dir
    monkeypatch.setitem(sys.modules, HERMES_MODULE, mod)


@pytest.fixture
def dirs(tmp_path, monkeypatch):
    proc = (tmp_path / "proc").resolve()
    (proc / "grant").mkdir(parents=True)
    ws = (tmp_path / "ws").resolve()
    (ws / "grant" / "sub").mkdir(parents=True)
    monkeypatch.chdir(proc)
    monkeypatch.delitem(sys.modules, HERMES_MODULE, raising=False)
    home = hermes_home(tmp_path, monkeypatch)
    return types.SimpleNamespace(proc=proc, ws=ws, home=home)


def _pre(d, grant_root: Path, tools=("write_file", "patch", "search_files")):
    adapter = load_adapter("p2")
    skills = {"UNLABELED": {"tools": list(tools), "paths": [str(grant_root / "**")]}}
    return register(adapter, d.home, skills)


def test_relative_path_checked_where_hermes_resolves_it(dirs, monkeypatch) -> None:
    # In-grant from the process folder, off-grant from the folder Hermes uses.
    _fake_hermes(monkeypatch)
    monkeypatch.setenv("TERMINAL_CWD", str(dirs.ws))
    pre = _pre(dirs, dirs.proc / "grant")
    assert blocked(pre("write_file", {"path": "grant/x.txt", "content": "x"}, "t"))


def test_relative_path_allowed_where_hermes_resolves_it(dirs, monkeypatch) -> None:
    _fake_hermes(monkeypatch)
    monkeypatch.setenv("TERMINAL_CWD", str(dirs.ws))
    pre = _pre(dirs, dirs.ws / "grant")
    assert pre("write_file", {"path": "grant/x.txt", "content": "x"}, "t") is None
    rec = json.loads(
        (dirs.home / "logs" / "gate.jsonl").read_text(encoding="utf-8").splitlines()[-1]
    )
    assert rec["paths"] == [str(dirs.ws / "grant" / "x.txt")]


def test_v4a_relative_header_resolved_the_same_way(dirs, monkeypatch) -> None:
    _fake_hermes(monkeypatch)
    monkeypatch.setenv("TERMINAL_CWD", str(dirs.ws))
    pre = _pre(dirs, dirs.proc / "grant")
    body = "*** Begin Patch\n*** Add File: grant/x.txt\n+x\n*** End Patch"
    assert blocked(pre("patch", {"mode": "patch", "patch": body}, "t"))


def test_search_files_default_path_is_the_hermes_folder(dirs, monkeypatch) -> None:
    _fake_hermes(monkeypatch)
    monkeypatch.setenv("TERMINAL_CWD", str(dirs.ws / "grant" / "sub"))
    pre = _pre(dirs, dirs.ws / "grant")
    assert pre("search_files", {"pattern": "x"}, "t") is None


def test_relative_path_without_hermes_resolver_denied(dirs) -> None:
    # In-grant from the process folder, but there is no Hermes folder to ask.
    pre = _pre(dirs, dirs.proc / "grant")
    assert blocked(pre("write_file", {"path": "grant/x.txt", "content": "x"}, "t"))


@pytest.mark.parametrize(
    "resolver",
    [
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no env")),
        lambda *a, **k: ".",
    ],
    ids=["raises", "relative"],
)
def test_unusable_hermes_base_denied(dirs, monkeypatch, resolver) -> None:
    _fake_hermes(monkeypatch, resolver)
    pre = _pre(dirs, dirs.proc / "grant")
    assert blocked(pre("write_file", {"path": "grant/x.txt", "content": "x"}, "t"))


def test_absolute_in_grant_path_still_allowed(dirs, monkeypatch) -> None:
    # T14: a stock absolute in-grant path is untouched by any of this.
    pre = _pre(dirs, dirs.proc / "grant")
    args = {"path": str(dirs.proc / "grant" / "x.txt"), "content": "x"}
    assert pre("write_file", args, "t") is None


def test_gate_api_relative_path_needs_a_base(tmp_path) -> None:
    grant = (tmp_path / "g").resolve()
    grant.mkdir()
    gate = Gate(
        load_policy(
            {"skills": {"s": {"tools": ["read_file"], "paths": [str(grant / "**")]}}}
        ),
        log_path=str(tmp_path / "d.jsonl"),
        mode=ENFORCE,
    )
    assert gate.evaluate("s", "read_file", ["x.txt"]).verdict is Verdict.DENY
    d = gate.evaluate("s", "read_file", ["x.txt"], base_dir=str(grant))
    assert d.verdict is Verdict.ALLOW
    assert d.paths == (str(grant / "x.txt"),)


def _runtime_file_tools() -> Path:
    root = os.environ.get("HERMES_AGENT_SRC") or os.path.expanduser(
        "~/.hermes/hermes-agent"
    )
    return Path(root) / "tools" / "file_tools.py"


def test_hermes_resolver_order_unchanged() -> None:
    """Drift guard: the adapter trusts Hermes's resolver by name. If Hermes
    renames it or changes its order, this fails so the change gets a review."""
    src_path = _runtime_file_tools()
    if not src_path.is_file():
        pytest.skip(
            f"Hermes runtime not present at {src_path} (CI does not install it)"
        )
    src = src_path.read_text(encoding="utf-8")
    assert 'def _resolve_base_dir(\n    task_id: str = "default",' in src
    start = src.index("def _resolve_base_dir(")
    doc = src[start : start + 2500]
    order = [
        "1. The task's live terminal cwd",
        "2. A registered task/session cwd override",
        "3. A sentinel-free, absolute ``$TERMINAL_CWD``",
        "4. The process cwd.",
    ]
    at = [doc.find(s) for s in order]
    assert all(i >= 0 for i in at), at
    assert at == sorted(at)
