"""Closed argument schemas: the gate sees every file a call can touch, or denies it.

Before this, the adapter read a fixed set of path-like keys. A ``patch`` call
in V4A form names its files in header lines inside the patch body, which were
never read, so a granted ``patch`` could write anywhere. Other shapes dropped to
"no paths" too: an unlisted key, a list or bytes value, or args that were not a
dict. Each of those now resolves to a list of paths or a refusal.
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from grind01_util import blocked, hermes_home, load_adapter, register  # noqa: E402


@pytest.fixture
def env(tmp_path, monkeypatch):
    home = hermes_home(tmp_path, monkeypatch)
    grant = (tmp_path / "grant").resolve()
    grant.mkdir()
    outside = (tmp_path / "outside").resolve()
    outside.mkdir()
    adapter = load_adapter("p1")
    tools = ["read_file", "write_file", "patch", "search_files", "list_dir"]
    pre = register(
        adapter,
        home,
        {"UNLABELED": {"tools": tools, "paths": [str(grant / "**")]}},
    )
    return types.SimpleNamespace(
        pre=pre, adapter=adapter, home=home, grant=grant, outside=outside
    )


def _v4a(*lines: str) -> str:
    return "\n".join(["*** Begin Patch", *lines, "*** End Patch"])


def _call(env, tool, args):
    return env.pre(tool, args, "p1")


# --- V4A patch headers -----------------------------------------------------


@pytest.mark.parametrize(
    "header",
    [
        "*** Update File: {off}",
        "*** Add File: {off}",
        "*** Delete File: {off}",
        "***Update File: {off}",
        "*** Move File: {grant}/a.txt -> {off}",
        "*** Move File: {off} -> {grant}/a.txt",
        "*** Move to: {off}",
    ],
)
def test_v4a_header_off_grant_denied(env, header) -> None:
    line = header.format(off=env.outside / "x.txt", grant=env.grant)
    out = _call(env, "patch", {"mode": "patch", "patch": _v4a(line, "+x")})
    assert blocked(out), out


def test_v4a_in_grant_path_does_not_hide_off_grant_header(env) -> None:
    body = _v4a(f"*** Update File: {env.outside / 'x.txt'}", "+x")
    args = {"mode": "patch", "path": str(env.grant / "ok.txt"), "patch": body}
    assert blocked(_call(env, "patch", args))


@pytest.mark.parametrize("mode", [None, "PATCH", "bogus"])
def test_v4a_headers_read_whatever_the_mode(env, mode) -> None:
    args = {"patch": _v4a(f"*** Add File: {env.outside / 'x.txt'}", "+x")}
    if mode is not None:
        args["mode"] = mode
    assert blocked(_call(env, "patch", args))


def test_v4a_body_with_no_file_header_denied(env) -> None:
    # The in-grant path keeps "names no file" from catching it first.
    args = {"mode": "patch", "path": str(env.grant / "a.txt"), "patch": "+a line"}
    assert blocked(_call(env, "patch", args))


@pytest.mark.parametrize("mode", ["PATCH", "bogus", 1])
def test_unknown_patch_mode_denied(env, mode) -> None:
    # In-grant on its face: only the mode check can deny it.
    args = {
        "mode": mode,
        "path": str(env.grant / "a.txt"),
        "old_string": "a",
        "new_string": "b",
    }
    assert blocked(_call(env, "patch", args))


def test_v4a_unknown_control_line_denied(env) -> None:
    body = _v4a(f"*** Update File: {env.grant / 'a.txt'}", "*** Rename: /etc/x")
    assert blocked(_call(env, "patch", {"mode": "patch", "patch": body}))


def test_v4a_in_grant_patch_allowed(env) -> None:
    body = _v4a(f"*** Update File: {env.grant / 'a.txt'}", "@@", "-a", "+b")
    assert _call(env, "patch", {"mode": "patch", "patch": body}) is None


def test_replace_mode_in_grant_allowed(env) -> None:
    args = {
        "mode": "replace",
        "path": str(env.grant / "a.txt"),
        "old_string": "a",
        "new_string": "b",
    }
    assert _call(env, "patch", args) is None


# --- shapes that used to drop to "no paths" --------------------------------


@pytest.mark.parametrize("key", ["filepath", "filename", "src", "dest", "bogus"])
def test_unknown_key_denied(env, key) -> None:
    args = {"path": str(env.grant / "ok.txt"), "content": "x", key: "y"}
    assert blocked(_call(env, "write_file", args))


def test_tool_with_no_schema_denied(env) -> None:
    # list_dir is granted in the policy, but the adapter has no schema for it,
    # so it cannot know which argument names a path.
    assert blocked(_call(env, "list_dir", {"path": str(env.grant / "sub")}))


@pytest.mark.parametrize(
    "value",
    [
        lambda e: [str(e.outside / "x.txt")],
        lambda e: str(e.outside / "x.txt").encode(),
        lambda e: e.outside / "x.txt",
    ],
    ids=["list", "bytes", "pathlike"],
)
def test_non_string_path_value_denied(env, value) -> None:
    args = {"path": value(env), "content": "x"}
    assert blocked(_call(env, "write_file", args))


def test_non_dict_args_denied(env) -> None:
    mapping = types.MappingProxyType({"path": str(env.outside / "x.txt")})
    assert blocked(_call(env, "read_file", mapping))
    assert blocked(_call(env, "read_file", [str(env.outside / "x.txt")]))


def test_missing_required_path_denied(env) -> None:
    assert blocked(_call(env, "write_file", {"content": "x"}))


def test_extractor_error_denied(env, monkeypatch) -> None:
    def boom(_body):
        raise RuntimeError("parser broke")

    monkeypatch.setattr(env.adapter, "_v4a_paths", boom)
    body = _v4a(f"*** Update File: {env.grant / 'a.txt'}", "+x")
    assert blocked(_call(env, "patch", {"mode": "patch", "patch": body}))


def test_search_files_target_is_not_a_path(env) -> None:
    for target in ("content", "files"):
        # A subfolder: "<root>/**" not covering the root itself is a separate,
        # known false deny (A-P2-R1-1), not this test's subject.
        args = {"pattern": "x", "target": target, "path": str(env.grant / "sub")}
        assert _call(env, "search_files", args) is None, target


def test_refusal_is_logged_in_observe(tmp_path, monkeypatch) -> None:
    home = hermes_home(tmp_path, monkeypatch, mode="observe")
    adapter = load_adapter("p1obs")
    pre = register(adapter, home, {"UNLABELED": {"tools": ["write_file"], "paths": []}})
    assert pre("list_dir", {"path": "/etc"}, "p1") is None  # observe acts on nothing
    lines = (home / "logs" / "gate.jsonl").read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[-1])
    assert rec["verdict"] == "deny"
    assert "no argument schema" in rec["reason"]
