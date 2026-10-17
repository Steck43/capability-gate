"""The registered Hermes hook over the path escape layouts in
tests/test_path_escapes.py: it must block exactly when the file the operating
system opens is outside the grant."""

from __future__ import annotations

import os
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from grind01_util import blocked, hermes_home, load_adapter, register
from test_path_escapes import (
    ESCAPE,
    IN_GRANT,
    _opened,
    layout,
    search_area,
)

__all__ = ["layout", "search_area"]

HERMES_MODULE = "tools.file_tools"


@pytest.fixture
def pre_tool_call(layout, monkeypatch):
    def _resolve_base_dir(task_id="default", *, container_paths=None):
        return Path(os.environ["TERMINAL_CWD"])

    mod = types.ModuleType(HERMES_MODULE)
    mod._resolve_base_dir = _resolve_base_dir
    monkeypatch.setitem(sys.modules, HERMES_MODULE, mod)
    monkeypatch.setenv("TERMINAL_CWD", str(layout.granted))
    home = hermes_home(layout.root, monkeypatch)
    skills = {
        "UNLABELED": {"tools": ["read_file"], "paths": [str(layout.granted / "**")]}
    }
    return register(load_adapter("escapes"), home, skills)


def test_symlink_then_dotdot_relative_denied_through_the_hook(
    layout, pre_tool_call
) -> None:
    opened = _opened(layout, ESCAPE)
    out = pre_tool_call("read_file", {"path": ESCAPE}, "t")
    assert blocked(out) is (opened == "SECRET"), (opened, out)


def test_dotdot_inside_the_grant_allows_through_the_hook(layout, pre_tool_call) -> None:
    assert pre_tool_call("read_file", {"path": IN_GRANT}, "t") is None


def test_search_files_hardlink_denied_through_the_hook(search_area, monkeypatch):
    os.link(search_area.outside / "secret.txt", search_area.docs / "hl.txt")
    home = hermes_home(search_area.root, monkeypatch)
    skills = {
        "UNLABELED": {
            "tools": ["search_files"],
            "paths": [str(search_area.granted / "**")],
        }
    }
    pre_tool_call = register(load_adapter("search"), home, skills)
    args = {"pattern": "x", "path": str(search_area.docs)}
    out = pre_tool_call("search_files", args, "t")
    assert blocked(out), out
