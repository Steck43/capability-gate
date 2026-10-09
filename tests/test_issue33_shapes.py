"""Issue #33 shapes: incomplete path extraction must deny, not allow.

On main before A5 these returned paths=[] and ALLOW. Closed argument schemas
raise ArgsRefused; the hook turns that into a logged denial. Blank / '*' skill
resolves to UNLABELED.
"""

from __future__ import annotations

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
    adapter = load_adapter("i33")
    pre = register(
        adapter,
        home,
        {"UNLABELED": {"tools": ["write_file"], "paths": [str(grant / "**")]}},
    )
    return types.SimpleNamespace(pre=pre, adapter=adapter, grant=grant)


def test_list_valued_path_denied(env) -> None:
    out = env.pre("write_file", {"path": ["/etc/passwd"], "content": "x"}, "t")
    assert blocked(out), out


@pytest.mark.parametrize(
    "key",
    ("filepath", "filename", "file", "src", "dest", "destination"),
)
def test_alternate_path_key_alone_denied(env, key) -> None:
    out = env.pre("write_file", {key: "/etc/passwd", "content": "x"}, "t")
    assert blocked(out), out


def test_blank_and_star_skill_are_unlabeled(env) -> None:
    for kwargs in (
        {},
        {"skill": ""},
        {"skill": "   "},
        {"skill": "*"},
        {"skill": "\t"},
    ):
        assert env.adapter._resolve_skill(kwargs) == "UNLABELED"


def test_star_grant_does_not_cover_blank_skill(tmp_path, monkeypatch) -> None:
    """Whitespace / '*' must not fall into the ambient '*' bucket."""
    home = hermes_home(tmp_path, monkeypatch)
    grant = (tmp_path / "grant").resolve()
    grant.mkdir()
    adapter = load_adapter("i33star")
    pre = register(
        adapter,
        home,
        {"*": {"tools": ["write_file"], "paths": [str(grant / "**")]}},
    )
    # No skill → UNLABELED, not '*', so deny even though '*' is granted.
    out = pre("write_file", {"path": str(grant / "a.txt"), "content": "x"}, "t")
    assert blocked(out), out
