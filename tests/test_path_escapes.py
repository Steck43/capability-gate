"""Known-answer tests for path escapes through links.

# KAT

The gate must judge the file the operating system will open, not the string it
was handed. Each case builds a link layout, reads what the OS actually opens,
and requires the gate to deny exactly when that file is outside the grant.
Both the gate and the registered Hermes hook are driven.
"""

# KAT

from __future__ import annotations

import os
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from grind01_util import blocked, hermes_home, load_adapter, register  # noqa: E402

from capability_gate import Gate, Verdict, load_policy  # noqa: E402

HERMES_MODULE = "tools.file_tools"


@pytest.fixture
def layout(tmp_path: Path):
    """granted/sl -> outside/inner; outside/secret.txt off grant; a decoy in grant."""
    granted = (tmp_path / "granted").resolve()
    granted.mkdir()
    outside = (tmp_path / "outside").resolve()
    (outside / "inner").mkdir(parents=True)
    (outside / "secret.txt").write_text("SECRET", encoding="utf-8")
    (granted / "secret.txt").write_text("DECOY", encoding="utf-8")
    (granted / "a").mkdir()
    (granted / "b.txt").write_text("IN", encoding="utf-8")
    if os.name == "nt":
        try:
            os.symlink(outside / "inner", granted / "sl", target_is_directory=True)
        except OSError as exc:
            pytest.skip(f"this Windows account cannot create symlinks: {exc}")
    else:
        os.symlink(outside / "inner", granted / "sl", target_is_directory=True)
    return types.SimpleNamespace(root=tmp_path, granted=granted, outside=outside)


@pytest.fixture
def gate(layout):
    policy = load_policy(
        {
            "skills": {
                "s": {"tools": ["read_file"], "paths": [str(layout.granted / "**")]}
            }
        }
    )
    return Gate(policy, log_path=str(layout.root / "logs" / "decisions.jsonl"))


def _opened(layout, rel: str) -> str:
    return Path(layout.granted, rel).read_text(encoding="utf-8")


ESCAPE = os.path.join("sl", "..", "secret.txt")
IN_GRANT = os.path.join("a", "..", "b.txt")


def test_symlink_then_dotdot_relative_denied(layout, gate) -> None:
    # On POSIX the OS resolves sl before "..", so this opens outside/secret.txt.
    # On Windows the path is collapsed as text first, so it opens the decoy.
    opened = _opened(layout, ESCAPE)
    if os.name != "nt":
        assert opened == "SECRET", "layout does not reproduce the escape"
    d = gate.evaluate("s", "read_file", [ESCAPE], base_dir=str(layout.granted))
    expected = Verdict.DENY if opened == "SECRET" else Verdict.ALLOW
    assert d.verdict is expected, (opened, d.reason)


def test_dotdot_inside_the_grant_still_allows(layout, gate) -> None:
    assert _opened(layout, IN_GRANT) == "IN"
    d = gate.evaluate("s", "read_file", [IN_GRANT], base_dir=str(layout.granted))
    assert d.verdict is Verdict.ALLOW, d.reason


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
