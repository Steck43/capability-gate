"""Known-answer tests for path escapes through links.

# KAT

The gate must judge the file the operating system will open, not the string it
was handed. Each case builds a link layout, reads what the OS actually opens,
and requires the gate to deny exactly when that file is outside the grant.
The registered Hermes hook is driven over the same layout in
tests/test_path_escapes_hook.py.
"""

# KAT

from __future__ import annotations

import os
import types
from pathlib import Path

import pytest

from capability_gate import Gate, Verdict, load_policy


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


@pytest.mark.skipif(
    os.name == "nt", reason="Windows collapses .. before it follows the link"
)
def test_symlink_then_dotdot_relative_denied(layout, gate) -> None:
    # On POSIX the OS resolves sl before "..", so this opens outside/secret.txt.
    assert _opened(layout, ESCAPE) == "SECRET", "layout does not reproduce the escape"
    d = gate.evaluate("s", "read_file", [ESCAPE], base_dir=str(layout.granted))
    assert d.verdict is Verdict.DENY, d.reason


@pytest.mark.skipif(os.name != "nt", reason="POSIX follows the link before ..")
def test_symlink_then_dotdot_opens_the_decoy_on_windows_and_allows(
    layout, gate
) -> None:
    # On Windows the path is collapsed as text first, so it opens the decoy
    # inside the grant, and the gate allows it.
    assert _opened(layout, ESCAPE) == "DECOY"
    d = gate.evaluate("s", "read_file", [ESCAPE], base_dir=str(layout.granted))
    assert d.verdict is Verdict.ALLOW, d.reason


def test_dotdot_inside_the_grant_still_allows(layout, gate) -> None:
    assert _opened(layout, IN_GRANT) == "IN"
    d = gate.evaluate("s", "read_file", [IN_GRANT], base_dir=str(layout.granted))
    assert d.verdict is Verdict.ALLOW, d.reason
