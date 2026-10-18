"""K8: other spellings of the names the gate denies by name.

Inside a grant the gate denies two kinds of name: a protected segment (.env,
.env.*, .envrc, .aegis) and the canary basename secret-canary.txt. Windows
opens one file under several spellings: any case, a trailing dot or space
dropped, ``::$DATA``, and the ``\\\\?\\`` and ``\\\\.\\`` prefixes. Measured
on Windows 11, NTFS, Python 3.12 (AEG-163):

- The protected segment check holds for every spelling here, because it also
  checks the resolved path of the name and of its folder.
- The canary check reads only the name as given. Upper case, a trailing dot
  and a trailing space each open the canary and are allowed. So is an
  in-grant symlink to it, on every OS.
- A write to ".env " (trailing space) in a folder with no .env yet is
  allowed, and Windows creates .env.

Each miss is a strict expected failure that accepts only AssertionError, so
a fix turns it red until the mark comes off. The 8.3 short names are in
test_alias_class.py, since a volume can have them turned off.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOF = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOF))

from capability_gate import Gate, Verdict, load_policy  # noqa: E402

CANARY = "secret-canary.txt"


@pytest.fixture()
def grant(tmp_path: Path) -> Path:
    work = (tmp_path / "ws").resolve()
    work.mkdir()
    (work / ".env").write_text("x", encoding="utf-8")
    (work / CANARY).write_text("x", encoding="utf-8")
    return work


def _gate(grant: Path) -> Gate:
    policy = load_policy(
        {
            "skills": {
                "writer": {
                    "tools": ["read_file", "write_file"],
                    "paths": [str(grant) + "/**"],
                }
            }
        }
    )
    return Gate(policy, log_path=str(grant.parent / "k8.jsonl"))


# Held: each spelling opens .env or the canary, and the gate denies it.
@pytest.mark.skipif(os.name != "nt", reason="Windows file name rules")
@pytest.mark.parametrize(
    "spelling",
    [
        "{g}\\.ENV",
        "{g}\\.env.",
        "{g}\\.env ",
        "{g}\\.env::$DATA",
        "\\\\?\\{g}\\.env",
        "\\\\?\\{g}\\" + CANARY,
        "\\\\.\\{g}\\" + CANARY,
        "{g}\\" + CANARY + "::$DATA",
    ],
)
def test_k8_windows_spelling_of_a_denied_name_is_denied(
    grant: Path, spelling: str
) -> None:
    d = _gate(grant).evaluate("writer", "read_file", [spelling.format(g=grant)])
    assert d.verdict is Verdict.DENY, d.reason


@pytest.mark.skipif(os.name != "nt", reason="Windows file name rules")
def test_k8_write_to_env_with_trailing_dot_is_denied(grant: Path) -> None:
    new = grant / "fresh"
    new.mkdir()
    d = _gate(grant).evaluate("writer", "write_file", [f"{new}\\.env."])
    assert d.verdict is Verdict.DENY, d.reason


# Missed: the canary check compares the basename as given.
@pytest.mark.skipif(os.name != "nt", reason="Windows file name rules")
@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="LIMIT: the canary check is case-sensitive; Windows opens any case",
)
def test_k8_canary_in_upper_case_is_denied(grant: Path) -> None:
    d = _gate(grant).evaluate("writer", "read_file", [f"{grant}\\SECRET-CANARY.TXT"])
    assert d.verdict is Verdict.DENY, d.reason


@pytest.mark.skipif(os.name != "nt", reason="Windows file name rules")
@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="LIMIT: Windows drops a trailing dot; the canary check does not",
)
def test_k8_canary_with_trailing_dot_is_denied(grant: Path) -> None:
    d = _gate(grant).evaluate("writer", "read_file", [f"{grant}\\{CANARY}."])
    assert d.verdict is Verdict.DENY, d.reason


@pytest.mark.skipif(os.name != "nt", reason="Windows file name rules")
@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="LIMIT: Windows drops a trailing space; the canary check does not",
)
def test_k8_canary_with_trailing_space_is_denied(grant: Path) -> None:
    d = _gate(grant).evaluate("writer", "read_file", [f"{grant}\\{CANARY} "])
    assert d.verdict is Verdict.DENY, d.reason


# Missed: a new name is checked as given, and Windows creates .env.
@pytest.mark.skipif(os.name != "nt", reason="Windows file name rules")
@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="LIMIT: a write to '.env ' is allowed and Windows creates .env",
)
def test_k8_write_to_env_with_trailing_space_is_denied(grant: Path) -> None:
    new = grant / "fresh"
    new.mkdir()
    d = _gate(grant).evaluate("writer", "write_file", [f"{new}\\.env "])
    assert d.verdict is Verdict.DENY, d.reason


# Missed on every OS: the canary check reads the link's name, not its target.
@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="LIMIT: an in-grant symlink to the canary is allowed",
)
def test_k8_symlink_to_canary_is_denied(grant: Path) -> None:
    link = grant / "notes.txt"
    try:
        os.symlink(grant / CANARY, link)
    except OSError as exc:
        if os.name == "nt":
            pytest.skip(f"symlink refused without the privilege ({exc})")
        raise
    d = _gate(grant).evaluate("writer", "read_file", [str(link)])
    assert d.verdict is Verdict.DENY, d.reason
