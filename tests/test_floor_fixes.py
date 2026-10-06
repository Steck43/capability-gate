"""A5 floor fixes: no ambient grant, and the checked path is the opened object.

A5a. Hermes 0.18 sends no skill field on pre_tool_call, so every live call used
to resolve to the ``*`` grant. A call with no skill is now ``UNLABELED`` and is
denied unless the policy grants ``UNLABELED`` by name. A labeled skill the
policy does not name is denied too; nothing falls back to ``*``.

A5b. The gate matched the request string after expanding ``~`` and ``$VARS``.
It now refuses request paths that need expansion and matches the resolved real
path, so an in-grant symlink to an off-grant file is denied.

Two cases stay open and are strict expected failures, so each fails outright
the day it closes without the marker being updated:
- a hardlink: the in-grant name is the real path, so realpath cannot see that
  the inode is also reachable off-grant;
- a swap between check and open: the gate checks a path, the tool opens it
  later by name. Only the host opening once by file descriptor closes it.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOF = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOF))

from capability_gate import ENFORCE, Gate, Verdict, load_policy  # noqa: E402


def _adapter():
    if "capability_gate" not in sys.modules:
        cg_spec = importlib.util.spec_from_file_location(
            "capability_gate", ROOF / "capability_gate.py"
        )
        cg = importlib.util.module_from_spec(cg_spec)
        sys.modules["capability_gate"] = cg
        cg_spec.loader.exec_module(cg)
    spec = importlib.util.spec_from_file_location(
        "capability_gate_adapter", ROOF / "__init__.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _gate(tmp_path: Path, skills: dict) -> Gate:
    return Gate(
        load_policy({"skills": skills}),
        log_path=str(tmp_path / "decisions.jsonl"),
        mode=ENFORCE,
    )


def _grant(tmp_path: Path) -> Path:
    grant = (tmp_path / "grant").resolve()
    grant.mkdir()
    return grant


def _star_policy(grant: Path) -> dict:
    return {"*": {"tools": ["read_file", "write_file"], "paths": [str(grant / "**")]}}


# ---------------------------------------------------------------- A5a


@pytest.mark.parametrize("kwargs", [{}, {"skill": ""}, {"skill": "  "}, {"skill": "*"}])
def test_missing_skill_resolves_unlabeled(kwargs: dict) -> None:
    assert _adapter()._resolve_skill(kwargs) == "UNLABELED"


def test_unlabeled_call_denied_without_named_grant(tmp_path: Path) -> None:
    grant = _grant(tmp_path)
    gate = _gate(tmp_path, _star_policy(grant))
    skill = _adapter()._resolve_skill({})
    decision = gate.evaluate(skill, "read_file", [str(grant / "notes.md")])
    assert decision.verdict is Verdict.DENY


def test_unlabeled_call_allowed_when_granted_by_name(tmp_path: Path) -> None:
    grant = _grant(tmp_path)
    gate = _gate(
        tmp_path,
        {"UNLABELED": {"tools": ["read_file"], "paths": [str(grant / "**")]}},
    )
    skill = _adapter()._resolve_skill({})
    decision = gate.evaluate(skill, "read_file", [str(grant / "notes.md")])
    assert decision.verdict is Verdict.ALLOW


def test_labeled_unknown_skill_denied_not_star(tmp_path: Path) -> None:
    grant = _grant(tmp_path)
    gate = _gate(tmp_path, _star_policy(grant))
    skill = _adapter()._resolve_skill({"skill": "ghost-skill"})
    assert skill == "ghost-skill"
    decision = gate.evaluate(skill, "read_file", [str(grant / "notes.md")])
    assert decision.verdict is Verdict.DENY


# ---------------------------------------------------------------- A5b


def _symlink(target: Path, link: Path) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"OS refused the symlink: {exc}")


def test_in_grant_symlink_to_outside_denied(tmp_path: Path) -> None:
    grant = _grant(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "id_rsa"
    secret.write_text("x", encoding="utf-8")
    link = grant / "innocent.md"
    _symlink(secret, link)
    gate = _gate(tmp_path, _star_policy(grant))
    assert gate.evaluate("*", "read_file", [str(link)]).verdict is Verdict.DENY


def test_in_grant_symlink_to_inside_allowed(tmp_path: Path) -> None:
    grant = _grant(tmp_path)
    real = grant / "real.md"
    real.write_text("x", encoding="utf-8")
    link = grant / "alias.md"
    _symlink(real, link)
    gate = _gate(tmp_path, _star_policy(grant))
    assert gate.evaluate("*", "read_file", [str(link)]).verdict is Verdict.ALLOW


def test_symlinked_grant_root_still_allows_its_own_files(tmp_path: Path) -> None:
    real_root = (tmp_path / "real-root").resolve()
    real_root.mkdir()
    (real_root / "a.md").write_text("x", encoding="utf-8")
    link_root = tmp_path / "link-root"
    _symlink(real_root, link_root)
    gate = _gate(
        tmp_path,
        {"*": {"tools": ["read_file"], "paths": [str(link_root / "**")]}},
    )
    assert (
        gate.evaluate("*", "read_file", [str(link_root / "a.md")]).verdict
        is Verdict.ALLOW
    )


def test_sibling_prefix_denied(tmp_path: Path) -> None:
    grant = _grant(tmp_path)
    evil = tmp_path / "grant-evil"
    evil.mkdir()
    gate = _gate(tmp_path, _star_policy(grant))
    assert gate.evaluate("*", "read_file", [str(evil / "x.md")]).verdict is Verdict.DENY


@pytest.mark.parametrize("form", ["$HOME/notes.md", "${HOME}/notes.md", "~/notes.md"])
def test_request_path_needing_expansion_denied(
    tmp_path: Path, monkeypatch, form: str
) -> None:
    grant = _grant(tmp_path)
    monkeypatch.setenv("HOME", str(grant))
    gate = _gate(tmp_path, _star_policy(grant))
    assert gate.evaluate("*", "read_file", [form]).verdict is Verdict.DENY


@pytest.mark.parametrize("form", ["$HOME/notes.md", "~/notes.md"])
def test_unexpanded_request_path_not_matched_literally(
    tmp_path: Path, monkeypatch, form: str
) -> None:
    # The other direction: the gate does not expand, the tool does. With the
    # working directory inside the grant, the literal string resolves into the
    # grant while the tool would open $HOME, which is outside it.
    grant = _grant(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.setenv("HOME", str(outside))
    monkeypatch.chdir(grant)
    gate = _gate(tmp_path, _star_policy(grant))
    assert gate.evaluate("*", "read_file", [form]).verdict is Verdict.DENY


@pytest.mark.xfail(
    strict=True,
    reason="OPEN: a hardlink's in-grant name is its real path, so realpath cannot "
    "see the inode is also reachable off-grant. Needs an inode or link-count check.",
)
def test_hardlink_to_off_grant_inode_denied(tmp_path: Path) -> None:
    grant = _grant(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "id_rsa"
    secret.write_text("x", encoding="utf-8")
    link = grant / "innocent.md"
    try:
        os.link(secret, link)
    except OSError as exc:
        pytest.skip(f"OS refused the hardlink: {exc}")
    gate = _gate(tmp_path, _star_policy(grant))
    assert gate.evaluate("*", "read_file", [str(link)]).verdict is Verdict.DENY


@pytest.mark.xfail(
    strict=True,
    reason="OPEN: swap between check and open. The gate checks a path and the tool "
    "opens it later by name; needs the host to open the checked object by fd "
    "(open with O_NOFOLLOW once, then act through that fd).",
)
def test_swap_between_check_and_open_is_caught(tmp_path: Path) -> None:
    grant = _grant(tmp_path)
    target = grant / "notes.md"
    target.write_text("x", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "id_rsa"
    secret.write_text("x", encoding="utf-8")
    gate = _gate(tmp_path, _star_policy(grant))
    decision = gate.evaluate("*", "read_file", [str(target)])
    assert decision.verdict is Verdict.ALLOW
    # The swap: after the check, before the tool opens the name it was given.
    target.unlink()
    _symlink(secret, target)
    opened = Path(os.path.realpath(target))
    assert opened.is_relative_to(grant), f"tool would open {opened}"
