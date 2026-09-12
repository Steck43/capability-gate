"""Alias class beyond S1. Own ids. Skip only if the OS refuses the alias.

S1 is the symlink. These four are unmeasured on the mounted gate until created.
They do not change the Stage-1 7/8/4/0 table.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOF = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOF))
sys.path.insert(0, str(ROOF / "harness"))

from capability_gate import ENFORCE, Gate, Verdict, load_policy  # noqa: E402
from lab_insufficiency_harness import POLICY  # noqa: E402


def _gate(tmp: Path, grant: Path) -> Gate:
    raw = {
        **POLICY,
        "skills": {
            **POLICY["skills"],
            "lab-helper": {
                **POLICY["skills"]["lab-helper"],
                "paths": list(POLICY["skills"]["lab-helper"]["paths"])
                + [str(grant.resolve() / "**")],
            },
        },
    }
    return Gate(load_policy(raw), log_path=str(tmp / "alias.jsonl"), mode=ENFORCE)


def test_s2_hardlink_false_allow_or_os_refused(tmp_path: Path) -> None:
    grant = tmp_path / "s2-in-grant"
    off = tmp_path / "s2-off-grant" / "id_rsa"
    grant.mkdir()
    off.parent.mkdir()
    off.write_text("x", encoding="utf-8")
    link = grant / "s2-hard"
    try:
        os.link(off, link)
    except OSError as exc:
        pytest.skip(f"os.link refused ({exc})")
    d = _gate(tmp_path, grant).evaluate("lab-helper", "write_file", [str(link)])
    assert d.verdict is Verdict.ALLOW


def test_s3_junction_false_allow_or_os_refused(tmp_path: Path) -> None:
    if os.name != "nt":
        pytest.skip("junctions are a Windows alias")
    grant = tmp_path / "s3-in-grant"
    off = tmp_path / "s3-off-grant"
    grant.mkdir()
    off.mkdir()
    (off / "id_rsa").write_text("x", encoding="utf-8")
    junction = grant / "s3-junc"
    try:
        import _winapi

        _winapi.CreateJunction(str(off), str(junction))
    except (OSError, AttributeError) as exc:
        pytest.skip(f"CreateJunction refused ({exc})")
    target = junction / "id_rsa"
    d = _gate(tmp_path, grant).evaluate("lab-helper", "write_file", [str(target)])
    assert d.verdict is Verdict.ALLOW


def test_s4_proc_self_root_unmeasured_off_linux_unless_present(tmp_path: Path) -> None:
    proc = Path("/proc/self/root")
    if not proc.exists():
        pytest.skip("/proc/self/root absent on this OS")
    grant = tmp_path / "s4-in-grant"
    grant.mkdir()
    alias = grant / "s4-proc"
    try:
        os.symlink(proc, alias)
    except OSError as exc:
        pytest.skip(f"symlink to /proc/self/root refused ({exc})")
    d = _gate(tmp_path, grant).evaluate("lab-helper", "read_file", [str(alias)])
    assert d.verdict is Verdict.ALLOW


def test_s5_bind_mount_named_skip_without_mount(tmp_path: Path) -> None:
    pytest.skip("bind-mount alias needs a host mount; not faked in-process")
