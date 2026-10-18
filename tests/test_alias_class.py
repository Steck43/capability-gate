"""Alias class beyond S1. Own ids. Skip only if the OS refuses the alias.

S1 is the symlink. These four are unmeasured on the mounted gate until created.
They do not change the Stage-1 7/8/4/0 table. S6 is the Windows 8.3 short name
of a name the gate denies (K8, AEG-163); the other K8 spellings are in
test_k8_name_aliases.py.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOF = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOF))
sys.path.insert(0, str(ROOF / "harness"))

from lab_insufficiency_harness import POLICY  # noqa: E402

from capability_gate import ENFORCE, Gate, Verdict, load_policy  # noqa: E402


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
    # K5: refuse regular files with st_nlink > 1 so an in-grant hardlink to an
    # off-grant inode cannot ride the grant match on the in-grant name.
    assert d.verdict is Verdict.DENY


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
    # A5: was ALLOW. The decide path matches the resolved real path, and the
    # junction resolves to the off-grant directory.
    assert d.verdict is Verdict.DENY


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
    # A5: was ALLOW. The decide path matches the resolved real path, and
    # /proc/self/root resolves to "/", which is outside the grant.
    assert d.verdict is Verdict.DENY


def test_s5_bind_mount_named_skip_without_mount(tmp_path: Path) -> None:
    pytest.skip("bind-mount alias needs a host mount; not faked in-process")


def _short_name(path: Path) -> str | None:
    """The 8.3 short name Windows gives path, or None when the volume gives none."""
    import ctypes

    buf = ctypes.create_unicode_buffer(32768)
    n = ctypes.windll.kernel32.GetShortPathNameW(str(path), buf, len(buf))
    short = os.path.basename(buf.value) if n else ""
    return short if short and short != path.name else None


def _s6_grant(tmp_path: Path, name: str) -> tuple[Path, str]:
    if os.name != "nt":
        pytest.skip("8.3 short names are a Windows alias")
    grant = tmp_path / "s6-in-grant"
    grant.mkdir()
    (grant / name).write_text("x", encoding="utf-8")
    short = _short_name(grant / name)
    if short is None:
        pytest.skip(f"this volume gives {name} no 8.3 short name")
    return grant, short


def test_s6_short_name_of_env_denied(tmp_path: Path) -> None:
    grant, short = _s6_grant(tmp_path, ".env")
    target = str(grant.resolve() / short)
    d = _gate(tmp_path, grant).evaluate("lab-helper", "read_file", [target])
    # Held: the protected segment check also checks the resolved path, and
    # Windows resolves the short name to .env.
    assert d.verdict is Verdict.DENY


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="LIMIT: the canary check reads the name as given, not the 8.3 alias",
)
def test_s6_short_name_of_canary_denied(tmp_path: Path) -> None:
    grant, short = _s6_grant(tmp_path, "secret-canary.txt")
    target = str(grant.resolve() / short)
    d = _gate(tmp_path, grant).evaluate("lab-helper", "read_file", [target])
    assert d.verdict is Verdict.DENY
