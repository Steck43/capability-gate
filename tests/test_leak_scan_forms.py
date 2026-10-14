"""Leak scan: every encoding and path form, every scan mode, attributes cannot hide lines.

Every fixture is built at runtime (the fake term, and path shapes joined from
parts), so this file carries no form the scan would flag.
"""

from __future__ import annotations

import base64
import codecs
import itertools
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "leak_denylist_scan.py"
BS = chr(92)
TERM = "zq" + "xwvk"


def _j(sep: str, *parts: str) -> str:
    return sep.join(parts)


def _urlsafe(term: str) -> str:
    """Unpadded URL-safe base64 of the term plus a suffix that forces - or _."""
    suffixes = (
        "".join(combo)
        for n in (1, 2, 3)
        for combo in itertools.product("?>~", repeat=n)
    )
    for suffix in suffixes:
        coded = base64.urlsafe_b64encode((term + suffix).encode()).decode().rstrip("=")
        if "-" in coded or "_" in coded:
            return coded
    raise AssertionError("no URL-safe form")


def _text_forms(term: str) -> dict[str, str]:
    half = len(term) // 2
    a, b = term[:half], term[half:]
    q = '"'
    pct = "".join(f"%{ord(c):02X}" for c in term)
    return {
        "plain": term,
        "upper": term.upper(),
        "percent": pct,
        "double-percent": "".join(f"%25{ord(c):02X}" for c in term),
        "percent-lowercase": pct.lower(),
        "unicode-escape": "".join(BS + f"u{ord(c):04x}" for c in term),
        "long-unicode-escape": "".join(BS + f"U{ord(c):08x}" for c in term),
        "hex-escape": "".join(BS + f"x{ord(c):02x}" for c in term),
        "html-hex-entity": "".join(f"&#x{ord(c):x};" for c in term),
        "html-decimal-entity": "".join(f"&#{ord(c)};" for c in term),
        "fullwidth": "".join(chr(ord(c) + 0xFEE0) for c in term),
        "homoglyph": term.replace("x", chr(0x0445)),
        "zero-width-joiner": chr(0x200D).join(term),
        "zero-width-space": chr(0x200B).join(term),
        "base64": base64.b64encode(term.encode()).decode(),
        "base64-unpadded": base64.b64encode((term + "!").encode()).decode().rstrip("="),
        "base64-urlsafe": _urlsafe(term),
        "hex": term.encode().hex(),
        "base64-of-percent": base64.b64encode(pct.encode()).decode(),
        "percent-of-escape": "".join(
            f"%{b:02X}" for b in "".join(BS + f"u{ord(c):04x}" for c in term).encode()
        ),
        "split-literals": f"x = {q}{a}{q} + {q}{b}{q}",
        "split-across-lines": f"x = ({q}{a}{q}\n     {q}{b}{q})",
        "line-continuation": f"x = {q}{a}{q} {BS}\n    {q}{b}{q}",
        "bare-continuation": f"echo {a}{BS}\n{b}",
        "base64-of-base64": base64.b64encode(base64.b64encode(term.encode())).decode(),
    }


def _byte_forms(term: str) -> dict[str, bytes]:
    raw = term.encode()
    look = term.replace("x", chr(0x0445))
    return {
        "utf-16-le-bom": codecs.BOM_UTF16_LE + term.encode("utf-16-le"),
        "utf-16-be-bom": codecs.BOM_UTF16_BE + term.encode("utf-16-be"),
        "utf-16-le-no-bom": term.encode("utf-16-le"),
        "utf-16-be-no-bom": term.encode("utf-16-be"),
        "utf-16-odd-offset": b"\x00" + term.encode("utf-16-le"),
        "utf-32-le-bom": codecs.BOM_UTF32_LE + term.encode("utf-32-le"),
        "utf-32-be-bom": codecs.BOM_UTF32_BE + term.encode("utf-32-be"),
        "utf-32-le-no-bom": term.encode("utf-32-le"),
        "utf-32-be-no-bom": term.encode("utf-32-be"),
        "binary": b"\x89PNG\r\n\x1a\n\x00\x00" + raw + b"\x00\xff",
        "invalid-utf8": b"\xc3\x28 " + raw + b" \xc3",
        "irregular-nul": b"\x00".join(
            bytes([c]) + b"\x00" * (i % 3) for i, c in enumerate(raw)
        ),
        # A look-alike letter has no NUL byte in a wide encoding, so only the
        # matching decoder at the matching alignment can read these.
        **{
            f"homoglyph-{enc}-at-{shift}": b"\x00" * shift + look.encode(enc)
            for enc in ("utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be")
            for shift in range(4 if "32" in enc else 2)
        },
    }


WIN = _j(BS, "C:", "Users", "someone", "x")
POSIX = _j("/", "", "home", "someone", "x")

# (built-in shape, expected label)
PATH_FORMS: dict[str, tuple[str, str]] = {
    "windows-one-backslash": (WIN, "windows-user-home-path"),
    "windows-two-backslashes": (WIN.replace(BS, BS * 2), "windows-user-home-path"),
    "windows-four-backslashes": (WIN.replace(BS, BS * 4), "windows-user-home-path"),
    "windows-forward-slash": (WIN.replace(BS, "/"), "windows-user-home-path"),
    "windows-percent": (
        "".join(f"%{ord(c):02X}" if c in ":" + BS else c for c in WIN),
        "windows-user-home-path",
    ),
    "windows-double-percent": (
        "".join(f"%25{ord(c):02X}" if c in ":" + BS else c for c in WIN),
        "windows-user-home-path",
    ),
    "windows-base64": (
        base64.b64encode(WIN.encode()).decode(),
        "windows-user-home-path",
    ),
    "windows-fullwidth-letters": (
        WIN.replace("Users", "".join(chr(ord(c) + 0xFEE0) for c in "Users")),
        "windows-user-home-path",
    ),
    "posix": (POSIX, "posix-home-path"),
    "posix-hex": (POSIX.encode().hex(), "posix-home-path"),
    "posix-html": (POSIX.replace("/", "&#47;"), "posix-home-path"),
    "macos": (_j("/", "", "Users", "someone", "x"), "macos-user-home-path"),
    "wsl-mount": (_j("/", "", "mnt", "c", "Users", "someone"), "wsl-mount-home-path"),
    "wsl-network-dollar": (
        BS * 2 + _j(BS, "wsl$", "Ubuntu", "tmp"),
        "wsl-network-path",
    ),
    "wsl-network-localhost": (
        BS * 2 + _j(BS, "wsl.localhost", "Ubuntu"),
        "wsl-network-path",
    ),
    "wsl-network-forward": (
        "//" + _j("/", "wsl.localhost", "Ubuntu"),
        "wsl-network-path",
    ),
    "wsl-network-doubled": (
        BS * 4 + _j(BS * 2, "wsl$", "Ubuntu"),
        "wsl-network-path",
    ),
    "tilde-user": ("~" + _j("/", "someone", "x"), "tilde-user-path"),
    "home-variable": ("$" + _j("/", "HOME", "x"), "home-variable-path"),
    "home-variable-braced": ("${" + _j("/", "HOME}", "x"), "home-variable-path"),
    "home-variable-windows": ("%" + "USERPROFILE%" + BS + "x", "home-variable-path"),
    "home-variable-powershell": (
        "$" + "env:USERPROFILE" + BS + "x",
        "home-variable-path",
    ),
    "private-ipv4": (_j(".", "192", "168", "4", "20"), "private-ipv4"),
    "link-local-ipv4": (_j(".", "169", "254", "7", "1"), "private-ipv4"),
    "private-ipv6": (_j(":", "fd12", "3456", "", "1"), "private-ipv6"),
    "link-local-ipv6": (_j(":", "fe80", "", "1"), "private-ipv6"),
    "link-local-ipv6-upper": (_j(":", "FE80", "", "A"), "private-ipv6"),
    "ipv4-fullwidth-digits": (
        "".join(
            chr(ord(c) + 0xFEE0) if c.isdigit() else c
            for c in _j(".", "10", "1", "2", "3")
        ),
        "private-ipv4",
    ),
}

# Text that must stay clean: home-relative paths with no user, public
# addresses, digests, ordinary words that are also valid base64.
CLEAN = [
    "see ~/.config/tool for the settings",
    "cd ~ and run it",
    "$" + "HOME is set by the shell",
    "C:/Temp/x and D:" + BS + "work",
    _j(".", "8", "8", "8", "8") + " and " + _j(":", "2001", "db8", "", "1"),
    "a" * 64,
    "the test self None True False main from import",
    "feature/branch-name and v1.2.3",
    "plain prose with no secrets in it",
]


def _env(denylist: str | None = TERM) -> dict:
    env = {k: v for k, v in os.environ.items() if k != "LEAK_DENYLIST"}
    if denylist is not None:
        env["LEAK_DENYLIST"] = denylist
    return env


def _scan(
    args: list[str], cwd: Path, stdin: str | None = None, denylist: str | None = TERM
):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=cwd,
        env=_env(denylist),
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.name", "t")
    _git(tmp_path, "config", "user.email", "t@example.invalid")
    _git(tmp_path, "config", "core.autocrlf", "false")
    (tmp_path / "base.md").write_text("clean\n", encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    return tmp_path


TEXT = _text_forms(TERM)
BYTES = _byte_forms(TERM)


def _assert_quiet(r: subprocess.CompletedProcess[str]) -> None:
    out = (r.stdout + r.stderr).casefold()
    assert TERM not in out and "someone" not in out, "output repeated the matched text"


@pytest.mark.parametrize("form", sorted(TEXT))
def test_each_text_form_is_found_in_file_and_text_modes(
    tmp_path: Path, form: str
) -> None:
    f = tmp_path / "note.md"
    f.write_text("intro\n" + TEXT[form] + "\n", encoding="utf-8")
    r = _scan([str(f)], tmp_path)
    assert r.returncode == 1 and "denylist entry 1" in r.stdout, (form, r.stdout)
    _assert_quiet(r)
    r = _scan(["--text", "pull request"], tmp_path, stdin=TEXT[form] + "\n")
    assert r.returncode == 1 and "pull request:1: denylist entry 1" in r.stdout, (
        form,
        r.stdout,
    )
    _assert_quiet(r)


def test_short_base64_of_a_short_entry_is_found(tmp_path: Path) -> None:
    short = TERM[:3]
    coded = base64.b64encode(short.encode()).decode()
    assert len(coded) == 4
    r = _scan(["--text", "t"], tmp_path, stdin="token " + coded + "\n", denylist=short)
    assert r.returncode == 1 and "t:1: denylist entry 1" in r.stdout, r.stdout


@pytest.mark.parametrize("form", sorted(BYTES))
def test_each_byte_form_is_found_in_file_mode(tmp_path: Path, form: str) -> None:
    f = tmp_path / "blob.bin"
    f.write_bytes(BYTES[form])
    r = _scan([str(f)], tmp_path)
    assert r.returncode == 1 and "denylist entry 1" in r.stdout, (form, r.stdout)
    _assert_quiet(r)


@pytest.mark.parametrize("form", sorted(PATH_FORMS))
def test_each_path_and_address_form_is_found(tmp_path: Path, form: str) -> None:
    text, label = PATH_FORMS[form]
    r = _scan(["--text", "t"], tmp_path, stdin="see " + text + " here\n")
    assert r.returncode == 1 and f"t:1: {label}" in r.stdout, (form, r.stdout)
    _assert_quiet(r)


@pytest.mark.parametrize("text", CLEAN, ids=range(len(CLEAN)))
def test_clean_text_stays_clean(tmp_path: Path, text: str) -> None:
    r = _scan(["--text", "t"], tmp_path, stdin=text + "\n")
    assert r.returncode == 0, (text, r.stdout)


def _plant_everything(repo: Path) -> dict[str, int]:
    """One text file with every text and path form on its own line, and one file per byte form."""
    lines = ["clean header"]
    where: dict[str, int] = {}
    for name in sorted(TEXT):
        where[f"text:{name}"] = len(lines) + 1
        lines += TEXT[name].split("\n")
        lines.append("")
    for name in sorted(PATH_FORMS):
        where[f"path:{name}"] = len(lines) + 1
        lines.append("see " + PATH_FORMS[name][0] + " here")
        lines.append("")
    (repo / "forms.md").write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    for name, data in BYTES.items():
        (repo / f"blob-{name}.bin").write_bytes(data)
    return where


def _assert_every_form(out: str, prefix: str, where: dict[str, int]) -> None:
    hit_lines = {
        int(line.split(":")[1])
        for line in out.splitlines()
        if line.startswith(prefix) and line.count(":") >= 2
    }
    missed = [k for k, n in where.items() if n not in hit_lines]
    assert not missed, missed
    for name in BYTES:
        assert f"blob-{name}.bin" in out, name


def test_every_form_is_found_in_staged_and_ci_modes(repo: Path) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    where = _plant_everything(repo)
    _git(repo, "add", ".")
    r = _scan(["--staged"], repo)
    assert r.returncode == 1
    _assert_every_form(r.stdout, "forms.md:", where)
    _assert_quiet(r)
    _git(repo, "commit", "-qm", "plant")
    r = _scan(["--ci", "--base", base], repo)
    assert r.returncode == 1
    _assert_every_form(r.stdout, "forms.md @ ", where)
    _assert_quiet(r)


def test_a_binary_file_is_judged_on_what_the_change_adds(repo: Path) -> None:
    old = BYTES["utf-16-le-bom"]
    (repo / "wide.txt").write_bytes(old)
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "wide with the term")
    base = _git(repo, "rev-parse", "HEAD")
    # The same term again plus clean text: no new hit, so the edit passes.
    (repo / "wide.txt").write_bytes(old + "clean".encode("utf-16-le"))
    _git(repo, "commit", "-qam", "edit wide")
    r = _scan(["--ci", "--base", base], repo)
    assert r.returncode == 0, r.stdout
    # A new kind of hit in the same file fails.
    (repo / "wide.txt").write_bytes(old + POSIX.encode("utf-16-le"))
    _git(repo, "commit", "-qam", "add a path")
    r = _scan(["--ci", "--base", base], repo)
    assert r.returncode == 1 and "posix-home-path" in r.stdout, r.stdout


ATTRIBUTES = {
    "minus-diff": ("* -diff\n", {}),
    "binary-macro": ("* binary\n", {}),
    "textconv-driver": ("* diff=hide\n", {"diff.hide.textconv": "true"}),
    "binary-driver": ("* diff=hide\n", {"diff.hide.binary": "true"}),
    "external-diff": ("", {"diff.external": "true"}),
}


@pytest.mark.parametrize("attr", sorted(ATTRIBUTES))
@pytest.mark.parametrize("same_commit", [False, True], ids=["before", "same-commit"])
def test_repository_attributes_cannot_hide_added_lines(
    repo: Path, attr: str, same_commit: bool
) -> None:
    text, config = ATTRIBUTES[attr]
    for key, value in config.items():
        _git(repo, "config", key, value)
    if text:
        (repo / ".gitattributes").write_text(text, encoding="utf-8")
        if not same_commit:
            _git(repo, "add", ".gitattributes")
            _git(repo, "commit", "-qm", "attributes")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "note.md").write_text(
        "clean\nsee " + POSIX + " and " + TERM + "\n", encoding="utf-8"
    )
    _git(repo, "add", ".")
    r = _scan(["--staged"], repo)
    assert r.returncode == 1, (attr, r.stdout)
    assert "note.md:2: posix-home-path" in r.stdout, r.stdout
    assert "note.md:2: denylist entry 1" in r.stdout, r.stdout
    _git(repo, "commit", "-qm", "note")
    r = _scan(["--ci", "--base", base], repo)
    assert r.returncode == 1, (attr, r.stdout)
    assert ":2: posix-home-path" in r.stdout and ":2: denylist entry 1" in r.stdout, (
        r.stdout
    )


def test_a_clean_change_in_every_mode_passes(repo: Path) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "clean.md").write_text("\n".join(CLEAN) + "\n", encoding="utf-8")
    _git(repo, "add", ".")
    assert _scan(["--staged"], repo).returncode == 0
    _git(repo, "commit", "-qm", "clean")
    r = _scan(["--ci", "--base", base], repo)
    assert r.returncode == 0, r.stdout
    r = _scan([str(repo / "clean.md")], repo)
    assert r.returncode == 0, r.stdout


def test_a_denylist_entry_is_normalised_like_the_text(tmp_path: Path) -> None:
    wide_entry = "".join(chr(ord(c) + 0xFEE0) for c in TERM)
    r = _scan(
        ["--text", "t"], tmp_path, stdin="see " + TERM + "\n", denylist=wide_entry
    )
    assert r.returncode == 1 and "t:1: denylist entry 1" in r.stdout, r.stdout


def test_a_binary_file_is_not_also_judged_line_by_line(repo: Path) -> None:
    # The hit is already in the old version; the text diff of the added line
    # repeats it, but only hits the new version adds over the old one count.
    (repo / "data.bin").write_bytes(b"\x00head " + TERM.encode() + b"\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "binary with the term")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "data.bin").write_bytes(
        b"\x00head " + TERM.encode() + b"\nagain " + TERM.encode() + b"\n"
    )
    _git(repo, "commit", "-qam", "repeat the term")
    r = _scan(["--ci", "--base", base], repo)
    assert r.returncode == 0, r.stdout
