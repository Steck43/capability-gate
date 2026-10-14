"""Leak scan, wider shapes: other home-path spellings, split strings, UTF-16,
dashes, AI trailers, file names, an empty range, and the gh pr wrapper.

Fixtures are assembled at runtime through _j so this file cannot trip the scan.
"""

from __future__ import annotations

import base64
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "leak_denylist_scan.py"
GH_WRAPPER = ROOT / "scripts" / "gh_pr.py"
BS = chr(92)


def _j(sep: str, *parts: str) -> str:
    return sep.join(parts)


NAME = _j("", "Ze", "ta")
IP = _j(".", "192", "168", "4", "20")
TRAILER = _j("", "Co-authored", "-by: Claude <noreply@example.invalid>")


def _env(denylist: str | None = NAME) -> dict:
    env = {k: v for k, v in os.environ.items() if k != "LEAK_DENYLIST"}
    if denylist is not None:
        env["LEAK_DENYLIST"] = denylist
    return env


def _scan(args: list[str], cwd: Path, stdin: str | None = None):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=cwd,
        env=_env(),
        input=stdin,
        capture_output=True,
        text=True,
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
    (tmp_path / "base.md").write_text("clean\n", encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    return tmp_path


HOME_SHAPES = {
    "windows-forward-slash": _j("/", "C:", "Users", "someone", "x"),
    "macos-home": _j("/", "", "Users", "someone", "x"),
    "wsl-mount-home": _j("/", "", "mnt", "c", "Users", "someone", "x"),
    "wsl-unc-home": BS * 2 + _j(BS, "wsl$", "Ubuntu", "home", "someone", "x"),
    "wsl-localhost-home": BS * 2 + _j(BS, "wsl.localhost", "Ubuntu", "home", "someone"),
}


@pytest.mark.parametrize("shape", sorted(HOME_SHAPES))
def test_home_path_spelling_fails(tmp_path: Path, shape: str) -> None:
    f = tmp_path / "doc.md"
    f.write_text(f"see {HOME_SHAPES[shape]} here\n", encoding="utf-8")
    r = _scan([str(f)], tmp_path)
    assert r.returncode == 1, r.stdout


def test_split_string_literals_are_joined(tmp_path: Path) -> None:
    q = '"'
    path_line = _j(
        f"{q} + {q}", "p = " + q + "C:", BS * 2 + "Users" + BS * 2 + "someone" + q
    )
    name_line = _j(f"{q} {q}", "n = " + q + "Ze", "ta" + q)
    f = tmp_path / "x.py"
    f.write_text(path_line + "\n" + name_line + "\n", encoding="utf-8")
    r = _scan([str(f)], tmp_path)
    assert r.returncode == 1, r.stdout
    assert "x.py:1: windows-user-home-path (split string)" in r.stdout
    assert "x.py:2: denylist entry 1 (split string)" in r.stdout


def test_utf16_file_is_scanned_in_file_and_ci_modes(repo: Path) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    f = repo / "wide.txt"
    f.write_text(f"host {IP}\n", encoding="utf-16")
    r = _scan([str(f)], repo)
    assert r.returncode == 1, r.stdout
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "add wide file")
    r = _scan(["--ci", "--base", base], repo)
    assert r.returncode == 1, r.stdout
    assert "wide.txt (UTF-16)" in r.stdout


@pytest.mark.parametrize(
    "dash, label", [(chr(0x2014), "em-dash"), (chr(0x2013), "en-dash")]
)
def test_dashes_fail_in_added_lines_and_messages(
    repo: Path, dash: str, label: str
) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "note.md").write_text(f"one {dash} two\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", f"subject {dash} here")
    r = _scan(["--ci", "--base", base], repo)
    assert r.returncode == 1, r.stdout
    assert "note.md @ " in r.stdout and f":1: {label}" in r.stdout
    assert f"message:1: {label}" in r.stdout


def test_ai_trailer_fails_in_message_and_pr_text(repo: Path) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "subject\n\n" + TRAILER)
    r = _scan(["--ci", "--base", base], repo)
    assert r.returncode == 1, r.stdout
    assert "ai-trailer" in r.stdout
    r = _scan(["--text", "pull request"], repo, stdin="Title\n\n" + TRAILER + "\n")
    assert r.returncode == 1, r.stdout
    assert "pull request:3: ai-trailer" in r.stdout


def test_new_file_name_is_scanned(repo: Path) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    (repo / f"{NAME}-notes.md").write_text("clean\n", encoding="utf-8")
    _git(repo, "add", ".")
    r = _scan(["--staged"], repo)
    assert r.returncode == 1, r.stdout
    assert "(file name)" in r.stdout
    _git(repo, "commit", "-qm", "add notes")
    r = _scan(["--ci", "--base", base], repo)
    assert r.returncode == 1, r.stdout
    assert "(file name)" in r.stdout


def test_empty_range_fails_in_the_script(repo: Path) -> None:
    r = _scan(["--ci", "--base", "HEAD"], repo)
    assert r.returncode == 3, (r.returncode, r.stdout)
    assert "empty range" in r.stdout


def _fake_gh(tmp_path: Path) -> tuple[Path, Path]:
    calls = tmp_path / "gh-calls.txt"
    fake = tmp_path / "fake_gh.py"
    fake.write_text(
        "import sys\n"
        f"open({str(calls)!r}, 'a', encoding='utf-8').write(repr(sys.argv[1:]) + chr(10))\n",
        encoding="utf-8",
    )
    return fake, calls


def _wrapper(tmp_path: Path, *args: str, denylist: str | None = NAME):
    fake, calls = _fake_gh(tmp_path)
    env = _env(denylist)
    env["GH_PR_GH"] = str(fake)
    r = subprocess.run(
        [sys.executable, str(GH_WRAPPER), *args],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return r, calls


def test_gh_wrapper_blocks_a_leaking_title(tmp_path: Path) -> None:
    r, calls = _wrapper(
        tmp_path, "create", "--title", f"Fix for {NAME}", "--body", "ok"
    )
    assert r.returncode == 1, r.stdout + r.stderr
    assert not calls.exists()


def test_gh_wrapper_blocks_a_leaking_body_file(tmp_path: Path) -> None:
    body = tmp_path / "body.md"
    body.write_text("Summary\n\n" + TRAILER + "\n", encoding="utf-8")
    r, calls = _wrapper(tmp_path, "edit", "81", "--body-file", str(body))
    assert r.returncode == 1, r.stdout + r.stderr
    assert not calls.exists()


def test_gh_wrapper_passes_clean_text_through(tmp_path: Path) -> None:
    body = tmp_path / "body.md"
    body.write_text("Summary\n\nPlain text.\n", encoding="utf-8")
    r, calls = _wrapper(
        tmp_path,
        "create",
        "--title",
        "Plain title",
        "--body-file",
        str(body),
        "--base",
        "main",
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert calls.read_text(encoding="utf-8").strip() == repr(
        [
            "pr",
            "create",
            "--title",
            "Plain title",
            "--body-file",
            str(body),
            "--base",
            "main",
        ]
    )


def test_added_line_that_looks_like_a_diff_header_is_scanned(repo: Path) -> None:
    (repo / "notes.md").write_text("++ b/" + NAME + "\n", encoding="utf-8")
    _git(repo, "add", "notes.md")
    _git(repo, "commit", "-qm", "add a line")
    r = _scan(["--ci", "--base", "HEAD~1"], repo)
    assert r.returncode == 1, r.stdout + r.stderr


def test_encoded_name_is_scanned(tmp_path: Path) -> None:
    coded = base64.b64encode(NAME.encode()).decode()
    target = tmp_path / "note.md"
    target.write_text(coded + "\n", encoding="utf-8")
    r = _scan([str(target)], tmp_path)
    assert r.returncode == 1, r.stdout


def test_attached_short_flag_is_scanned(tmp_path: Path) -> None:
    r, calls = _wrapper(tmp_path, "create", "-t" + "Fix for " + NAME, "-b" + "ok")
    assert r.returncode == 1, r.stdout + r.stderr
    assert not calls.exists()


@pytest.mark.parametrize("flag", ["--fill", "--editor", "-T", "--web"])
def test_unscanned_compose_modes_are_refused(tmp_path: Path, flag: str) -> None:
    r, calls = _wrapper(tmp_path, "create", flag, "--title", "Plain")
    assert r.returncode == 2, r.stdout + r.stderr
    assert not calls.exists()


def test_each_gitleaks_rule_has_a_hit_and_a_miss() -> None:
    rules = {
        item["id"]: item["regex"]
        for item in tomllib.loads(
            (ROOT / ".gitleaks.toml").read_text(encoding="utf-8")
        )["rules"]
    }
    samples = {
        "windows-user-home-path": (
            _j("/", "C:", "Users", "someone", "x"),
            "C:/Temp/x",
        ),
        "macos-user-home-path": (_j("/", "", "Users", "someone"), "/opt/share"),
        "wsl-mount-home-path": (
            _j("/", "", "mnt", "c", "Users", "someone"),
            "/mnt/c/tmp",
        ),
        "wsl-network-home-path": (
            BS * 2 + _j(BS, "wsl$", "Ubuntu", "home", "someone"),
            "wsl-docs",
        ),
        "posix-home-path": (_j("/", "", "home", "someone"), "/opt/home"),
        "private-ipv4": (_j(".", "10", "1", "2", "3"), _j(".", "8", "8", "8", "8")),
    }
    assert set(samples) == set(rules)
    for rule_id, (hit, miss) in samples.items():
        pattern = re.compile(rules[rule_id])
        assert pattern.search(hit), rule_id
        assert pattern.search(miss) is None, rule_id


def test_gh_wrapper_fails_closed_without_list(tmp_path: Path) -> None:
    r, calls = _wrapper(
        tmp_path, "create", "--title", "Plain", "--body", "ok", denylist=None
    )
    assert r.returncode == 1
    assert not calls.exists()
