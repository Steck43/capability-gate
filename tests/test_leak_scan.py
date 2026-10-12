"""Leak scan: a name or a personal path in the scanned text fails the check.

Every leak fixture is assembled at runtime so this file cannot trip the scan
it tests.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "leak_denylist_scan.py"

SYNTHETIC_NAME = "Ze" + "ta"
SYNTHETIC_WIN_PATH = "C:" + "\\" + "Users" + "\\" + "someone" + "\\" + "x"
SYNTHETIC_WIN_PATH_DOUBLED = SYNTHETIC_WIN_PATH.replace("\\", "\\\\")
SYNTHETIC_POSIX_PATH = "/" + "home" + "/someone/x"
SYNTHETIC_PRIVATE_IP = "192" + ".168.4.20"


def _run(
    args: list[str], cwd: Path, denylist: str | None
) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if k != "LEAK_DENYLIST"}
    if denylist is not None:
        env["LEAK_DENYLIST"] = denylist
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for k, v in (("user.name", "t"), ("user.email", "t@example.invalid")):
        subprocess.run(["git", "-C", str(tmp_path), "config", k, v], check=True)
    return tmp_path


def _write(repo: Path, text: str) -> Path:
    f = repo / "doc.md"
    f.write_text(text, encoding="utf-8")
    return f


@pytest.mark.parametrize(
    "leak",
    [
        SYNTHETIC_WIN_PATH,
        SYNTHETIC_WIN_PATH_DOUBLED,
        SYNTHETIC_POSIX_PATH,
        SYNTHETIC_PRIVATE_IP,
    ],
    ids=["win-path", "win-path-doubled", "posix-path", "private-ip"],
)
def test_builtin_shape_fails(repo: Path, leak: str) -> None:
    f = _write(repo, f"clean line\nsee {leak} for details\n")
    r = _run([str(f)], repo, denylist=SYNTHETIC_NAME)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "doc.md:2:" in r.stdout


def test_denylisted_name_fails_and_is_redacted(repo: Path) -> None:
    f = _write(repo, f"reviewed by {SYNTHETIC_NAME} last night\n")
    r = _run([str(f)], repo, denylist=f"# names\n{SYNTHETIC_NAME}\n")
    assert r.returncode == 1
    assert "doc.md:1: denylist entry 1" in r.stdout
    assert SYNTHETIC_NAME.lower() not in (r.stdout + r.stderr).lower()


def test_name_matches_whole_word_only(repo: Path) -> None:
    f = _write(repo, f"the {SYNTHETIC_NAME}function helper\n")
    r = _run([str(f)], repo, denylist=SYNTHETIC_NAME)
    assert r.returncode == 0, r.stdout


def test_clean_text_passes(repo: Path) -> None:
    f = _write(repo, "the gate denies by default\nC:/tmp/x and 8.8.8.8 are fine\n")
    r = _run([str(f)], repo, denylist=SYNTHETIC_NAME)
    assert r.returncode == 0, r.stdout + r.stderr


def test_local_file_is_read_when_env_unset(repo: Path) -> None:
    (repo / ".git" / "info").mkdir(exist_ok=True)
    (repo / ".git" / "info" / "leak-denylist").write_text(
        SYNTHETIC_NAME + "\n", encoding="utf-8"
    )
    f = _write(repo, f"{SYNTHETIC_NAME}\n")
    r = _run([str(f)], repo, denylist=None)
    assert r.returncode == 1


def test_ci_mode_fails_closed_without_list(repo: Path) -> None:
    _write(repo, "clean\n")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "base"], check=True)
    for unset in (None, "", "\n# only a comment\n"):
        r = _run(["--ci", "--base", "HEAD"], repo, denylist=unset)
        assert r.returncode == 1, (unset, r.stdout)
        assert "denylist not configured" in r.stdout


def test_ci_mode_scans_added_lines_and_messages(repo: Path) -> None:
    _write(repo, f"old line mentions {SYNTHETIC_NAME}\n")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "base"], check=True)
    base = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    # A hit already on the base is out of scope for the diff-only CI check.
    (repo / "other.md").write_text("new clean line\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "add other"], check=True)
    r = _run(["--ci", "--base", base], repo, denylist=SYNTHETIC_NAME)
    assert r.returncode == 0, r.stdout

    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            f"thanks {SYNTHETIC_NAME}",
        ],
        check=True,
    )
    r = _run(["--ci", "--base", base], repo, denylist=SYNTHETIC_NAME)
    assert r.returncode == 1
    assert "message:1: denylist entry 1" in r.stdout

    subprocess.run(
        ["git", "-C", str(repo), "reset", "-q", "--hard", "HEAD~1"], check=True
    )
    (repo / "other.md").write_text(f"new line {SYNTHETIC_WIN_PATH}\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "commit", "-qam", "edit"], check=True)
    r = _run(["--ci", "--base", base], repo, denylist=SYNTHETIC_NAME)
    assert r.returncode == 1
    assert "other.md:1: windows-user-home-path" in r.stdout


def test_staged_mode_scans_index(repo: Path) -> None:
    _write(repo, f"{SYNTHETIC_POSIX_PATH}\n")
    subprocess.run(["git", "-C", str(repo), "add", "doc.md"], check=True)
    r = _run(["--staged"], repo, denylist=SYNTHETIC_NAME)
    assert r.returncode == 1
    assert "doc.md:1: posix-home-path" in r.stdout


def test_staged_mode_judges_added_lines_at_real_line_numbers(repo: Path) -> None:
    _write(repo, f"line one\n{SYNTHETIC_POSIX_PATH}\nline three\n")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "base"], check=True)

    # Editing a file that already carries a hit is not itself a leak.
    _write(repo, f"line one\n{SYNTHETIC_POSIX_PATH}\nline three\nline four\n")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    r = _run(["--staged"], repo, denylist=SYNTHETIC_NAME)
    assert r.returncode == 0, r.stdout

    _write(repo, f"line one\n{SYNTHETIC_POSIX_PATH}\nline three\n{SYNTHETIC_NAME}\n")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    r = _run(["--staged"], repo, denylist=SYNTHETIC_NAME)
    assert r.returncode == 1
    assert "doc.md:4: denylist entry 1" in r.stdout
