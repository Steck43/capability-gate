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


@pytest.mark.parametrize("glued", ["{n}Review", "the{n}", "x_{n}_1", "{n}.local"])
def test_name_glued_to_other_text_fails(repo: Path, glued: str) -> None:
    f = _write(repo, glued.format(n=SYNTHETIC_NAME) + "\n")
    r = _run([str(f)], repo, denylist=SYNTHETIC_NAME)
    assert r.returncode == 1, r.stdout


def test_regex_entry_can_keep_word_boundaries(repo: Path) -> None:
    f = _write(repo, f"the {SYNTHETIC_NAME}function helper\n")
    r = _run([str(f)], repo, denylist="re:\\b" + SYNTHETIC_NAME + "\\b")
    assert r.returncode == 0, r.stdout
    f = _write(repo, f"the {SYNTHETIC_NAME} helper\n")
    r = _run([str(f)], repo, denylist="re:\\b" + SYNTHETIC_NAME + "\\b")
    assert r.returncode == 1, r.stdout


def test_home_path_without_trailing_slash_fails(repo: Path) -> None:
    f = _write(repo, "cd " + "/" + "home" + "/someone\n")
    r = _run([str(f)], repo, denylist=SYNTHETIC_NAME)
    assert r.returncode == 1, r.stdout
    assert "posix-home-path" in r.stdout


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
    assert "other.md @ " in r.stdout
    assert ":1: windows-user-home-path" in r.stdout


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


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


def test_ci_mode_catches_a_name_added_then_removed(repo: Path) -> None:
    _write(repo, "clean\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "base")
    base = _git(repo, "rev-parse", "HEAD")
    _write(repo, f"clean\n{SYNTHETIC_NAME}\n")
    _git(repo, "commit", "-qam", "add")
    _write(repo, "clean\n")
    _git(repo, "commit", "-qam", "remove")
    assert _git(repo, "diff", f"{base}..HEAD") == ""
    r = _run(["--ci", "--base", base], repo, denylist=SYNTHETIC_NAME)
    assert r.returncode == 1, r.stdout
    assert ":2: denylist entry 1" in r.stdout


def test_non_ascii_file_name_is_scanned(repo: Path) -> None:
    f = repo / "h_ünicode note.md"
    f.write_text(f"{SYNTHETIC_NAME}\n", encoding="utf-8")
    _git(repo, "add", ".")
    r = _run(["--staged"], repo, denylist=SYNTHETIC_NAME)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "nicode note.md:1: denylist entry 1" in r.stdout


def test_quoted_header_is_unquoted() -> None:
    sys.path.insert(0, str(SCRIPT.parent))
    import leak_denylist_scan as scan

    bs = chr(92)
    header = '+++ "b/h_' + bs + "303" + bs + "274 x" + bs + 't.md"'
    assert scan._target(header) == "h_ü x\t.md"
    with pytest.raises(SystemExit):
        scan._target("+++ c/unexpected")


def test_text_mode_scans_stdin(repo: Path) -> None:
    env = {k: v for k, v in os.environ.items() if k != "LEAK_DENYLIST"}
    env["LEAK_DENYLIST"] = SYNTHETIC_NAME
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--text", "pull request"],
        input=f"Title\n\nThanks to {SYNTHETIC_NAME}Review\n",
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 1
    assert "pull request:3: denylist entry 1" in r.stdout


def test_text_mode_fails_closed_without_list(repo: Path) -> None:
    env = {k: v for k, v in os.environ.items() if k != "LEAK_DENYLIST"}
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--text", "pull request"],
        input="clean title\n",
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 1
    assert "denylist not configured" in r.stdout


# --- the scanner never prints a raw matched path or name (brief 82-41b P4) --------
# The fake term stands in for a private name. It sits in a file name, alone or
# beside a content hit, in every mode; no output stream may carry it.

FAKE = "zqx" + "wvk"


def _commit_all(repo: Path, message: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)


@pytest.mark.parametrize(
    ("content", "mode"),
    [
        pytest.param("clean text\n", "ci", id="name-only-ci"),
        pytest.param(f"{SYNTHETIC_PRIVATE_IP}\n", "ci", id="name-and-content-ci"),
        pytest.param("clean text\n", "staged", id="name-only-staged"),
        pytest.param(
            f"{SYNTHETIC_POSIX_PATH}\n", "staged", id="name-and-content-staged"
        ),
        pytest.param("clean text\n", "tree", id="name-only-tree"),
        pytest.param(f"{SYNTHETIC_PRIVATE_IP}\n", "tree", id="name-and-content-tree"),
        pytest.param(f"{SYNTHETIC_PRIVATE_IP}\n", "files", id="name-and-content-files"),
        pytest.param("clean text\n", "files", id="name-only-files"),
    ],
)
def test_a_matched_file_name_never_reaches_the_output(
    repo: Path, content: str, mode: str
) -> None:
    (repo / "base.md").write_text("base\n", encoding="utf-8")
    _commit_all(repo, "base")
    base = _git(repo, "rev-parse", "HEAD")
    name = f"notes-{FAKE}.md"
    (repo / name).write_text(content, encoding="utf-8")
    if mode == "staged":
        _git(repo, "add", "-A")
        args = ["--staged"]
    elif mode == "ci":
        _commit_all(repo, "add notes")
        args = ["--ci", "--base", base]
    elif mode == "tree":
        _commit_all(repo, "add notes")
        args = ["--tree"]
    else:
        args = [name]
    r = _run(args, repo, denylist=FAKE)
    assert r.returncode == 1, r.stdout + r.stderr
    assert FAKE not in (r.stdout + r.stderr).lower(), r.stdout + r.stderr


def test_a_git_failure_never_echoes_a_path(repo: Path) -> None:
    r = _run(["--ci", "--base", f"{FAKE}-missing-ref"], repo, denylist=FAKE)
    assert r.returncode == 2, r.stdout + r.stderr
    assert FAKE not in (r.stdout + r.stderr).lower(), r.stdout + r.stderr
