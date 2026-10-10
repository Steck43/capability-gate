"""Claude Code adapter: every way the hook can fail ends in a block.

Claude Code blocks a tool call only on hook exit 2 or a JSON deny. A hook that
crashes, cannot start, or times out does not block: the tool runs. So each
failure path inside the adapter is pinned here to exit 2, and each test names
the branch whose removal turns it red.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOF = Path(__file__).resolve().parents[1]
HOOK = ROOF / "adapters" / "claude_code_hook.py"


def _policy(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "allowlist.yaml"
    p.write_text(body, encoding="utf-8")
    return p


def _grant_read(project: Path) -> str:
    root = str(project).replace("\\", "/")
    return (
        "require_approval: [Bash, PowerShell]\n"
        "skills:\n"
        "  UNLABELED:\n"
        "    tools: [Read, Glob, Grep]\n"
        f"    paths: ['{root}/**']\n"
    )


def _env(tmp_path: Path, allowlist: Path | str, **extra: str) -> dict:
    env = dict(os.environ)
    env["CG_CC_ALLOWLIST"] = str(allowlist)
    env["CG_CC_LOG"] = str(tmp_path / "log" / "claude-code.jsonl")
    env.update(extra)
    return env


def _call(
    tool: str,
    tool_input: dict,
    cwd: Path,
    tool_use_id: str = "toolu_1",
    event: str = "PreToolUse",
) -> str:
    return json.dumps(
        {
            "session_id": "s1",
            "cwd": str(cwd),
            "hook_event_name": event,
            "tool_name": tool,
            "tool_input": tool_input,
            "tool_use_id": tool_use_id,
        }
    )


def _run(
    stdin: str, env: dict, *args: str, timeout: float = 30
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(HOOK), *args],
        input=stdin,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _denied(r: subprocess.CompletedProcess) -> bool:
    # A missing script also exits 2 under Python, so a deny only counts when the
    # adapter itself wrote its reason.
    return r.returncode == 2 and "capability-gate:" in r.stderr


@pytest.fixture
def project(tmp_path: Path) -> Path:
    p = tmp_path / "proj"
    (p / "notes").mkdir(parents=True)
    (p / "notes" / "a.txt").write_text("hello", encoding="utf-8")
    return p


# --- allow and deny on the plain path -------------------------------------


def test_read_inside_allowed(tmp_path, project):
    env = _env(tmp_path, _policy(tmp_path, _grant_read(project)))
    r = _run(
        _call("Read", {"file_path": str(project / "notes" / "a.txt")}, project), env
    )
    assert r.returncode == 0, r.stderr
    assert (
        r.stdout == ""
    )  # allow is "no decision": Claude Code's own permissions still apply


def test_write_outside_denied(tmp_path, project):
    env = _env(tmp_path, _policy(tmp_path, _grant_read(project)))
    r = _run(
        _call(
            "Write",
            {"file_path": str(tmp_path / "outside.txt"), "content": "x"},
            project,
        ),
        env,
    )
    assert _denied(r)


def test_glob_and_grep_in_project_allowed(tmp_path, project):
    env = _env(tmp_path, _policy(tmp_path, _grant_read(project)))
    for tool, ti in (
        ("Glob", {"pattern": "**/*.txt"}),
        ("Grep", {"pattern": "hello"}),
        ("Grep", {"pattern": "hello", "path": str(project / "notes")}),
    ):
        r = _run(_call(tool, ti, project), env)
        assert r.returncode == 0, (tool, ti, r.stderr)


def test_read_outside_denied(tmp_path, project):
    env = _env(tmp_path, _policy(tmp_path, _grant_read(project)))
    r = _run(_call("Read", {"file_path": str(tmp_path / "secret.txt")}, project), env)
    assert _denied(r)


def test_sibling_prefix_denied(tmp_path, project):
    evil = tmp_path / "proj-evil"
    evil.mkdir()
    env = _env(tmp_path, _policy(tmp_path, _grant_read(project)))
    r = _run(_call("Read", {"file_path": str(evil / "a.txt")}, project), env)
    assert _denied(r)


def test_relative_path_resolves_against_cwd(tmp_path, project):
    env = _env(tmp_path, _policy(tmp_path, _grant_read(project)))
    r = _run(_call("Read", {"file_path": "notes/a.txt"}, project), env)
    assert r.returncode == 0, r.stderr
    r = _run(_call("Read", {"file_path": "../secret.txt"}, project), env)
    assert _denied(r)


@pytest.mark.skipif(os.name != "nt", reason="Windows path spellings")
def test_windows_spellings_match(tmp_path, project):
    env = _env(tmp_path, _policy(tmp_path, _grant_read(project)))
    target = str(project / "notes" / "a.txt")
    for spelling in (target, target.replace("\\", "/"), target.upper(), target.lower()):
        r = _run(_call("Read", {"file_path": spelling}, project), env)
        assert r.returncode == 0, (spelling, r.stderr)


def test_shell_tools_denied(tmp_path, project):
    env = _env(tmp_path, _policy(tmp_path, _grant_read(project)))
    for tool in ("Bash", "PowerShell"):
        r = _run(_call(tool, {"command": "echo hi"}, project), env)
        assert _denied(r), tool


def test_ungranted_tool_denied(tmp_path, project):
    env = _env(tmp_path, _policy(tmp_path, _grant_read(project)))
    for tool in ("WebFetch", "mcp__server__tool", "Edit"):
        r = _run(_call(tool, {"url": "https://example.com"}, project), env)
        assert _denied(r), tool


def test_unexpanded_or_escaping_paths_denied(tmp_path, project):
    env = _env(tmp_path, _policy(tmp_path, _grant_read(project)))
    for call in (
        ("Read", {"file_path": "$HOME/x"}),
        ("Read", {"file_path": "~/x"}),
        ("Glob", {"pattern": str(tmp_path / "*.txt")}),
        ("Glob", {"pattern": "../**/*.txt"}),
    ):
        r = _run(_call(call[0], call[1], project), env)
        assert _denied(r), call


def test_glob_obfuscated_climb_denied(tmp_path, project):
    """B-P2-R2-1: a plain '..' substring check is not enough."""
    env = _env(tmp_path, _policy(tmp_path, _grant_read(project)))
    for pat in ("[.][.]/*", "{..,x}/*", "{x,..}/*", "[..]/*"):
        r = _run(_call("Glob", {"pattern": pat}, project), env)
        assert _denied(r), pat


def test_glob_climb_residuals_denied(tmp_path, project):
    """K2b: denylist residuals from hostile review (nested brace, .[.], ..*)."""
    env = _env(tmp_path, _policy(tmp_path, _grant_read(project)))
    for pat in (
        ".[.]/*",
        "[.]./*",
        r"[\.][\.]/*",
        "..*",
        ".{.,x}/*",
        "{a,{..,b}}/*",
        "{{..},x}/*",
        "{C:/Windows/System32/**,safe/**}",
    ):
        r = _run(_call("Glob", {"pattern": pat}, project), env)
        assert _denied(r), pat


def test_tool_without_path_schema_denied_even_when_granted(tmp_path, project):
    """B-P2-R2-2: a granted tool missing from the adapter schema must not skip path checks."""
    root = str(project).replace("\\", "/")
    body = (
        "require_approval: []\n"
        "skills:\n"
        "  UNLABELED:\n"
        "    tools: [Read, LS, NotebookRead, mcp__server__tool]\n"
        f"    paths: ['{root}/**']\n"
    )
    env = _env(tmp_path, _policy(tmp_path, body))
    for tool, ti in (
        ("LS", {"path": str(project / "notes")}),
        ("NotebookRead", {"notebook_path": str(project / "notes" / "a.txt")}),
        ("mcp__server__tool", {"path": str(project / "notes" / "a.txt")}),
    ):
        r = _run(_call(tool, ti, project), env)
        assert _denied(r), tool


def test_deadline_inf_and_over_cap_clamped(tmp_path, project):
    """B-P2-R3-1: inf / huge deadlines must not disable the watchdog or exceed the host cap."""
    env = _env(
        tmp_path,
        _policy(tmp_path, _grant_read(project)),
        CG_CC_DEADLINE_S="inf",
    )
    r = _run(
        _call("Read", {"file_path": str(project / "notes" / "a.txt")}, project), env
    )
    # inf used to break Timer; clamp must still allow a fast Read.
    assert r.returncode == 0, r.stderr
    env = _env(
        tmp_path,
        _policy(tmp_path, _grant_read(project)),
        CG_CC_DEADLINE_S="20",
    )
    # Cap is under Claude Code's 15s hook timeout; a hung stdin must still deny.
    p = subprocess.Popen(
        [sys.executable, str(HOOK)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
    )
    try:
        p.wait(timeout=20)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()
        pytest.fail("adapter hung past the clamped deadline")
    finally:
        if p.stdin:
            p.stdin.close()
    err = p.stderr.read()
    p.stdout.close()
    p.stderr.close()
    assert p.returncode == 2
    assert "capability-gate:" in err
    assert "deadline" in err


# --- every failure path blocks ---------------------------------------------


def test_adapter_raise_blocks(tmp_path, project):
    """Removal: the top-level `except BaseException` that exits 2."""
    env = _env(tmp_path, _policy(tmp_path, _grant_read(project)))
    r = _run("{not json", env)
    assert _denied(r)
    # A log path that is a directory makes the gate's durable write raise.
    logdir = tmp_path / "logdir"
    (logdir / "claude-code.jsonl").mkdir(parents=True)
    env["CG_CC_LOG"] = str(logdir / "claude-code.jsonl")
    r = _run(
        _call("Read", {"file_path": str(project / "notes" / "a.txt")}, project), env
    )
    assert _denied(r)


def test_deadline_denies(tmp_path, project):
    """Removal: the watchdog thread. stdin stays open and is never written."""
    env = _env(
        tmp_path, _policy(tmp_path, _grant_read(project)), CG_CC_DEADLINE_S="0.5"
    )
    p = subprocess.Popen(
        [sys.executable, str(HOOK)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
    )
    # wait(), not communicate(): communicate() would close stdin and end the read.
    try:
        p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()
        pytest.fail("adapter hung past its own deadline")
    finally:
        if p.stdin:
            p.stdin.close()
    err = p.stderr.read()
    p.stdout.close()
    p.stderr.close()
    assert p.returncode == 2
    assert "capability-gate:" in err
    assert "deadline" in err


@pytest.mark.parametrize("kind", ["missing", "directory", "invalid_yaml", "bad_policy"])
def test_unreadable_allowlist_denies_all(tmp_path, project, kind):
    """Removal: the top-level except, plus the absence of any default policy."""
    if kind == "missing":
        allow = tmp_path / "nope.yaml"
    elif kind == "directory":
        allow = tmp_path / "adir"
        allow.mkdir()
    elif kind == "invalid_yaml":
        allow = _policy(tmp_path, "skills: [unclosed\n")
    else:
        allow = _policy(tmp_path, "skills: 7\n")
    env = _env(tmp_path, allow)
    r = _run(
        _call("Read", {"file_path": str(project / "notes" / "a.txt")}, project), env
    )
    assert _denied(r), kind


def test_unlabeled_not_star(tmp_path, project):
    """Removal: the literal UNLABELED skill. A '*' grant must not reach Claude Code calls."""
    root = str(project).replace("\\", "/")
    body = f"skills:\n  '*':\n    tools: [Read]\n    paths: ['{root}/**']\n"
    env = _env(tmp_path, _policy(tmp_path, body))
    r = _run(
        _call("Read", {"file_path": str(project / "notes" / "a.txt")}, project), env
    )
    assert _denied(r)


def test_single_star_grant_refused_on_windows_style(tmp_path, project):
    """A single '*' or '?' in a grant could cross a backslash on Windows; refuse to load it."""
    root = str(project).replace("\\", "/")
    body = f"skills:\n  UNLABELED:\n    tools: [Read]\n    paths: ['{root}/*']\n"
    env = _env(tmp_path, _policy(tmp_path, body))
    r = _run(
        _call("Read", {"file_path": str(project / "notes" / "a.txt")}, project), env
    )
    assert _denied(r)


# --- input changed after the check -----------------------------------------


def test_input_changed_after_check_flagged(tmp_path, project):
    """Removal: the hash comparison in --post. Detection after the fact, not prevention."""
    env = _env(tmp_path, _policy(tmp_path, _grant_read(project)))
    checked = {"file_path": str(project / "notes" / "a.txt")}
    r = _run(_call("Read", checked, project, tool_use_id="toolu_X"), env)
    assert r.returncode == 0, r.stderr
    same = _run(
        _call("Read", checked, project, tool_use_id="toolu_X", event="PostToolUse"),
        env,
        "--post",
    )
    assert same.returncode == 0 and same.stdout == "", same.stdout
    changed = {"file_path": str(tmp_path / "secret.txt")}
    r = _run(
        _call("Read", changed, project, tool_use_id="toolu_X", event="PostToolUse"),
        env,
        "--post",
    )
    out = json.loads(r.stdout)
    assert out["decision"] == "block"
    assert "changed after the check" in out["reason"]


def test_post_with_no_pre_record_flagged(tmp_path, project):
    env = _env(tmp_path, _policy(tmp_path, _grant_read(project)))
    r = _run(
        _call(
            "Read",
            {"file_path": "x"},
            project,
            tool_use_id="toolu_never",
            event="PostToolUse",
        ),
        env,
        "--post",
    )
    out = json.loads(r.stdout)
    assert out["decision"] == "block"


def test_never_emits_updated_input(tmp_path, project):
    env = _env(tmp_path, _policy(tmp_path, _grant_read(project)))
    calls = [
        ("Read", {"file_path": str(project / "notes" / "a.txt")}),
        ("Read", {"file_path": str(tmp_path / "x")}),
        ("Write", {"file_path": str(project / "n.txt"), "content": "x"}),
        ("Bash", {"command": "ls"}),
        ("Glob", {"pattern": "**/*.txt"}),
        ("Grep", {"pattern": "hello"}),
    ]
    for tool, ti in calls:
        r = _run(_call(tool, ti, project), env)
        assert r.stdout == "", (tool, r.stdout)
        assert "updatedInput" not in r.stderr
