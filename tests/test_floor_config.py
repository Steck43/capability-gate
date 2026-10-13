"""The guardrails stay switched on: strict xfail, the CI jobs, the local hooks.

Each guardrail is configuration, and configuration can be deleted in the same
change that would trip it. These tests fail when a guardrail is turned off, so
removing one needs this file changed too, in plain sight of review.
"""

from __future__ import annotations

import configparser
import re
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _workflow() -> dict:
    return yaml.safe_load(
        (ROOT / ".github" / "workflows" / "floor.yml").read_text(encoding="utf-8")
    )


def _strip_comments(run: str) -> str:
    """Shell text without comment lines, so a needle kept in a comment does not count."""
    return "\n".join(
        line for line in run.splitlines() if not line.strip().startswith("#")
    )


def _runs(job: dict) -> str:
    return "\n".join(
        _strip_comments(str(s.get("run", ""))) for s in job.get("steps", [])
    )


# Jobs whose failure must fail the floor, and the only `if:` each may carry.
GUARDRAIL_JOBS = {
    "secrets": None,
    "leak-denylist": "github.event_name == 'pull_request' || github.event_name == 'push'",
    "kat-lint": None,
    "tests": None,
    "lint": None,
    "authorship": None,
}
ALLOWED_STEP_IFS = {"github.event_name == 'pull_request'"}
NEUTRALIZERS = re.compile(r"\|\|\s*(true|:)(\s|$)|\bexit\s+0\b|\bset\s+\+e\b")
_ENV_SINK = re.compile(r"GITHUB_(?:ENV|PATH)")
_PY_ASSIGN = re.compile(r"(?<![A-Za-z0-9_])(?:PYTEST|PYTHON)[A-Za-z0-9_]*\s*=")
_ERREXIT = re.compile(r"(?:^|\s)-[A-Za-z]*e[A-Za-z]*(?:\s|$)")


def _step_fault(step: dict) -> str | None:
    """Why this guardrail step would let a failing check pass, or None."""
    run = _strip_comments(str(step.get("run", "")))
    if step.get("continue-on-error"):
        return "continue-on-error"
    if step.get("if") not in (None, *ALLOWED_STEP_IFS):
        return f"if: {step.get('if')}"
    if "PYTEST_ADDOPTS" in (step.get("env") or {}):
        return "PYTEST_ADDOPTS"
    if NEUTRALIZERS.search(run):
        return "neutralizer"
    if _ENV_SINK.search(run) and _PY_ASSIGN.search(run):
        return "env-write"
    shell = step.get("shell")
    if shell is not None and not _ERREXIT.search(str(shell)):
        return "shell"
    return None


def test_pytest_ini_keeps_strict_xfail_and_syntax_warning_errors() -> None:
    cfg = configparser.ConfigParser()
    cfg.read(ROOT / "pytest.ini", encoding="utf-8")
    assert cfg.get("pytest", "xfail_strict").strip().lower() == "true"
    filters = cfg.get("pytest", "filterwarnings").split()
    assert "error::SyntaxWarning" in filters
    # Later filters win, so nothing after the error filter may relax it.
    for f in filters[filters.index("error::SyntaxWarning") + 1 :]:
        action, _, rest = f.partition("::")
        category = rest.split(":")[0]
        assert action == "error" or category not in ("", "Warning", "SyntaxWarning"), f
    # addopts can switch off strict xfail (--runxfail, -o) or warnings
    # (-p no:warnings, -W) without touching the lines above.
    assert not cfg.has_option("pytest", "addopts"), cfg.get("pytest", "addopts")


@pytest.mark.parametrize(
    "job, needle",
    [
        ("secrets", "gitleaks/gitleaks-action@"),
        ("leak-denylist", "--ci --base"),
        ("leak-denylist", '--text "pull request title and body"'),
        ("leak-denylist", "origin/main:scripts/leak_denylist_scan.py"),
        ("kat-lint", "scripts/kat_lint.py"),
        ("tests", "pytest"),
    ],
)
def test_floor_workflow_keeps_guardrail_jobs(job: str, needle: str) -> None:
    jobs = _workflow()["jobs"]
    assert job in jobs, f"floor.yml lost the {job} job"
    text = _runs(jobs[job]) + "\n".join(
        str(s.get("uses", "")) for s in jobs[job].get("steps", [])
    )
    assert needle in text, f"{job} no longer runs {needle!r}"


def test_leak_job_reads_the_denylist_secret() -> None:
    job = _workflow()["jobs"]["leak-denylist"]
    envs = [
        s.get("env", {})
        for s in job["steps"]
        if 'python "$RUNNER_TEMP/leak_scan.py"' in str(s.get("run", ""))
    ]
    assert envs, "no step runs the scanner"
    for env in envs:
        assert env.get("LEAK_DENYLIST") == "${{ secrets.LEAK_DENYLIST }}"


def test_pre_commit_keeps_local_guardrail_hooks() -> None:
    cfg = yaml.safe_load((ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8"))
    hooks = {h["id"]: h for repo in cfg["repos"] for h in repo.get("hooks", [])}
    assert (
        "scripts/leak_denylist_scan.py --staged"
        in hooks["leak-denylist-staged"]["entry"]
    )
    assert "scripts/kat_lint.py" in hooks["kat-lint"]["entry"]


def test_gitleaks_config_keeps_default_and_custom_rules() -> None:
    cfg = tomllib.loads((ROOT / ".gitleaks.toml").read_text(encoding="utf-8"))
    assert cfg["extend"]["useDefault"] is True
    ids = {r["id"] for r in cfg["rules"]}
    assert {"windows-user-home-path", "posix-home-path", "private-ipv4"} <= ids


def test_pull_request_trigger_reruns_on_title_or_body_edit() -> None:
    # PyYAML reads the bare key "on" as boolean True.
    wf = _workflow()
    triggers = wf.get("on", wf.get(True))
    pr = triggers["pull_request"] or {}
    types = set(pr.get("types", []))
    # Without "edited", a title or body changed after the last push is never
    # rescanned, so the leak check could pass on text it never read.
    assert {"opened", "synchronize", "reopened", "edited"} <= types


def test_guardrail_jobs_cannot_be_skipped_or_soft_failed() -> None:
    wf = _workflow()
    jobs = wf["jobs"]
    assert "PYTEST_ADDOPTS" not in (wf.get("env") or {})
    for name, allowed_if in GUARDRAIL_JOBS.items():
        job = jobs[name]
        assert job.get("if") == allowed_if, (name, job.get("if"))
        assert not job.get("continue-on-error"), name
        assert "PYTEST_ADDOPTS" not in (job.get("env") or {}), name
        for s in job.get("steps", []):
            label = (name, s.get("name") or s.get("uses") or s.get("run"))
            fault = _step_fault(s)
            assert fault is None, (label, fault)


def test_guardrail_commands_run_as_written() -> None:
    jobs = _workflow()["jobs"]
    pytest_runs = [
        _strip_comments(str(s.get("run", ""))).strip()
        for s in jobs["tests"]["steps"]
        if "pytest" in str(s.get("run", ""))
        and "pip install" not in str(s.get("run", ""))
    ]
    assert pytest_runs == ["pytest -q"], pytest_runs
    assert "python scripts/kat_lint.py" in _runs(jobs["kat-lint"]).splitlines()
    leak = _runs(jobs["leak-denylist"])
    load = 'git show origin/main:scripts/leak_denylist_scan.py > "$RUNNER_TEMP/leak_scan.py"'
    assert load in leak
    assert 'python "$RUNNER_TEMP/leak_scan.py" --ci --base "$BASE" --head HEAD' in leak
    assert '| python "$RUNNER_TEMP/leak_scan.py" --text' in leak


@pytest.mark.parametrize(
    "run",
    [
        "echo 'PYTEST_ADDOPTS=--co' >> \"$GITHUB_ENV\"\npytest -q",
        "echo 'PYTHONPATH=/opt/py' >> \"$GITHUB_PATH\"\npython scripts/kat_lint.py",
    ],
)
def test_guardrail_step_rejects_pytest_or_python_env_writes(run: str) -> None:
    fault = _step_fault({"run": run})
    assert fault == "env-write", fault


@pytest.mark.parametrize(
    "shell",
    [
        "bash --noprofile --norc {0}",
        "bash {0}",
    ],
)
def test_guardrail_step_rejects_shell_without_errexit(shell: str) -> None:
    fault = _step_fault({"run": "python scripts/kat_lint.py", "shell": shell})
    assert fault == "shell", fault


def test_guardrail_step_allows_default_shell_and_errexit() -> None:
    assert _step_fault({"run": "pytest -q"}) is None
    assert _step_fault({"run": "pytest -q", "shell": "bash -e {0}"}) is None
    assert _step_fault({"run": "pytest -q", "shell": "bash -eo pipefail {0}"}) is None
