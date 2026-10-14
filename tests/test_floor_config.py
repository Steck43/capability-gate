"""The guardrails stay switched on: strict xfail, the CI jobs, the local hooks.

Each guardrail is configuration, and configuration can be deleted in the same
change that would trip it. The floor guard (scripts/floor_guard.py) pins every
job and guard file exactly and checks the pinned values against rules; these
tests prove it on the live tree and on every class of tamper planted in the
real workflow. Removing a guardrail needs this file and the pins changed too,
in plain sight of review.
"""

from __future__ import annotations

import configparser
import json
import re
import shutil
import sys
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import floor_guard as guard  # noqa: E402

WORKFLOW = ROOT / ".github" / "workflows" / "floor.yml"


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _runs(job: dict) -> str:
    return "\n".join(str(s.get("run", "")) for s in job.get("steps", []))


def _strip_comments(run: str) -> str:
    return "\n".join(ln for ln in run.splitlines() if not ln.strip().startswith("#"))


# --- the live floor -----------------------------------------------------------


def test_live_floor_matches_its_pins_and_rules() -> None:
    assert guard.violations(ROOT) == []


def test_pins_cover_every_job_and_guard_file() -> None:
    pins = guard.pins_from_file(
        json.loads((ROOT / ".github" / "floor-pins.json").read_text(encoding="utf-8"))
    )
    assert set(pins["jobs"]) == set(_workflow()["jobs"])
    for rel in (
        "scripts/floor_guard.py",
        "scripts/kat_lint.py",
        "scripts/leak_denylist_scan.py",
        "tests/test_floor_config.py",
        "requirements-ci.lock",
        "pytest.ini",
        ".github/workflows/floor.yml",
    ):
        assert rel in pins["files"], rel


def test_pytest_ini_keeps_strict_xfail_and_syntax_warning_errors() -> None:
    cfg = configparser.ConfigParser()
    cfg.read(ROOT / "pytest.ini", encoding="utf-8")
    assert cfg.get("pytest", "xfail_strict").strip().lower() == "true"
    filters = cfg.get("pytest", "filterwarnings").split()
    assert "error::SyntaxWarning" in filters
    for f in filters[filters.index("error::SyntaxWarning") + 1 :]:
        action, _, rest = f.partition("::")
        category = rest.split(":")[0]
        assert action == "error" or category not in ("", "Warning", "SyntaxWarning"), f
    assert not cfg.has_option("pytest", "addopts"), cfg.get("pytest", "addopts")


@pytest.mark.parametrize(
    "job, needle",
    [
        ("secrets", "gitleaks/gitleaks-action@"),
        ("leak-denylist", "--ci --base"),
        ("leak-denylist", '--text "pull request title and body"'),
        ("leak-denylist", "git show origin/main:scripts/leak_denylist_scan.py"),
        ("leak-denylist", '--text "pull request branch"'),
        ("kat-lint", "git show origin/main:scripts/kat_lint.py"),
        ("kat-lint", 'python "$RUNNER_TEMP/kat_lint.py" --root . --require-kats'),
        ("tests", "pytest -q"),
        ("floor-guard", 'git show "$BASE:scripts/floor_guard.py"'),
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


def test_leak_job_fails_closed_without_a_base_scanner() -> None:
    run = _runs(_workflow()["jobs"]["leak-denylist"])
    assert "refusing to run this change's copy" in run
    assert "cp scripts/leak_denylist_scan.py" not in run


# A guard loaded from the default branch must stop the job when the default
# branch lacks it, never fall back to the copy the pull request carries.
_LOAD_FROM_MAIN = {
    "leak-denylist": ("scripts/leak_denylist_scan.py", "leak_scan.py"),
    "kat-lint": ("scripts/kat_lint.py", "kat_lint.py"),
}


@pytest.mark.parametrize("job", sorted(_LOAD_FROM_MAIN))
def test_guard_loaded_from_main_fails_closed_when_main_lacks_it(job: str) -> None:
    script, temp = _LOAD_FROM_MAIN[job]
    steps = _workflow()["jobs"][job]["steps"]
    loads = [s for s in steps if f"origin/main:{script}" in str(s.get("run", ""))]
    assert len(loads) == 1, job
    lines = [
        ln.strip() for ln in _strip_comments(loads[0]["run"]).splitlines() if ln.strip()
    ]
    assert lines == [
        f"if ! git cat-file -e origin/main:{script}; then",
        lines[1],
        "exit 1",
        "fi",
        f'git show origin/main:{script} > "$RUNNER_TEMP/{temp}"',
    ], (job, lines)
    assert lines[1].startswith('echo "::error::') and "refusing" in lines[1], lines[1]
    for s in steps:
        run = str(s.get("run", ""))
        assert f"cp {script}" not in run and "::warning::" not in run, job


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
    wf = _workflow()
    triggers = wf.get("on", wf.get(True))
    types = set((triggers["pull_request"] or {}).get("types", []))
    assert {"opened", "synchronize", "reopened", "edited"} <= types


def test_pytest_invocation_is_exact_and_from_the_gate_directory() -> None:
    steps = _workflow()["jobs"]["tests"]["steps"]
    runs = [
        s
        for s in steps
        if "pytest" in str(s.get("run", ""))
        and "pip install" not in str(s.get("run", ""))
    ]
    assert len(runs) == 1
    assert str(runs[0]["run"]).strip() == "pytest -q"
    assert runs[0].get("working-directory") == "capability-gate"


def test_installs_use_only_the_hash_locked_file() -> None:
    lock = (ROOT / "requirements-ci.lock").read_text(encoding="utf-8")
    pinned = [line for line in lock.splitlines() if "==" in line]
    assert pinned and lock.count("--hash=sha256:") >= len(pinned)
    installs = 0
    for name, job in _workflow()["jobs"].items():
        for step in job.get("steps", []):
            run = str(step.get("run", "")).strip()
            if "pip" in run:
                installs += 1
                assert run.replace('"', "") in guard.LOCKED_INSTALLS, (name, run)
    assert installs >= 3


# --- every tamper class, planted in the real workflow (T8) ---------------------

KAT = '        run: python "$RUNNER_TEMP/kat_lint.py" --root . --require-kats\n'
RUFF = "      - run: ruff check .\n"
PYTEST = "        run: pytest -q\n"


def _step(run: str, extra: str = "") -> str:
    return (
        KAT
        + extra
        + "      - run: |\n"
        + "".join(f"          {line}\n" for line in run.splitlines())
    )


TAMPERS = [
    # T1: exact pins (values a rule cannot judge)
    (
        "T1 runner",
        (
            "    name: tests (known-answer tests call the gate)\n    timeout-minutes: 10\n    runs-on: ubuntu-latest\n",
            "    name: tests (known-answer tests call the gate)\n    timeout-minutes: 10\n    runs-on: self-hosted\n",
        ),
        "pin: job kat-lint changed",
        True,
    ),
    (
        "T1 timeout",
        (
            "    name: tests (known-answer tests call the gate)\n    timeout-minutes: 10\n",
            "    name: tests (known-answer tests call the gate)\n    timeout-minutes: 1\n",
        ),
        "pin: job kat-lint changed",
        True,
    ),
    (
        "T1 matrix",
        ('python: ["3.11", "3.12"]', 'python: ["3.12"]'),
        "pin: job tests changed",
        True,
    ),
    (
        "T1 run text",
        (KAT, KAT.replace("--root .", "--root tests")),
        "pin: job kat-lint changed",
        True,
    ),
    (
        "T1 working directory",
        (
            PYTEST,
            PYTEST.replace("run:", "working-directory: aegis-atoms\n        run:"),
        ),
        "working directory",
        False,
    ),
    (
        "T1 concurrency",
        ("  cancel-in-progress: true\n", "  cancel-in-progress: false\n"),
        "pin: workflow settings changed",
        True,
    ),
    (
        "T1 permissions",
        ("permissions:\n  contents: read\n", "permissions:\n  contents: write\n"),
        "permissions beyond contents: read",
        False,
    ),
    (
        "T1 expression in run",
        (PYTEST, "        run: pytest -q ${{ github.event.pull_request.title }}\n"),
        "expression interpolated",
        False,
    ),
    (
        "T1 unparseable shell",
        (KAT, _step('echo "unterminated')),
        "does not parse",
        False,
    ),
    (
        "T1 unknown command",
        (KAT, _step("make test")),
        "command make is not allowlisted",
        False,
    ),
    # T2: stop-on-error
    (
        "T2 shell without -e",
        (KAT, KAT + "        shell: bash {0}\n"),
        "shell without stop-on-error",
        False,
    ),
    (
        "T2 shell -e then +e",
        (KAT, KAT + "        shell: bash -e +e {0}\n"),
        "shell without stop-on-error",
        False,
    ),
    (
        "T2 shell +e first",
        (KAT, KAT + "        shell: bash +e -e {0}\n"),
        "shell without stop-on-error",
        False,
    ),
    (
        "T2 set +e",
        (KAT, _step("set +e\npython scripts/kat_lint.py")),
        "set is not allowed",
        False,
    ),
    (
        "T2 set +o errexit",
        (KAT, _step("set +o errexit\npython scripts/kat_lint.py")),
        "set is not allowed",
        False,
    ),
    (
        "T2 set -e then +e",
        (KAT, _step("set -e +e\npython scripts/kat_lint.py")),
        "set is not allowed",
        False,
    ),
    (
        "T2 quoted set",
        (KAT, _step("'set' +e\npython scripts/kat_lint.py")),
        "set is not allowed",
        False,
    ),
    (
        "T2 built-up set",
        (KAT, _step('S=se; "${S}t" +e\npython scripts/kat_lint.py')),
        "constructed command",
        False,
    ),
    (
        "T2 eval",
        (KAT, _step('eval "set +e"\npython scripts/kat_lint.py')),
        "eval is not allowed",
        False,
    ),
    (
        "T2 shopt",
        (KAT, _step("shopt -u -o errexit\npython scripts/kat_lint.py")),
        "shopt is not allowed",
        False,
    ),
    (
        "T2 workflow default shell",
        ("permissions:\n", "defaults:\n  run:\n    shell: bash {0}\npermissions:\n"),
        "default shell without stop-on-error",
        False,
    ),
    (
        "T2 negated statement",
        (KAT, _step("! python scripts/kat_lint.py")),
        "negated",
        False,
    ),
    # T3: runner files by any spelling, any position
    (
        "T3 GITHUB_ENV",
        (KAT, _step('echo "A=1" >> "$GITHUB_ENV"')),
        "runner environment",
        False,
    ),
    (
        "T3 braces GITHUB_PATH",
        (KAT, _step('echo /tmp >> "${GITHUB_PATH}"')),
        "runner environment",
        False,
    ),
    (
        "T3 split name",
        (KAT, _step('echo A=1 >> "$GITH""UB_ENV"')),
        "runner environment",
        False,
    ),
    (
        "T3 indirect name",
        (KAT, _step('N=GITHUB_; echo A=1 >> "${!N}ENV"')),
        "redirect target",
        False,
    ),
    (
        "T3 constructed variable",
        (KAT, _step('X=GI; Y=THUB_OUTPUT; F="$X$Y"; echo a >> "${!F}"')),
        "redirect target",
        False,
    ),
    (
        "T3 file commands dir",
        (
            KAT,
            _step("echo A=1 >> $HOME/work/_temp/_runner_file_commands/set_env_1"),
        ),
        "runner environment",
        False,
    ),
    (
        "T3 redirect after &&",
        (KAT, _step("python scripts/kat_lint.py && echo x > pytest.ini")),
        "redirect target",
        False,
    ),
    (
        "T3 redirect in substitution",
        (KAT, _step('echo "$(echo x > conftest.py)"')),
        "redirect target",
        False,
    ),
    (
        "T3 tee",
        (KAT, _step("python scripts/kat_lint.py | tee out.txt")),
        "tee is not allowed",
        False,
    ),
    (
        "T3 env prefix",
        (KAT, _step("BASH_ENV=/tmp/rc python scripts/kat_lint.py")),
        "assignment to BASH_ENV",
        False,
    ),
    (
        "T3 step env",
        (KAT, KAT + "        env:\n          LD_PRELOAD: /tmp/x.so\n"),
        "env sets LD_PRELOAD",
        False,
    ),
    (
        "T3 job env",
        (
            "    name: tests (known-answer tests call the gate)\n",
            "    name: tests (known-answer tests call the gate)\n    env:\n      PYTHONPATH: /tmp\n",
        ),
        "env at job level",
        False,
    ),
    (
        "T3 workflow env",
        ("permissions:\n", "env:\n  PYTEST_ADDOPTS: --co\npermissions:\n"),
        "env at workflow level",
        False,
    ),
    (
        "T3 in if condition",
        (KAT, _step('if echo A >> "$GITHUB_ENV"; then python scripts/kat_lint.py; fi')),
        "runner environment",
        False,
    ),
    # T4: installs
    (
        "T4 free pip",
        (KAT, _step("pip install requests\npython scripts/kat_lint.py")),
        "pip is not allowed",
        False,
    ),
    (
        "T4 python -m pip unlocked",
        (KAT, _step("python -m pip install requests")),
        "install outside the hash-locked",
        False,
    ),
    (
        "T4 index override",
        (
            KAT,
            _step(
                "python -m pip install --require-hashes --no-deps -r requirements-ci.lock --index-url https://example.invalid/simple"
            ),
        ),
        "install outside the hash-locked",
        False,
    ),
    (
        "T4 index env",
        (
            KAT,
            KAT
            + "        env:\n          PIP_INDEX_URL: https://example.invalid/simple\n",
        ),
        "env sets PIP_INDEX_URL",
        False,
    ),
    ("T4 uv", (KAT, _step("uv pip install requests")), "uv is not allowed", False),
    # T5: check names
    (
        "T5 case-folded name",
        (
            "  authorship:\n",
            "  decoy:\n    name: Tests (Known-Answer Tests Call The Gate)\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n      - run: echo hi\n  authorship:\n",
        ),
        "produced by more than one job",
        False,
    ),
    (
        "T5 matrix-expanded name",
        (
            "  authorship:\n",
            '  decoy:\n    name: tests\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    strategy:\n      matrix:\n        python: ["3.12"]\n    steps:\n      - run: echo hi\n  authorship:\n',
        ),
        "produced by more than one job",
        False,
    ),
    (
        "T5 name equal only after matrix expansion",
        (
            "  authorship:\n",
            "  decoy:\n    name: tests (3.12)\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n      - run: echo hi\n  authorship:\n",
        ),
        "produced by more than one job",
        False,
    ),
    # T6: checkout inputs and guard files
    (
        "T6 checkout ref",
        (
            "    name: tests (known-answer tests call the gate)\n    timeout-minutes: 10\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2\n        with:\n          fetch-depth: 0\n          persist-credentials: false\n",
            "    name: tests (known-answer tests call the gate)\n    timeout-minutes: 10\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2\n        with:\n          fetch-depth: 0\n          persist-credentials: false\n          ref: main\n",
        ),
        "checkout inputs change",
        False,
    ),
    (
        "T6 git checkout guard file",
        (KAT, _step("git checkout HEAD~1 -- pytest.ini")),
        "can change the tree",
        False,
    ),
    (
        "T6 cp over conftest",
        (KAT, _step("cp /tmp/x tests/conftest.py")),
        "cp to a non-workspace path",
        False,
    ),
    (
        "T6 unpinned action",
        (KAT, KAT + "      - uses: actions/checkout@v4\n"),
        "is not allowlisted",
        False,
    ),
    (
        "T6 continue-on-error",
        (KAT, KAT + "        continue-on-error: true\n"),
        "keys ['continue-on-error']",
        False,
    ),
    (
        "T6 job permissions",
        (
            "    name: tests (known-answer tests call the gate)\n",
            "    name: tests (known-answer tests call the gate)\n    permissions:\n      contents: write\n",
        ),
        "permissions beyond contents: read",
        False,
    ),
    (
        "T6 temp path escape",
        (KAT, _step('cp /tmp/x "$RUNNER_TEMP/../work/capability-gate/pytest.ini"')),
        "cp to a non-workspace path",
        False,
    ),
    # T7: lint cannot be made non-failing
    (
        "T7 ruff exit-zero",
        (RUFF, "      - run: ruff check --exit-zero .\n"),
        "lint made non-failing",
        False,
    ),
    (
        "T7 masked by || true",
        (RUFF, "      - run: ruff check . || true\n"),
        "failure masked",
        False,
    ),
    (
        "T7 masked by || exit 0",
        (RUFF, "      - run: ruff check . || exit 0\n"),
        "failure masked",
        False,
    ),
    (
        "T7 masked by || echo",
        (RUFF, "      - run: ruff check . || echo ignored\n"),
        "failure masked",
        False,
    ),
    ("T7 exit 0", (KAT, _step("exit 0")), "exit with a success code", False),
    (
        "T7 python -c",
        (KAT, _step('python -c "print(1)"')),
        "python runs code from the command line",
        False,
    ),
]


def _copy_tree(tmp: Path) -> Path:
    root = tmp / "repo"
    for rel in guard.guard_files(ROOT) + [str(guard.PINS.as_posix())]:
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel, dest)
    return root


@pytest.mark.parametrize(
    ("label", "edit", "expect", "pin_only"), TAMPERS, ids=[t[0] for t in TAMPERS]
)
def test_each_tamper_planted_in_the_real_workflow_turns_the_floor_red(
    tmp_path: Path, label: str, edit: tuple[str, str], expect: str, pin_only: bool
) -> None:
    root = _copy_tree(tmp_path)
    wf = root / ".github" / "workflows" / "floor.yml"
    text = wf.read_text(encoding="utf-8")
    old, new = edit
    assert text.count(old) >= 1, label
    wf.write_text(text.replace(old, new, 1), encoding="utf-8")
    # Against the committed pins: the pin catches every change.
    found = guard.violations(root)
    assert any(f.startswith("pin:") for f in found), (label, found)
    if pin_only:
        assert expect in found, (label, found)
    # With the pins regenerated, as an attacker would: the rules still catch it,
    # except for values only an exact pin can judge.
    (root / guard.PINS).write_text(
        json.dumps(guard.pins_to_file(guard.compute_pins(root))), encoding="utf-8"
    )
    found = guard.violations(root)
    if pin_only:
        assert found == [], (label, found)
    else:
        assert any(expect in f for f in found), (label, found)


def test_a_called_script_is_pinned(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    script = root / "scripts" / "kat_lint.py"
    script.write_text(
        script.read_text(encoding="utf-8") + "\nimport sys; sys.exit(0)\n",
        encoding="utf-8",
    )
    assert "pin: file scripts/kat_lint.py changed" in guard.violations(root)


def test_an_added_conftest_or_pytest_config_is_caught(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    (root / "tests" / "conftest.py").write_text(
        "collect_ignore_glob = ['*']\n", encoding="utf-8"
    )
    (root / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\naddopts = '--co'\n", encoding="utf-8"
    )
    found = guard.violations(root)
    assert "pin: file tests/conftest.py added" in found
    assert "pin: file pyproject.toml added" in found


def test_a_changed_lock_file_is_caught(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    lock = root / "requirements-ci.lock"
    lock.write_text(
        lock.read_text(encoding="utf-8") + "evil==1.0 --hash=sha256:" + "0" * 64 + "\n",
        encoding="utf-8",
    )
    assert "pin: file requirements-ci.lock changed" in guard.violations(root)


def test_a_deleted_guard_job_is_caught(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    wf = root / ".github" / "workflows" / "floor.yml"
    data = yaml.safe_load(wf.read_text(encoding="utf-8"))
    del data["jobs"]["kat-lint"]
    wf.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    assert "pin: job kat-lint removed" in guard.violations(root)


def test_a_missing_pin_file_fails_closed(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    (root / guard.PINS).unlink()
    assert guard.violations(root) == ["pin: .github/floor-pins.json is missing"]


# Every digest in the pins file sits under a "sha256" field, so no line pairs a
# credential-shaped name (a job called "secrets") with a 64-hex value.
_NAMED_HEX = re.compile(r'"([^"]*)"\s*:\s*"[0-9a-fA-F]{64}"')


def test_every_pinned_digest_sits_under_a_sha256_field() -> None:
    text = (ROOT / ".github" / "floor-pins.json").read_text(encoding="utf-8")
    names = _NAMED_HEX.findall(text)
    assert len(names) >= 20
    assert set(names) == {"sha256"}


def test_pins_round_trip_through_the_file_form() -> None:
    pins = guard.compute_pins(ROOT)
    assert guard.pins_from_file(guard.pins_to_file(pins)) == pins
    assert (
        guard.pins_from_file(json.loads(json.dumps(guard.pins_to_file(pins)))) == pins
    )


_H = "a" * 64


def _pin_doc(**over: object) -> dict:
    doc: dict = {
        "workflow": {"sha256": _H},
        "files": [{"path": "x.py", "sha256": _H}],
        "jobs": [{"job": "lint", "sha256": _H}],
    }
    doc.update(over)
    return doc


@pytest.mark.parametrize(
    "doc",
    [
        pytest.param(
            {"workflow": _H, "files": {"x.py": _H}, "jobs": {"lint": _H}},
            id="old-map-form",
        ),
        pytest.param(_pin_doc(extra=1), id="extra-top-key"),
        pytest.param(
            {k: v for k, v in _pin_doc().items() if k != "jobs"}, id="missing-group"
        ),
        pytest.param(_pin_doc(workflow=_H), id="workflow-not-object"),
        pytest.param(
            _pin_doc(workflow={"sha256": _H, "x": 1}), id="workflow-extra-key"
        ),
        pytest.param(_pin_doc(workflow={"sha256": "A" * 64}), id="workflow-uppercase"),
        pytest.param(_pin_doc(files={"x.py": _H}), id="group-not-list"),
        pytest.param(_pin_doc(files={}), id="group-empty-object"),
        pytest.param(_pin_doc(files=["x.py"]), id="entry-not-object"),
        pytest.param(_pin_doc(files=[{"path": "x.py"}]), id="entry-missing-sha"),
        pytest.param(
            _pin_doc(files=[{"path": "x.py", "sha256": _H, "x": 1}]),
            id="entry-extra-key",
        ),
        pytest.param(
            _pin_doc(jobs=[{"path": "lint", "sha256": _H}]), id="wrong-name-field"
        ),
        pytest.param(_pin_doc(files=[{"path": "", "sha256": _H}]), id="empty-name"),
        pytest.param(_pin_doc(files=[{"path": 7, "sha256": _H}]), id="name-not-string"),
        pytest.param(
            _pin_doc(files=[{"path": "x.py", "sha256": "a" * 63}]), id="short-digest"
        ),
        pytest.param(
            _pin_doc(files=[{"path": "x.py", "sha256": 1}]), id="digest-not-string"
        ),
        pytest.param(
            _pin_doc(
                files=[{"path": "x.py", "sha256": _H}, {"path": "x.py", "sha256": _H}]
            ),
            id="duplicate-name",
        ),
        pytest.param([], id="not-an-object"),
    ],
)
def test_a_malformed_pin_file_fails_closed(tmp_path: Path, doc: object) -> None:
    root = _copy_tree(tmp_path)
    (root / guard.PINS).write_text(json.dumps(doc), encoding="utf-8")
    found = guard.violations(root)
    assert len(found) == 1 and found[0].startswith(
        "pin: .github/floor-pins.json is malformed"
    ), found


def test_a_pin_file_that_is_not_json_fails_closed(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    (root / guard.PINS).write_text("{not json", encoding="utf-8")
    found = guard.violations(root)
    assert len(found) == 1 and "is malformed" in found[0], found


def test_another_workflow_cannot_shadow_a_check_name(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    (root / ".github" / "workflows" / "decoy.yml").write_text(
        "on: push\njobs:\n  x:\n    name: LINT (RUFF)\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
        encoding="utf-8",
    )
    found = guard.violations(root)
    assert any("produced by more than one job" in f for f in found), found


def test_floor_guard_job_reads_guard_pins_and_lock_from_base() -> None:
    run = _runs(_workflow()["jobs"]["floor-guard"])
    for rel in (
        "scripts/floor_guard.py",
        ".github/floor-pins.json",
        "requirements-ci.lock",
    ):
        assert f'git show "$BASE:{rel}"' in run, rel
    assert "refusing to judge with the pull request copy" in run
    assert '--pins "$RUNNER_TEMP/floor/floor-pins.json"' in run


def test_the_tamper_list_covers_every_property() -> None:
    keys = {label.split()[0] for label, *_ in TAMPERS}
    assert keys == {"T1", "T2", "T3", "T4", "T5", "T6", "T7"}
