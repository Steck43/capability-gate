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
import os
import re
import shutil
import subprocess
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
        ("kat-lint", "python scripts/kat_lint.py"),
        ("tests", "pytest -q"),
        ("floor-guard", 'git show "$GUARD_BASE:scripts/floor_guard.py"'),
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
    # main without a scanner fails at git cat-file; nothing falls back to the
    # copy under review.
    assert "git cat-file -e origin/main:scripts/leak_denylist_scan.py" in run
    assert (
        'git show origin/main:scripts/leak_denylist_scan.py > "$RUNNER_TEMP/leak_scan.py"'
        in run
    )
    assert "cp scripts/leak_denylist_scan.py" not in run
    assert "python scripts/leak_denylist_scan.py" not in run


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

KAT = "      - run: python scripts/kat_lint.py\n"
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
        "runner is not ubuntu-latest",
        False,
    ),
    (
        "T1 timeout",
        (
            "    name: tests (known-answer tests call the gate)\n    timeout-minutes: 10\n",
            "    name: tests (known-answer tests call the gate)\n    timeout-minutes: 1\n",
        ),
        "timeout is not the pinned 10 minutes",
        False,
    ),
    (
        "T1 matrix",
        ('python: ["3.11", "3.12"]', 'python: ["3.12"]'),
        "check names are not",
        False,
    ),
    (
        "T1 run text",
        (KAT, "      - run: python scripts/kat_lint.py --root .\n"),
        "python scripts/kat_lint.py arguments are not the allowlisted ones",
        False,
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
        "concurrency is not the floor's pinned value",
        False,
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
        "shell is not an allowlisted value",
        False,
    ),
    (
        "T2 shell -e then +e",
        (KAT, KAT + "        shell: bash -e +e {0}\n"),
        "shell is not an allowlisted value",
        False,
    ),
    (
        "T2 shell +e first",
        (KAT, KAT + "        shell: bash +e -e {0}\n"),
        "shell is not an allowlisted value",
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
        (
            "    shell: bash --noprofile --norc -eo pipefail {0}\n",
            "    shell: bash {0}\n",
        ),
        "default shell is not an allowlisted value",
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
            '      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2\n        with:\n          persist-credentials: false\n      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0\n        with:\n          python-version: "3.12"\n      - run: python scripts/kat_lint.py\n',
            '      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2\n        with:\n          persist-credentials: false\n          ref: main\n      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0\n        with:\n          python-version: "3.12"\n      - run: python scripts/kat_lint.py\n',
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


def _pins_text(root: Path) -> str:
    """The pin file bytes --update-pins writes for this tree."""
    return (
        json.dumps(
            guard.pins_to_file(guard.compute_pins(root)), indent=2, sort_keys=True
        )
        + "\n"
    )


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
    (root / guard.PINS).write_text(_pins_text(root), encoding="utf-8")
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
        assert f'git cat-file -e "$GUARD_BASE:{rel}"' in run, rel
        assert f'git show "$GUARD_BASE:{rel}"' in run, rel
    assert 'git rev-parse --verify "$GUARD_BASE^{commit}"' in run
    assert "scripts/floor_guard.py --root" not in run.replace(
        "/floor/floor_guard.py", ""
    )
    assert '--pins "$RUNNER_TEMP/floor/floor-pins.json"' in run


def test_the_tamper_list_covers_every_property() -> None:
    keys = {label.split()[0] for label, *_ in TAMPERS}
    assert keys == {"T1", "T2", "T3", "T4", "T5", "T6", "T7"}


# --- shell values are an exact allowlist (brief 3a) ---------------------------
# A shell value passes only when absent or exactly equal to one listed value,
# at step, job-defaults and workflow-defaults level. Flags are never parsed.

_BAD_SHELLS = [
    # trailing arguments after the placeholder
    pytest.param("bash -e {0} +e", id="trailing-plus-e"),
    pytest.param("bash -e {0} -x", id="trailing-flag"),
    pytest.param("bash -e {0} {0}", id="trailing-second-placeholder"),
    pytest.param("bash -eo pipefail {0} --norc", id="trailing-long-option"),
    # combined or extra flags
    pytest.param("bash -ex {0}", id="combined-flags"),
    pytest.param("bash -e -n {0}", id="parse-only"),
    pytest.param("bash -e -c true {0}", id="command-string"),
    pytest.param("bash -e -s {0}", id="script-from-stdin"),
    pytest.param("bash -e --rcfile zqxwvk.sh {0}", id="rcfile"),
    pytest.param("bash -e +e {0}", id="e-then-plus-e"),
    pytest.param("bash +e -e {0}", id="plus-e-then-e"),
    pytest.param("bash -e zqxwvk.sh {0}", id="extra-file-before-placeholder"),
    pytest.param("bash -E {0}", id="errtrace-not-errexit"),
    pytest.param("bash -e", id="no-placeholder"),
    pytest.param("bash  -e {0}", id="double-space"),
    pytest.param(" bash -e {0}", id="leading-space"),
    # alternate shells
    pytest.param("zsh -e {0}", id="zsh"),
    pytest.param("pwsh -command . '{0}'", id="pwsh"),
    pytest.param("python {0}", id="python"),
    pytest.param("/bin/bash -e {0}", id="absolute-bash"),
    pytest.param("bash", id="bare-bash-keyword"),
    pytest.param("sh {0}", id="sh-without-e"),
    # stop-on-error without pipefail: a failing command early in a pipe is hidden
    pytest.param("bash -e {0}", id="errexit-without-pipefail"),
    pytest.param("sh -e {0}", id="sh-errexit-without-pipefail"),
    # the end-of-options marker
    pytest.param("bash -e -- {0}", id="end-of-options"),
    pytest.param("bash -- -e {0}", id="end-of-options-first"),
]
_LEVELS = ("step", "job-defaults", "workflow-defaults")
_ALLOWED_SHELLS = [
    "bash --noprofile --norc -eo pipefail {0}",
    "bash -eo pipefail {0}",
]


def _plant_shell(text: str, level: str, value: str) -> str:
    quoted = json.dumps(value)
    if level == "step":
        return text.replace(KAT, KAT + f"        shell: {quoted}\n", 1)
    if level == "job-defaults":
        anchor = "    name: tests (known-answer tests call the gate)\n"
        return text.replace(
            anchor, anchor + f"    defaults:\n      run:\n        shell: {quoted}\n", 1
        )
    if FLOOR_DEFAULTS in text:
        return text.replace(
            FLOOR_DEFAULTS, f"defaults:\n  run:\n    shell: {quoted}\n", 1
        )
    return text.replace(
        "permissions:\n", f"defaults:\n  run:\n    shell: {quoted}\npermissions:\n", 1
    )


_SHELL_MESSAGE = {
    "step": "job kat-lint step 3: shell is not an allowlisted value",
    "job-defaults": "job kat-lint: default shell is not an allowlisted value",
    "workflow-defaults": "workflow: default shell is not an allowlisted value",
}


@pytest.mark.parametrize("level", _LEVELS)
@pytest.mark.parametrize("value", _BAD_SHELLS)
def test_a_shell_outside_the_allowlist_is_a_rules_violation(
    tmp_path: Path, level: str, value: str
) -> None:
    root = _copy_tree(tmp_path)
    wf = root / ".github" / "workflows" / "floor.yml"
    planted = _plant_shell(wf.read_text(encoding="utf-8"), level, value)
    assert value in planted or json.dumps(value) in planted
    wf.write_text(planted, encoding="utf-8")
    # Pins regenerated with the change: only the rules layer can catch it.
    (root / guard.PINS).write_text(_pins_text(root), encoding="utf-8")
    found = guard.violations(root)
    assert any(f.endswith(_SHELL_MESSAGE[level]) for f in found), found


@pytest.mark.parametrize(
    "value", [pytest.param(1, id="int"), pytest.param(["bash", "-e", "{0}"], id="list")]
)
def test_a_shell_that_is_not_a_string_is_rejected(value: object) -> None:
    assert not guard.shell_ok(value)


@pytest.mark.parametrize("value", _ALLOWED_SHELLS)
def test_each_allowlisted_shell_passes_the_rules_at_every_level(
    tmp_path: Path, value: str
) -> None:
    for level in ("step", "workflow-defaults"):
        root = _copy_tree(tmp_path / level)
        wf = root / ".github" / "workflows" / "floor.yml"
        wf.write_text(
            _plant_shell(wf.read_text(encoding="utf-8"), level, value), encoding="utf-8"
        )
        (root / guard.PINS).write_text(_pins_text(root), encoding="utf-8")
        assert guard.violations(root) == [], (level, value)
    assert guard.shell_ok(value)


def test_the_shell_allowlist_is_exactly_the_stop_on_error_values() -> None:
    assert getattr(guard, "SHELL_ALLOWLIST", None) == frozenset(_ALLOWED_SHELLS)


@pytest.mark.parametrize("value", _ALLOWED_SHELLS)
def test_each_allowlisted_shell_stops_a_failing_script(
    tmp_path: Path, value: str
) -> None:
    """Behavior, not text: real bash or sh runs the step and the step fails."""
    script = tmp_path / "step.sh"
    script.write_bytes(b"false\necho zqxwvk-reached\n")
    words = value.split()
    exe = shutil.which(words[0])
    assert exe, f"{words[0]} is required on every runner that runs this suite"
    argv = [exe] + [
        str(script).replace("\\", "/") if w == "{0}" else w for w in words[1:]
    ]
    run = subprocess.run(argv, capture_output=True, text=True)
    assert run.returncode != 0, value
    assert "zqxwvk-reached" not in run.stdout, value


# --- guard globs see what pytest loads, and skip only what pytest skips --------


def test_sibling_checkouts_under_the_scratch_dir_are_not_guard_files(
    tmp_path: Path,
) -> None:
    """run_full_suite.py clones pinned siblings under .tmp/; pytest never recurses there."""
    root = _copy_tree(tmp_path)
    sib = root / ".tmp" / "pinned-siblings" / "zqxwvk" / "tests"
    sib.mkdir(parents=True)
    (sib / "conftest.py").write_text("x = 1\n", encoding="utf-8")
    (root / ".tmp" / "pinned-siblings" / "zqxwvk" / "pytest.ini").write_text(
        "[pytest]\n", encoding="utf-8"
    )
    assert guard.violations(root) == []


def test_a_conftest_where_pytest_does_recurse_is_still_caught(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    for rel in ("node_modules/zqxwvk/conftest.py", "harness/conftest.py"):
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x = 1\n", encoding="utf-8")
    found = guard.violations(root)
    assert "pin: file node_modules/zqxwvk/conftest.py added" in found, found
    assert "pin: file harness/conftest.py added" in found, found


def test_every_directory_the_guard_skips_is_one_pytest_skips() -> None:
    import fnmatch

    ini = configparser.ConfigParser()
    ini.read(ROOT / "pytest.ini", encoding="utf-8")
    patterns = ini["pytest"]["norecursedirs"].split()
    assert guard.GUARD_SKIP_DIRS
    for prefix in guard.GUARD_SKIP_DIRS:
        name = prefix.rstrip("/")
        assert any(fnmatch.fnmatch(name, p) for p in patterns), name


# --- the one gitleaks fingerprint (brief 3d) -----------------------------------
# Commit 14b3be1 stored a pin digest under the job key "secrets", which the
# generic-api-key rule reads as a credential. The tree no longer does that, and
# history is not rewritten, so exactly that finding is ignored and nothing else.

OLD_PIN_FINDING = "14b3be176f09833ea0da0421bf7d5cf15a6095c1:.github/floor-pins.json:generic-api-key:31"


def test_gitleaksignore_holds_exactly_the_one_old_pin_finding() -> None:
    lines = (ROOT / ".gitleaksignore").read_text(encoding="utf-8").splitlines()
    entries = [
        ln.strip() for ln in lines if ln.strip() and not ln.lstrip().startswith("#")
    ]
    assert entries == [OLD_PIN_FINDING]


def _has_allowlist(node: object) -> bool:
    if isinstance(node, dict):
        return any(
            "allowlist" in str(k).lower() or _has_allowlist(v) for k, v in node.items()
        )
    if isinstance(node, list):
        return any(_has_allowlist(v) for v in node)
    return False


def test_gitleaks_config_has_no_allowlist() -> None:
    config = tomllib.loads((ROOT / ".gitleaks.toml").read_text(encoding="utf-8"))
    assert config["rules"], "config parsed to no rules"
    assert not _has_allowlist(config)
    assert _has_allowlist({"rules": [{"allowlists": [{}]}]})  # the check itself works


def test_gitleaksignore_is_a_pinned_guard_file(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    ignore = root / ".gitleaksignore"
    ignore.write_text(
        ignore.read_text(encoding="utf-8")
        + "0" * 40
        + ":zqxwvk.txt:generic-api-key:1\n",
        encoding="utf-8",
    )
    assert "pin: file .gitleaksignore changed" in guard.violations(root)


# --- the pin file loads strictly (brief 3b: D1 to D4) ---------------------------


def _write_pins_text(root: Path, text: str) -> None:
    (root / guard.PINS).write_bytes(text.encode("utf-8"))


def _canonical(root: Path) -> str:
    return _pins_text(root)


def test_deep_nesting_is_one_malformed_violation(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    _write_pins_text(root, "[" * 200000 + "]" * 200000)
    found = guard.violations(root)
    assert len(found) == 1 and "is malformed" in found[0], found


def test_a_malformed_pin_file_exits_nonzero_without_a_traceback(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    _write_pins_text(root, "[" * 200000)
    run = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "floor_guard.py"), "--root", str(root)],
        capture_output=True,
        text=True,
    )
    assert run.returncode == 1
    assert "Traceback" not in run.stdout + run.stderr
    assert "is malformed" in run.stdout


def test_a_duplicate_top_level_key_is_malformed(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    text = _canonical(root)
    dup = '  "workflow": {"sha256": "' + "b" * 64 + '"},\n'
    planted = text.replace('  "workflow": {', dup + '  "workflow": {', 1)
    assert planted != text
    _write_pins_text(root, planted)
    found = guard.violations(root)
    assert len(found) == 1 and "duplicate key 'workflow'" in found[0], found


def test_a_duplicate_sha256_inside_one_entry_is_malformed(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    text = _canonical(root)
    entry = '"path": ".floor/craft/changelog_gate.py",\n'
    assert entry in text
    planted = text.replace(entry, entry + '      "sha256": "' + "c" * 64 + '",\n', 1)
    _write_pins_text(root, planted)
    found = guard.violations(root)
    assert len(found) == 1 and "duplicate key 'sha256'" in found[0], found


@pytest.mark.parametrize(
    ("old", "new"),
    [
        pytest.param('"sha256"', '"\\u0073ha256"', id="escaped-key"),
        pytest.param('"job": "secrets"', '"job": "\\u0073ecrets"', id="escaped-name"),
    ],
)
def test_an_escaped_key_or_name_is_malformed(
    tmp_path: Path, old: str, new: str
) -> None:
    root = _copy_tree(tmp_path)
    text = _canonical(root)
    assert old in text
    _write_pins_text(root, text.replace(old, new, 1))
    found = guard.violations(root)
    assert len(found) == 1 and "canonical form" in found[0], found


@pytest.mark.parametrize(
    "edit",
    [
        pytest.param(lambda s: s.replace("\n", "\n  ", 1), id="extra-indent"),
        pytest.param(lambda s: s.rstrip("\n"), id="no-final-newline"),
        pytest.param(lambda s: json.dumps(json.loads(s)), id="compact"),
    ],
)
def test_a_non_canonical_pin_file_is_malformed(tmp_path: Path, edit) -> None:
    root = _copy_tree(tmp_path)
    _write_pins_text(root, edit(_canonical(root)))
    found = guard.violations(root)
    assert len(found) == 1 and "canonical form" in found[0], found


def test_crlf_line_endings_load(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    _write_pins_text(root, _canonical(root).replace("\n", "\r\n"))
    assert guard.violations(root) == []


def _base_pins(root: Path, tmp_path: Path) -> Path:
    base = tmp_path / "base-pins.json"
    base.write_bytes((root / guard.PINS).read_bytes())
    return base


def test_deleting_the_in_tree_pin_file_is_a_violation_with_base_pins(
    tmp_path: Path,
) -> None:
    root = _copy_tree(tmp_path)
    base = _base_pins(root, tmp_path)
    (root / guard.PINS).unlink()
    found = guard.violations(root, base)
    assert "pin: in-tree .github/floor-pins.json is missing" in found, found


def test_renaming_the_in_tree_pin_file_is_a_violation_with_base_pins(
    tmp_path: Path,
) -> None:
    root = _copy_tree(tmp_path)
    base = _base_pins(root, tmp_path)
    (root / guard.PINS).rename(root / ".github" / "floor-pins.old.json")
    found = guard.violations(root, base)
    assert "pin: in-tree .github/floor-pins.json is missing" in found, found


def test_a_broken_in_tree_pin_file_is_a_violation_with_base_pins(
    tmp_path: Path,
) -> None:
    root = _copy_tree(tmp_path)
    base = _base_pins(root, tmp_path)
    _write_pins_text(root, "{not json")
    found = guard.violations(root, base)
    assert any(
        f.startswith("pin: in-tree .github/floor-pins.json is malformed") for f in found
    ), found


def test_a_good_in_tree_pin_file_with_base_pins_passes(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    assert guard.violations(root, _base_pins(root, tmp_path)) == []


# --- interpreter startup files are guard files (brief 3b: N3) -------------------


@pytest.mark.parametrize(
    "rel",
    ["sitecustomize.py", "usercustomize.py", "zqxwvk.pth", "scripts/sitecustomize.py"],
)
def test_an_added_startup_file_is_caught(tmp_path: Path, rel: str) -> None:
    root = _copy_tree(tmp_path)
    (root / rel).write_text("import os\n", encoding="utf-8")
    assert f"pin: file {rel} added" in guard.violations(root)


def test_an_edited_startup_file_is_caught(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    (root / "sitecustomize.py").write_text("x = 1\n", encoding="utf-8")
    _write_pins_text(root, _canonical(root))
    assert guard.violations(root) == []
    (root / "sitecustomize.py").write_text("x = 2\n", encoding="utf-8")
    assert "pin: file sitecustomize.py changed" in guard.violations(root)


# --- every class the rules layer must catch with the pins regenerated (brief 3b) -
# A legitimate floor change regenerates the pins, so these run rules-only: the
# workflow is edited, the pins rewritten, and the named rule must still fire.

_DECOY = (
    "  zqxwvk-decoy:\n"
    "    name: tests (known-answer tests call the gate)\n"
    "    timeout-minutes: 10\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - run: echo ok\n\n"
)
RULE_TAMPERS = [
    # N1: renamed job, decoy, protected key reused for a trivial step
    (
        "N1 protected job renamed away",
        ("  kat-lint:\n", "  kat-lint-old:\n"),
        "job kat-lint: protected job is missing",
    ),
    (
        "N1 decoy takes the check name",
        (
            "    name: tests (known-answer tests call the gate)\n",
            "    name: tests (kat old)\n",
        ),
        "job kat-lint: check names are not",
    ),
    (
        "N1 decoy job added",
        ("  authorship:\n", _DECOY + "  authorship:\n"),
        "job zqxwvk-decoy: not in the protected jobs table",
    ),
    (
        "N1 protected key reused for a trivial step",
        (KAT, "      - run: echo ok\n"),
        "required step text 'kat_lint.py' is missing",
    ),
    # pytest invocation is exact
    (
        "pytest -k",
        (PYTEST, "        run: pytest -q -k zqxwvk\n"),
        "pytest argument '-k'",
    ),
    (
        "pytest --co",
        (PYTEST, "        run: pytest -q --co\n"),
        "pytest argument '--co'",
    ),
    (
        "pytest -p no:plugin",
        (PYTEST, "        run: pytest -q -p no:zqxwvk\n"),
        "pytest argument '-p'",
    ),
    (
        "pytest --rootdir",
        (PYTEST, "        run: pytest -q --rootdir=zqxwvk\n"),
        "pytest argument '--rootdir=zqxwvk'",
    ),
    (
        "pytest --deselect",
        (PYTEST, "        run: pytest -q --deselect tests\n"),
        "pytest argument '--deselect'",
    ),
    (
        "python -m pytest -x",
        (PYTEST, "        run: python -m pytest -q --runxfail\n"),
        "pytest argument '--runxfail'",
    ),
    # guardrail jobs and steps always run
    (
        "job if false",
        (
            "    name: tests (known-answer tests call the gate)\n",
            "    name: tests (known-answer tests call the gate)\n    if: false\n",
        ),
        "job kat-lint: job condition is not allowlisted",
    ),
    (
        "allowlisted job condition widened",
        (
            "    if: github.event_name == 'pull_request' || github.event_name == 'push'\n",
            "    if: github.event_name == 'push'\n",
        ),
        "job leak-denylist: job condition is not allowlisted",
    ),
    (
        "job needs",
        (
            "    name: tests (known-answer tests call the gate)\n",
            "    name: tests (known-answer tests call the gate)\n    needs: [lint]\n",
        ),
        "job kat-lint: needs",
    ),
    (
        "step condition",
        (
            KAT,
            "      - if: github.event_name == 'push'\n        run: python scripts/kat_lint.py\n",
        ),
        "step condition is not allowlisted",
    ),
    # runner, timeout and matrix
    (
        "timeout zero",
        (
            "    name: tests (known-answer tests call the gate)\n    timeout-minutes: 10\n",
            "    name: tests (known-answer tests call the gate)\n    timeout-minutes: 0\n",
        ),
        "job kat-lint: timeout is not 1 to 30 minutes",
    ),
    (
        "timeout too long",
        (
            "    name: tests (known-answer tests call the gate)\n    timeout-minutes: 10\n",
            "    name: tests (known-answer tests call the gate)\n    timeout-minutes: 600\n",
        ),
        "job kat-lint: timeout is not 1 to 30 minutes",
    ),
    (
        "matrix excludes every run",
        (
            'python: ["3.11", "3.12"]',
            'python: ["3.11"]\n        exclude:\n          - python: "3.11"',
        ),
        "job tests: matrix expands to no runs",
    ),
    # triggers of the floor workflow
    (
        "pull_request loses synchronize",
        (
            "types: [opened, synchronize, reopened, edited]",
            "types: [opened, reopened, edited]",
        ),
        "triggers are not exactly the floor's triggers",
    ),
    (
        "pull_request ignores every path",
        (
            "    types: [opened, synchronize, reopened, edited]\n",
            "    types: [opened, synchronize, reopened, edited]\n    paths-ignore: ['**']\n",
        ),
        "triggers are not exactly the floor's triggers",
    ),
    (
        "privileged trigger in the floor",
        ("  workflow_dispatch:\n", "  workflow_dispatch:\n  pull_request_target:\n"),
        "privileged trigger pull_request_target",
    ),
    # failure is never masked
    (
        "|| grep",
        (RUFF, "      - run: ruff check . || grep -q zqxwvk .\n"),
        "failure masked by || grep",
    ),
    (
        "&& before the guarded command",
        (KAT, _step("[ -n zqxwvk ] && python scripts/kat_lint.py")),
        "python runs only after &&",
    ),
    (
        "pipe under a shell without pipefail",
        (KAT, KAT + "        shell: bash -e {0}\n"),
        "no explicit pipefail shell",
    ),
    # python runs only allowlisted scripts; nothing written to temp and run
    (
        "python other script",
        (KAT, _step("python zqxwvk.py")),
        "python runs a script that is not allowlisted",
    ),
    (
        "python -m other",
        (KAT, _step("python -m zqxwvk")),
        "python -m runs a module other than pytest or pip",
    ),
    ("python alone", (KAT, _step("python")), "python runs no script"),
    (
        "temp file written then run",
        (
            KAT,
            _step(
                'printf "%s" zqxwvk > "$RUNNER_TEMP/zqxwvk.py"\npython "$RUNNER_TEMP/zqxwvk.py"'
            ),
        ),
        "only a read-only git command may write into the temp dir",
    ),
    (
        "python runs a script variable",
        (KAT, _step('V=scripts/kat_lint.py\npython "$V"')),
        "python runs a script that is not allowlisted",
    ),
    # environment is allowlisted with exact values
    (
        "new env var",
        (
            "          ISOLATION_LAYER_ROOT: ${{ github.workspace }}/isolation-layer\n",
            "          ISOLATION_LAYER_ROOT: ${{ github.workspace }}/isolation-layer\n          ZQXWVK: x\n",
        ),
        "env sets ZQXWVK",
    ),
    (
        "env value changed",
        (
            "          AEGIS_ATOMS_ROOT: ${{ github.workspace }}/aegis-atoms\n",
            "          AEGIS_ATOMS_ROOT: ${{ github.workspace }}/zqxwvk\n",
        ),
        "env sets AEGIS_ATOMS_ROOT",
    ),
]


def _repin(root: Path) -> list[str]:
    (root / guard.PINS).write_bytes(_pins_text(root).encode("utf-8"))
    return guard.violations(root)


@pytest.mark.parametrize(
    ("label", "edit", "expect"), RULE_TAMPERS, ids=[t[0] for t in RULE_TAMPERS]
)
def test_each_class_is_caught_by_rules_with_pins_regenerated(
    tmp_path: Path, label: str, edit: tuple[str, str], expect: str
) -> None:
    root = _copy_tree(tmp_path)
    wf = root / ".github" / "workflows" / "floor.yml"
    text = wf.read_text(encoding="utf-8")
    old, new = edit
    assert text.count(old) >= 1, label
    wf.write_text(text.replace(old, new, 1), encoding="utf-8")
    found = _repin(root)
    assert any(expect in f for f in found), (label, found)


def test_the_live_floor_passes_every_rule_with_pins_regenerated(tmp_path: Path) -> None:
    assert _repin(_copy_tree(tmp_path)) == []


def test_pipefail_lets_a_guarded_command_feed_a_pipe(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    wf = root / ".github" / "workflows" / "floor.yml"
    text = wf.read_text(encoding="utf-8")
    wf.write_text(
        text.replace(
            KAT,
            _step("set -o pipefail\npython scripts/kat_lint.py | grep -v zqxwvk"),
            1,
        ),
        encoding="utf-8",
    )
    assert not any("hidden by a pipe" in f for f in _repin(root))


@pytest.mark.parametrize(
    ("label", "workflow", "expect"),
    [
        pytest.param(
            "privileged",
            "name: zqxwvk\non: pull_request_target\npermissions:\n  contents: read\njobs: {}\n",
            "workflow zqxwvk: privileged trigger pull_request_target",
            id="privileged-trigger",
        ),
        pytest.param(
            "write-on-pr",
            "name: zqxwvk\non: pull_request\npermissions:\n  contents: write\njobs: {}\n",
            "workflow zqxwvk: write permission with trigger(s) ['pull_request']",
            id="write-permission-on-pull-request",
        ),
        pytest.param(
            "write-all",
            "name: zqxwvk\non: [push, pull_request]\npermissions: write-all\njobs: {}\n",
            "workflow zqxwvk: write permission with trigger(s) ['pull_request']",
            id="write-all-on-pull-request",
        ),
        pytest.param(
            "job-write",
            "name: zqxwvk\non:\n  pull_request:\npermissions: {}\njobs:\n  x:\n    permissions:\n      id-token: write\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n",
            "workflow zqxwvk: write permission with trigger(s) ['pull_request']",
            id="job-write-permission-on-pull-request",
        ),
    ],
)
def test_every_workflow_file_has_its_triggers_and_permissions_judged(
    tmp_path: Path, label: str, workflow: str, expect: str
) -> None:
    root = _copy_tree(tmp_path)
    (root / ".github" / "workflows" / "zqxwvk.yml").write_text(
        workflow, encoding="utf-8"
    )
    found = _repin(root)
    assert expect in found, (label, found)


@pytest.mark.parametrize(
    ("extra", "expect"),
    [
        pytest.param("zqxwvk==1.0\n", "lock: entry", id="no-hash"),
        pytest.param(
            "zqxwvk>=1.0 \\\n    --hash=sha256:" + "a" * 64 + "\n",
            "lock: entry",
            id="range-not-pin",
        ),
        pytest.param(
            "-e git+https://example.invalid/zqxwvk\n", "lock: entry", id="editable-url"
        ),
        pytest.param(
            "--index-url https://example.invalid/simple\n",
            "lock: entry",
            id="index-url",
        ),
        pytest.param(
            "--extra-index-url https://example.invalid\n",
            "lock: entry",
            id="extra-index",
        ),
        pytest.param("-r zqxwvk.txt\n", "lock: entry", id="include"),
    ],
)
def test_lock_edits_are_judged_by_rules(
    tmp_path: Path, extra: str, expect: str
) -> None:
    root = _copy_tree(tmp_path)
    lock = root / guard.LOCK
    lock.write_text(lock.read_text(encoding="utf-8") + extra, encoding="utf-8")
    assert any(expect in f for f in _repin(root))


def test_an_empty_lock_is_a_rules_violation(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    (root / guard.LOCK).write_text("# nothing\n", encoding="utf-8")
    assert "lock: no requirements" in _repin(root)


@pytest.mark.parametrize(
    ("rel", "content", "expect"),
    [
        pytest.param(
            "pytest.ini",
            "[pytest]\nnorecursedirs = .* build dist design .tmp\nxfail_strict = true\nfilterwarnings =\n    error::SyntaxWarning\naddopts = -p no:zqxwvk\n",
            "key addopts is not allowed",
            id="addopts",
        ),
        pytest.param(
            "pytest.ini",
            "[pytest]\nnorecursedirs = .* build dist design .tmp\nxfail_strict = false\nfilterwarnings =\n    error::SyntaxWarning\n",
            "xfail_strict is not true",
            id="xfail-not-strict",
        ),
        pytest.param(
            "pytest.ini",
            "[pytest]\nnorecursedirs = .* build dist design .tmp\nxfail_strict = true\nfilterwarnings =\n    ignore::SyntaxWarning\n",
            "filterwarnings",
            id="warning-ignored",
        ),
        pytest.param(
            "pytest.ini",
            "[pytest]\nnorecursedirs = .* tests\nxfail_strict = true\nfilterwarnings =\n    error::SyntaxWarning\n",
            "hides tests",
            id="tests-not-recursed",
        ),
        pytest.param(
            "pytest.ini",
            "[pytest]\nnorecursedirs = .* build dist design .tmp\nxfail_strict = true\nfilterwarnings =\n    error::SyntaxWarning\n[zqxwvk]\nx = 1\n",
            "section other than",
            id="extra-section",
        ),
        pytest.param(
            "pyproject.toml",
            "[tool.pytest.ini_options]\naddopts = '--co'\n",
            "pyproject.toml configures pytest",
            id="pyproject-section",
        ),
        pytest.param(
            "tox.ini",
            "[pytest]\naddopts = --co\n",
            "tox.ini configures pytest",
            id="tox-section",
        ),
        pytest.param(
            "setup.cfg",
            "[tool:pytest]\naddopts = --co\n",
            "setup.cfg configures pytest",
            id="setup-cfg-section",
        ),
        pytest.param(
            "tests/conftest.py",
            "collect_ignore_glob = ['*']\n",
            "tests/conftest.py is not allowed",
            id="conftest",
        ),
    ],
)
def test_pytest_config_edits_are_judged_by_rules(
    tmp_path: Path, rel: str, content: str, expect: str
) -> None:
    root = _copy_tree(tmp_path)
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_text(content, encoding="utf-8")
    found = _repin(root)
    assert any(expect in f for f in found), found


# --- nothing pytest loads is hidden behind a link (brief 82-84 item 1) -----------


def _git(root: Path, *args: str) -> str:
    run = subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, check=True
    )
    return run.stdout.strip()


def _git_tree(tmp_path: Path) -> Path:
    root = _copy_tree(tmp_path)
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "zqxwvk@example.invalid")
    _git(root, "config", "user.name", "zqxwvk")
    _git(root, "config", "core.symlinks", "false")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "tree")
    return root


def test_a_committed_directory_symlink_into_a_skipped_dir_fails_the_guard(
    tmp_path: Path,
) -> None:
    """Index mode 120000 is a symlink whatever the checkout platform does with it."""
    root = _git_tree(tmp_path)
    hidden = root / ".tmp" / "zqxwvk"
    hidden.mkdir(parents=True)
    (hidden / "conftest.py").write_text(
        "collect_ignore_glob = ['*']\n", encoding="utf-8"
    )
    blob = subprocess.run(
        ["git", "hash-object", "-w", "--stdin"],
        cwd=root,
        input="../.tmp/zqxwvk",
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    _git(root, "update-index", "--add", "--cacheinfo", f"120000,{blob},tests/zqxwvk")
    _git(root, "commit", "-q", "-m", "link")
    found = guard.violations(root)
    assert "tracked symlink tests/zqxwvk: the guard does not follow links" in found, (
        found
    )


def test_a_symlink_on_disk_into_a_skipped_dir_fails_the_guard(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    hidden = root / ".tmp" / "zqxwvk"
    hidden.mkdir(parents=True)
    (hidden / "conftest.py").write_text(
        "collect_ignore_glob = ['*']\n", encoding="utf-8"
    )
    os.symlink(hidden, root / "tests" / "zqxwvk", target_is_directory=True)
    found = guard.violations(root)
    assert "symlink tests/zqxwvk: the guard does not follow links" in found, found


def test_a_file_symlink_to_a_guard_file_fails_the_guard(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    os.symlink(root / "pytest.ini", root / "zqxwvk.ini")
    found = guard.violations(root)
    assert "symlink zqxwvk.ini: the guard does not follow links" in found, found


def test_a_tree_without_symlinks_passes(tmp_path: Path) -> None:
    assert guard.violations(_git_tree(tmp_path)) == []


# --- a guardrail step fails whenever its command fails (item 2) -------------------
# The floor sets one pipefail shell for every step and the rules refuse every
# construct that can keep a failing command from failing the step.

FLOOR_DEFAULTS = (
    "defaults:\n  run:\n    shell: bash --noprofile --norc -eo pipefail {0}\n"
)

STEP_EXIT_TAMPERS = [
    pytest.param(
        "python scripts/kat_lint.py &\nwait",
        "runs a command in the background",
        id="background",
    ),
    pytest.param(
        "[ -n zqxwvk ] && python scripts/kat_lint.py", "uses &&", id="and-list"
    ),
    pytest.param(
        "python scripts/kat_lint.py && echo done", "uses &&", id="non-final-and"
    ),
    pytest.param("python scripts/kat_lint.py || exit 1", "uses ||", id="or-list"),
    pytest.param(
        "if python scripts/kat_lint.py; then echo ok; fi",
        "uses a condition",
        id="if-condition",
    ),
    pytest.param(
        "if [ -n zqxwvk ]; then python scripts/kat_lint.py; fi",
        "uses a condition",
        id="if-around-the-check",
    ),
    pytest.param(
        "while python scripts/kat_lint.py; do break; done",
        "uses a condition",
        id="while-condition",
    ),
    pytest.param(
        "until python scripts/kat_lint.py; do break; done",
        "uses a condition",
        id="until-condition",
    ),
    pytest.param(
        'echo "$(python scripts/kat_lint.py)"',
        "uses command substitution",
        id="dollar-paren",
    ),
    pytest.param(
        "echo `python scripts/kat_lint.py`", "uses command substitution", id="backticks"
    ),
    pytest.param(
        "grep -c zqxwvk <(python scripts/kat_lint.py)",
        "uses command substitution",
        id="process-substitution",
    ),
    pytest.param("! python scripts/kat_lint.py", "exit status negated", id="negation"),
]


@pytest.mark.parametrize(("run", "expect"), STEP_EXIT_TAMPERS)
def test_a_construct_that_can_hide_a_failure_is_a_rules_violation(
    tmp_path: Path, run: str, expect: str
) -> None:
    root = _copy_tree(tmp_path)
    wf = root / ".github" / "workflows" / "floor.yml"
    text = wf.read_text(encoding="utf-8")
    assert KAT in text
    wf.write_text(text.replace(KAT, _step(run), 1), encoding="utf-8")
    (root / guard.PINS).write_text(_pins_text(root), encoding="utf-8")
    found = guard.violations(root)
    assert any(expect in f for f in found), found


def test_a_pipe_is_allowed_only_under_the_pipefail_shell(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    wf = root / ".github" / "workflows" / "floor.yml"
    text = wf.read_text(encoding="utf-8")
    assert FLOOR_DEFAULTS in text
    piped = text.replace(KAT, _step("python scripts/kat_lint.py | grep -v zqxwvk"), 1)
    wf.write_text(piped, encoding="utf-8")
    (root / guard.PINS).write_text(_pins_text(root), encoding="utf-8")
    assert not any("pipe" in f for f in guard.violations(root))
    wf.write_text(piped.replace(FLOOR_DEFAULTS, "", 1), encoding="utf-8")
    (root / guard.PINS).write_text(_pins_text(root), encoding="utf-8")
    assert any("no explicit pipefail shell" in f for f in guard.violations(root))


def test_a_step_with_no_explicit_shell_is_unsafe(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    wf = root / ".github" / "workflows" / "floor.yml"
    text = wf.read_text(encoding="utf-8")
    assert FLOOR_DEFAULTS in text
    wf.write_text(text.replace(FLOOR_DEFAULTS, "", 1), encoding="utf-8")
    (root / guard.PINS).write_text(_pins_text(root), encoding="utf-8")
    found = guard.violations(root)
    assert any(f.endswith("step 3: no explicit pipefail shell") for f in found), found


@pytest.mark.parametrize(
    "shell",
    [pytest.param("bash -e {0}", id="no-pipefail"), pytest.param("sh -e {0}", id="sh")],
)
def test_a_step_shell_without_pipefail_is_unsafe(tmp_path: Path, shell: str) -> None:
    root = _copy_tree(tmp_path)
    wf = root / ".github" / "workflows" / "floor.yml"
    text = wf.read_text(encoding="utf-8")
    wf.write_text(
        text.replace(KAT, KAT + f"        shell: {shell}\n", 1), encoding="utf-8"
    )
    (root / guard.PINS).write_text(_pins_text(root), encoding="utf-8")
    found = guard.violations(root)
    assert any("shell is not an allowlisted value" in f for f in found), found


def test_the_live_floor_steps_hold_no_hiding_construct() -> None:
    wf = _workflow()
    assert guard.job_violations(wf) == []
    runs = "\n".join(
        str(step.get("run", ""))
        for job in wf["jobs"].values()
        for step in job.get("steps", [])
    )
    for token in (" && ", " || ", "$(", "`", "if ", "while "):
        assert token not in runs, token


def test_pipefail_stops_a_failing_pipe_in_each_allowed_shell(tmp_path: Path) -> None:
    script = tmp_path / "pipe.sh"
    script.write_bytes(b"false | true\necho zqxwvk-reached\n")
    for value in sorted(guard.SHELL_ALLOWLIST):
        words = value.split()
        exe = shutil.which(words[0])
        assert exe, words[0]
        argv = [exe] + [
            str(script).replace("\\", "/") if w == "{0}" else w for w in words[1:]
        ]
        run = subprocess.run(argv, capture_output=True, text=True)
        assert run.returncode != 0, value
        assert "zqxwvk-reached" not in run.stdout, value


# --- python never runs from a world-writable place (item 11) ---------------------


@pytest.mark.parametrize(
    "path",
    [
        "/tmp/zqxwvk.py",
        "/var/tmp/zqxwvk.py",
        "/dev/shm/zqxwvk.py",
        "$TMPDIR/zqxwvk.py",
        "${TMPDIR}/zqxwvk.py",
    ],
)
def test_python_never_runs_a_script_from_a_world_writable_place(
    tmp_path: Path, path: str
) -> None:
    root = _copy_tree(tmp_path)
    wf = root / ".github" / "workflows" / "floor.yml"
    text = wf.read_text(encoding="utf-8")
    wf.write_text(text.replace(KAT, _step(f'python "{path}"'), 1), encoding="utf-8")
    (root / guard.PINS).write_text(_pins_text(root), encoding="utf-8")
    found = guard.violations(root)
    assert any("python runs a script that is not allowlisted" in f for f in found), (
        found
    )


def test_every_allowlisted_python_script_is_in_the_repo_or_the_runner_temp() -> None:
    for script in guard.PY_SCRIPTS:
        assert not script.startswith(
            ("/tmp", "/var/tmp", "/dev/shm", "$TMPDIR", "${TMPDIR}")
        )
        assert script.startswith(("$RUNNER_TEMP/", "scripts/", ".floor/")), script


# --- the authorship check runs as a plain command ---------------------------------


def _trailer_check(tmp_path: Path, text: str) -> subprocess.CompletedProcess:
    history = tmp_path / "history.txt"
    history.write_text(text, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "no_ai_trailers.py"), str(history)],
        capture_output=True,
        text=True,
    )


# Each trailer is assembled from a key and a tool name kept on separate lines,
# so no line of this file reads as a trailer to the repository's leak scans.
_TRAILER_CASES = [
    pytest.param(
        "Co-authored-by:",
        "Claude <noreply@example.invalid>",
        id="co-author-claude",
    ),
    pytest.param(
        "co-authored-by:",
        "zqxwvk via Cursor",
        id="co-author-cursor-lower",
    ),
    pytest.param(
        "Co-Authored-By:",
        "GitHub Copilot",
        id="co-author-copilot-title",
    ),
    pytest.param(
        "Generated with",
        "Claude Code",
        id="generated-claude",
    ),
    pytest.param(
        "generated with",
        "cursor",
        id="generated-cursor-lower",
    ),
]


@pytest.mark.parametrize(("key", "tool"), _TRAILER_CASES)
def test_the_trailer_check_fails_on_an_ai_trailer(
    tmp_path: Path, key: str, tool: str
) -> None:
    line = f"{key} {tool}"
    run = _trailer_check(tmp_path, f"Fix zqxwvk\n\n{line}\n")
    assert run.returncode == 1, run.stdout
    assert "AI authorship trailer" in run.stdout


def test_the_trailer_check_passes_clean_history_and_fails_on_none(
    tmp_path: Path,
) -> None:
    run = _trailer_check(
        tmp_path, "Fix zqxwvk\n\nCo-authored-by: A Person <a@example.invalid>\n"
    )
    assert run.returncode == 0, run.stdout
    assert "lines checked" in run.stdout
    assert _trailer_check(tmp_path, "").returncode == 1


# --- the classes base pins caught alone are rules too (brief 82-84 item 10) -------

EXACT_TAMPERS = [
    pytest.param(
        (KAT, "      - run: python scripts/kat_lint.py --root zqxwvk\n"),
        "python scripts/kat_lint.py arguments are not the allowlisted ones",
        id="guard-script-gains-an-argument",
    ),
    pytest.param(
        (" --prose --fail-on-warn", " --prose"),
        "python .floor/craft/voice_lint.py arguments are not the allowlisted ones",
        id="craft-script-loses-an-argument",
    ),
    pytest.param(
        (
            '--pins "$RUNNER_TEMP/floor/floor-pins.json"',
            "--pins .github/floor-pins.json",
        ),
        "arguments are not the allowlisted ones",
        id="floor-guard-judged-with-the-tree-pins",
    ),
    pytest.param(
        (RUFF, "      - run: ruff check scripts\n"),
        "ruff arguments are not the allowlisted ones",
        id="ruff-narrowed",
    ),
    pytest.param(
        ("  cancel-in-progress: true\n", "  cancel-in-progress: false\n"),
        "concurrency is not the floor's pinned value",
        id="concurrency-changed",
    ),
    pytest.param(
        ("name: floor\n", "name: floor\nrun-name: zqxwvk\n"),
        "workflow: key run-name is not allowed",
        id="top-level-key-added",
    ),
    pytest.param(
        (
            "    name: tests (known-answer tests call the gate)\n    timeout-minutes: 10\n",
            "    name: tests (known-answer tests call the gate)\n    timeout-minutes: 2\n",
        ),
        "timeout is not the pinned 10 minutes",
        id="timeout-inside-the-range",
    ),
]


@pytest.mark.parametrize(("edit", "expect"), EXACT_TAMPERS)
def test_a_value_only_pins_caught_is_now_a_rules_violation(
    tmp_path: Path, edit: tuple[str, str], expect: str
) -> None:
    root = _copy_tree(tmp_path)
    wf = root / ".github" / "workflows" / "floor.yml"
    text = wf.read_text(encoding="utf-8")
    old, new = edit
    assert old in text
    wf.write_text(text.replace(old, new, 1), encoding="utf-8")
    (root / guard.PINS).write_text(_pins_text(root), encoding="utf-8")
    found = guard.violations(root)
    assert any(expect in f for f in found), found


def test_no_tamper_is_left_to_pins_alone() -> None:
    assert [label for label, *_rest, pin_only in TAMPERS if pin_only] == []


# --- brief 82-41b: properties judged by rules, each red first ---------------------
# Every case edits the parsed workflow, writes it back and regenerates the pins,
# as a pull request that changes the floor would, so only the rules can catch it.


def _plant_wf(tmp_path: Path, edit) -> list[str]:
    root = _copy_tree(tmp_path)
    wf = root / ".github" / "workflows" / "floor.yml"
    doc = yaml.safe_load(wf.read_text(encoding="utf-8"))
    edit(doc)
    wf.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return _repin(root)


def _last_run(job: str) -> str:
    return str(_workflow()["jobs"][job]["steps"][-1]["run"]).strip()


def _set_last_run(job: str, run: str):
    def edit(doc: dict) -> None:
        doc["jobs"][job]["steps"][-1]["run"] = run

    return edit


def _parsed(run: str) -> list[list[str]]:
    import bashlex

    out: list[list[str]] = []

    def walk(node) -> None:
        if getattr(node, "kind", None) == "command":
            out.append([p.word for p in node.parts if p.kind == "word"])
        for attr in ("parts", "list"):
            for child in getattr(node, attr, None) or []:
                if hasattr(child, "kind"):
                    walk(child)

    for tree in bashlex.parse(run):
        walk(tree)
    return out


def _live_commands() -> list[tuple[str, list[str]]]:
    return [
        (key, words)
        for key, job in _workflow()["jobs"].items()
        for step in job.get("steps") or []
        if step.get("run")
        for words in _parsed(str(step["run"]))
    ]


def test_the_plant_helper_keeps_the_live_floor_clean(tmp_path: Path) -> None:
    assert _plant_wf(tmp_path, lambda doc: None) == []


# P1: guardrail python runs isolated, so no file in the checkout is importable.


def test_every_python_in_the_live_floor_runs_isolated() -> None:
    pythons = [w for _key, w in _live_commands() if w[0] in {"python", "python3"}]
    assert len(pythons) >= 12
    for words in pythons:
        assert words[1] == "-I", words


@pytest.mark.parametrize(
    ("job", "run"),
    [
        pytest.param("kat-lint", "python scripts/kat_lint.py", id="script"),
        pytest.param("kat-lint", "python3 scripts/kat_lint.py", id="python3"),
        pytest.param("kat-lint", "python -P scripts/kat_lint.py", id="safe-path-only"),
        pytest.param("kat-lint", "python -E -I scripts/kat_lint.py", id="flag-first"),
        pytest.param(
            "lint",
            "python -m pip install --require-hashes --no-deps -r requirements-ci.lock",
            id="pip",
        ),
        pytest.param("tests", "python -m pytest -q", id="pytest-module"),
    ],
)
def test_python_that_is_not_isolated_is_a_rules_violation(
    tmp_path: Path, job: str, run: str
) -> None:
    found = _plant_wf(tmp_path, _set_last_run(job, run))
    assert any("python does not run isolated (-I)" in f for f in found), found


def _shadow(marker: Path) -> str:
    return (
        "import pathlib\n"
        f"pathlib.Path({str(marker)!r}).write_text('loaded', encoding='utf-8')\n"
        "raise SystemExit(0)\n"
    )


def test_a_stdlib_named_module_beside_a_guard_script_never_loads(
    tmp_path: Path,
) -> None:
    """The kat-lint step, run as the live floor runs it, ignores scripts/argparse.py."""
    words = next(w for key, w in _live_commands() if key == "kat-lint")
    tree = tmp_path / "tree"
    (tree / "scripts").mkdir(parents=True)
    shutil.copyfile(ROOT / "scripts" / "kat_lint.py", tree / "scripts" / "kat_lint.py")
    marker = tmp_path / "loaded.txt"
    (tree / "scripts" / "argparse.py").write_text(_shadow(marker), encoding="utf-8")
    # The fixture bites: without isolation the shadow runs instead of the guard.
    subprocess.run(
        [sys.executable, "scripts/kat_lint.py"], cwd=tree, capture_output=True
    )
    assert marker.exists()
    marker.unlink()
    subprocess.run([sys.executable, *words[1:]], cwd=tree, capture_output=True)
    assert not marker.exists(), words


def test_a_package_main_in_the_checkout_never_replaces_pip(tmp_path: Path) -> None:
    """Each live install, run as the floor runs it, ignores a pip/__main__.py."""
    tree = tmp_path / "tree"
    (tree / "pip").mkdir(parents=True)
    marker = tmp_path / "loaded.txt"
    (tree / "pip" / "__init__.py").write_text("", encoding="utf-8")
    (tree / "pip" / "__main__.py").write_text(_shadow(marker), encoding="utf-8")
    subprocess.run(
        [sys.executable, "-m", "pip", "--version"], cwd=tree, capture_output=True
    )
    assert marker.exists()
    installs = [w for _k, w in _live_commands() if "pip" in w]
    assert len(installs) >= 3
    for words in installs:
        marker.unlink(missing_ok=True)
        upto = words.index("pip") + 1
        subprocess.run(
            [sys.executable, *words[1:upto], "--version"], cwd=tree, capture_output=True
        )
        assert not marker.exists(), words


# P2: every guardrail command runs, judged as parsed commands.


@pytest.mark.parametrize(
    ("template", "expect"),
    [
        pytest.param("kat_lint() { true; }\nLIVE", "defines a function", id="function"),
        pytest.param(
            "function python { :; }\nLIVE", "defines a function", id="function-keyword"
        ),
        pytest.param("for x in zqxwvk; do LIVE; done", "uses a loop", id="for-loop"),
        pytest.param("for x in; do LIVE; done", "uses a loop", id="empty-loop"),
        pytest.param("( LIVE )", "uses a subshell or command group", id="subshell"),
        pytest.param("{ LIVE; }", "uses a subshell or command group", id="group"),
        pytest.param(
            "timeout 1 LIVE", "command timeout is not allowlisted", id="timeout"
        ),
        pytest.param("nice LIVE", "command nice is not allowlisted", id="nice"),
    ],
)
def test_a_construct_that_defines_shadows_or_skips_a_command_is_rejected(
    tmp_path: Path, template: str, expect: str
) -> None:
    run = template.replace("LIVE", _last_run("kat-lint"))
    found = _plant_wf(tmp_path, _set_last_run("kat-lint", run))
    assert any(expect in f for f in found), found


@pytest.mark.parametrize(
    ("job", "run", "missing"),
    [
        pytest.param("kat-lint", "echo LIVE", "kat_lint.py", id="kat-lint-echoed"),
        pytest.param("tests", "echo pytest -q", "pytest -q", id="pytest-echoed"),
        pytest.param(
            "lint", "true ruff format --check .", "ruff format", id="ruff-behind-true"
        ),
        pytest.param("kat-lint", "printf '%s' LIVE", "kat_lint.py", id="printed"),
    ],
)
def test_a_required_command_is_a_parsed_command_not_a_substring(
    tmp_path: Path, job: str, run: str, missing: str
) -> None:
    run = run.replace("LIVE", _last_run(job))
    found = _plant_wf(tmp_path, _set_last_run(job, run))
    assert any(
        f"job {job}: required command" in f and missing in f and "is missing" in f
        for f in found
    ), found


@pytest.mark.parametrize(
    "masker",
    [
        "echo pytest -q",
        "printf '%s' ruff",
        "true python",
        ": git log",
        "test -n pytest",
        "[ -n kat_lint.py ]",
        "echo scripts/floor_guard.py",
    ],
)
def test_a_no_op_naming_a_guarded_tool_is_rejected(tmp_path: Path, masker: str) -> None:
    run = f"{masker}\n{_last_run('kat-lint')}"
    found = _plant_wf(tmp_path, _set_last_run("kat-lint", run))
    assert any("names a guarded tool as an argument" in f for f in found), found


# P3: allowed commands take exact argument shapes, judged per job.

_GIT_BAD = [
    "git fetch --upload-pack=zqxwvk origin",
    "git fetch -u zqxwvk origin",
    "git fetch --upload-pack zqxwvk origin",
    "git log --output=zqxwvk.txt",
    "git diff --ext-diff",
    "git log -p --textconv",
    "git diff --no-index zqxwvk.a zqxwvk.b",
    "git fetch origin main:zqxwvk",
    "git fetch https://example.invalid/zqxwvk.git",
    "git fetch file:///tmp/zqxwvk",
    "git -c core.pager=zqxwvk log",
    "git rev-parse --verify zqxwvk",
    "git cat-file -e origin/main:zqxwvk.py",
    'git show origin/main:scripts/kat_lint.py > "$RUNNER_TEMP/zqxwvk.py"',
    'git show origin/main:scripts/kat_lint.py > "$RUNNER_TEMP/leak_scan.py"',
    'git log --all --format=%B > "$RUNNER_TEMP/zqxwvk.py"',
]


@pytest.mark.parametrize("bad", _GIT_BAD)
def test_git_takes_only_its_exact_shapes(tmp_path: Path, bad: str) -> None:
    run = f"{bad}\n{_last_run('kat-lint')}"
    found = _plant_wf(tmp_path, _set_last_run("kat-lint", run))
    assert any("git arguments are not an allowlisted shape" in f for f in found), found


_TAR = "tar -C /tmp -xzf /tmp/actionlint.tgz actionlint"
_TAR_BAD = [
    "tar -C /tmp -xzf /tmp/actionlint.tgz --checkpoint=1 "
    "--checkpoint-action=exec=zqxwvk actionlint",
    "tar -C /tmp -xzf /tmp/actionlint.tgz --to-command=zqxwvk actionlint",
    "tar -C /tmp -I zqxwvk -xf /tmp/actionlint.tgz actionlint",
    "tar -C /tmp --use-compress-program=zqxwvk -xf /tmp/actionlint.tgz actionlint",
    "tar -C /tmp -xzf /tmp/actionlint.tgz -T zqxwvk",
    "tar -C . -xzf /tmp/actionlint.tgz actionlint",
    "tar -C /tmp -xzf /tmp/actionlint.tgz",
    "tar -C /tmp -xzf /tmp/actionlint.tgz conftest.py",
]


@pytest.mark.parametrize("bad", _TAR_BAD)
def test_tar_takes_only_its_pinned_arguments(tmp_path: Path, bad: str) -> None:
    def edit(doc: dict) -> None:
        step = doc["jobs"]["workflow-lint"]["steps"][-1]
        assert _TAR in step["run"]
        step["run"] = step["run"].replace(_TAR, bad)

    found = _plant_wf(tmp_path, edit)
    assert any("tar arguments are not the pinned ones" in f for f in found), found


def test_tar_runs_only_in_the_workflow_lint_job(tmp_path: Path) -> None:
    run = f"{_TAR}\n{_last_run('kat-lint')}"
    found = _plant_wf(tmp_path, _set_last_run("kat-lint", run))
    assert any("tar is allowed only in the workflow-lint job" in f for f in found), (
        found
    )


@pytest.mark.parametrize(
    "bad",
    [
        'cp "$RUNNER_TEMP/zqxwvk" test_zqxwvk.py',
        'cp "$RUNNER_TEMP/zqxwvk" zqxwvk/test_zqxwvk.py',
        'cp -t . "$RUNNER_TEMP/conftest.py"',
        'cp "$RUNNER_TEMP/zqxwvk" zqxwvk_plugin.py',
        "echo zqxwvk > test_zqxwvk.py",
        "printf zqxwvk > zqxwvk_test.py",
        "mkdir -p zqxwvk",
        'mkdir -p "$RUNNER_TEMP/floor"',
    ],
)
def test_no_write_outside_its_exact_shape_can_plant_a_test_file(
    tmp_path: Path, bad: str
) -> None:
    run = f"{bad}\n{_last_run('kat-lint')}"
    found = _plant_wf(tmp_path, _set_last_run("kat-lint", run))
    assert any(
        "is not an allowlisted command shape for job kat-lint" in f for f in found
    ), found


# P5: workflow-level defaults are judged.

_SHELL = "bash --noprofile --norc -eo pipefail {0}"


@pytest.mark.parametrize(
    "run_defaults",
    [
        {"shell": _SHELL, "working-directory": "zqxwvk"},
        {"shell": _SHELL, "working-directory": "tests"},
        {"shell": "bash -eo pipefail {0}", "working-directory": "capability-gate"},
    ],
)
def test_workflow_level_defaults_are_judged(tmp_path: Path, run_defaults: dict) -> None:
    def edit(doc: dict) -> None:
        doc["defaults"] = {"run": run_defaults}

    found = _plant_wf(tmp_path, edit)
    assert any(
        "workflow: defaults are not exactly the floor's shell" in f for f in found
    ), found


# P7 D4: the workflow loads without duplicate keys; D3: odd tags fail closed.


@pytest.mark.parametrize(
    ("old", "new"),
    [
        pytest.param(
            "    name: tests (known-answer tests call the gate)\n",
            "    name: tests (known-answer tests call the gate)\n"
            "    runs-on: self-hosted\n",
            id="job-key",
        ),
        pytest.param(
            "permissions:\n  contents: read\n",
            "permissions:\n  contents: read\npermissions:\n  contents: write\n",
            id="top-level-key",
        ),
    ],
)
def test_a_duplicate_workflow_key_is_a_violation(
    tmp_path: Path, old: str, new: str
) -> None:
    root = _copy_tree(tmp_path)
    wf = root / ".github" / "workflows" / "floor.yml"
    text = wf.read_text(encoding="utf-8")
    assert old in text
    wf.write_text(text.replace(old, new, 1), encoding="utf-8")
    found = guard.violations(root)
    assert any("duplicate key" in f for f in found), found


@pytest.mark.parametrize(
    "new",
    [
        "name: !!binary emFxeHdyaw==\n",
        "name: 2026-10-14\n",
        "name: !!set {zqxwvk: null}\n",
        "name: !!python/name:os.system\n",
    ],
)
def test_an_odd_yaml_tag_fails_closed_without_a_traceback(
    tmp_path: Path, new: str
) -> None:
    root = _copy_tree(tmp_path)
    wf = root / ".github" / "workflows" / "floor.yml"
    text = wf.read_text(encoding="utf-8")
    wf.write_text(text.replace("name: floor\n", new, 1), encoding="utf-8")
    guard_py = str(ROOT / "scripts" / "floor_guard.py")
    r = subprocess.run(
        [sys.executable, guard_py, "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 1, r.stdout + r.stderr
    assert "Traceback" not in r.stdout + r.stderr, r.stderr
    assert "does not load" in r.stdout, r.stdout


# P7 N4: no test module declares pytest_plugins.


@pytest.mark.parametrize(
    ("rel", "text"),
    [
        ("tests/test_zqxwvk.py", 'pytest_plugins = ["zqxwvk_plugin"]\n'),
        ("tests/test_zqxwvk.py", 'pytest_plugins: list = ["zqxwvk_plugin"]\n'),
        ("zqxwvk_test.py", 'pytest_plugins = "zqxwvk_plugin"\n'),
        ("tests/test_zqxwvk.py", 'globals()["pytest_plugins"] = ["zqxwvk"]\n'),
    ],
)
def test_a_pytest_plugins_declaration_is_a_violation(
    tmp_path: Path, rel: str, text: str
) -> None:
    root = _copy_tree(tmp_path)
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_text(text, encoding="utf-8")
    found = _repin(root)
    assert any(f"{rel}: declares pytest_plugins" in f for f in found), found


# P7 PR82-5: startup files and every pytest config spelling are rules violations.


@pytest.mark.parametrize(
    ("rel", "text", "expect"),
    [
        ("sitecustomize.py", "x = 1\n", "interpreter startup file"),
        ("usercustomize.py", "x = 1\n", "interpreter startup file"),
        ("zqxwvk.pth", "import os\n", "interpreter startup file"),
        ("tests/sitecustomize.py", "x = 1\n", "interpreter startup file"),
        (".pytest.ini", "[pytest]\naddopts = -q\n", ".pytest.ini configures pytest"),
        (
            "pyproject.toml",
            "[ tool . pytest . ini_options ]\naddopts = '-q'\n",
            "pyproject.toml configures pytest",
        ),
        (
            "pyproject.toml",
            '[tool."pytest".ini_options]\naddopts = "-q"\n',
            "pyproject.toml configures pytest",
        ),
        ("setup.cfg", "[ tool:pytest ]\naddopts = -q\n", "setup.cfg configures pytest"),
        ("tox.ini", "[ pytest ]\naddopts = -q\n", "tox.ini configures pytest"),
        ("pyproject.toml", "[tool\n", "pyproject.toml does not parse"),
    ],
)
def test_startup_files_and_pytest_config_spellings_are_rules_violations(
    tmp_path: Path, rel: str, text: str, expect: str
) -> None:
    root = _copy_tree(tmp_path)
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_text(text, encoding="utf-8")
    found = _repin(root)
    assert any(expect in f for f in found), found
