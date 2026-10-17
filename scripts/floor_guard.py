"""Floor guard: the CI floor is exactly what review approved, and stays honest.

Two layers.

1. Pins. ``.github/floor-pins.json`` records a sha256 for the workflow's
   top-level settings, for every job (canonical JSON after YAML parsing, so
   every field counts: run text, shell, inputs, working directory, timeouts,
   runner, matrix, ``if``), and for every guard file: the scripts the jobs
   call, the pytest configuration, every conftest, the dependency lock, and
   this guard with its tests. Any difference, any job or guard file added or
   removed, is a violation. Changing the floor means changing the pins in the
   same pull request, in plain sight.

2. Rules, so the pinned values themselves cannot be weak. A legitimate floor
   change regenerates the pins, so every rule here is tested with the pins
   regenerated. Every run step runs under an allowlisted pipefail shell, and
   its run text is parsed as shell (bashlex): no condition, ``&&``, ``||``,
   background job, command or process substitution or ``!`` may hide a
   failing command; nothing may switch off stop-on-error, write a runner
   environment, path, output or state file by any spelling, run constructed,
   indirect or unlisted commands, run python other than the listed scripts,
   write into the temp directory except from git, add pytest options, install
   anything but the hash-locked lock file, or make a lint step non-failing.
   A protected-jobs table fixes each job's key, check names and required
   actions (matched against uses, never run text), and every required
   command must run as a parsed command; a per-job table fixes the exact
   shape of every simple command a job may run, compared as written with
   quotes and backslashes kept, and python must run isolated (-I) so no
   checkout file is importable. A $ the shell does not expand, an
   assignment-only command and a path holding $, a backtick or a backslash
   are refused. Functions, loops, subshells and groups are refused, and no
   no-op may name a guarded tool. The lint config must be the pinned one,
   and the floor's conftest must hold its pinned content.
   Job and step conditions, environment, runner, timeout, matrix, workflow
   defaults and every workflow's triggers and write permissions are
   allowlisted. Workflows and the pin file load strictly (no repeated key, no
   odd tag), the lock and pytest configuration are judged by rule, no test
   module names pytest_plugins, no interpreter startup file may exist, and
   any symlink fails the guard, which never follows links.

Where it loads from: in CI the guard script, its pins and its lock come from
the pull request's base (see floor.yml); for a stacked pull request that base
is another feature branch, not main. The floor-guard job definition itself
comes from the pull request, so a repository ruleset or required workflow is
the structural fix; that is a settings action for the maintainer. Until this
version of the guard is on the base, the base copy that judges a pull request
lacks the rules this version adds.

Usage: python scripts/floor_guard.py [--root DIR] [--update-pins] [--pins FILE]
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import itertools
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = Path(".github/workflows/floor.yml")
PINS = Path(".github/floor-pins.json")
LOCK = "requirements-ci.lock"
LOCKED_INSTALLS = frozenset(
    {
        f"python -I -m pip install --require-hashes --no-deps -r {LOCK}",
        f"python -I -m pip install --require-hashes --no-deps -r $RUNNER_TEMP/floor/{LOCK}",
    }
)
REPO = "Steck43/capability-gate"
SIBLING_REF = re.compile(r"[0-9a-f]{40}")
TOKEN_ENV = {"GITHUB_TOKEN": "${{ secrets.GITHUB_TOKEN }}"}

# Guard files pinned by content. Globbed groups must match the pinned set
# exactly, so adding a conftest or a pytest config file is a violation too.
GUARD_FILES = (
    "scripts/floor_guard.py",
    "scripts/kat_lint.py",
    "scripts/kat_swap.py",
    "scripts/leak_denylist_scan.py",
    "scripts/gh_pr.py",
    "scripts/no_ai_trailers.py",
    "scripts/run_record_check.py",
    "tests/test_floor_config.py",
    # Files the KAT lint exempts from discovery by name or receipts path.
    "tests/test_kat_lint.py",
    "tests/test_public_text_paths.py",
    LOCK,
    "ruff.toml",
    ".pre-commit-config.yaml",
    ".gitleaks.toml",
    ".gitleaksignore",
)
GUARD_GLOBS = (
    ".floor/**/*.py",
    "craft/**/*.py",
    "**/conftest.py",
    "pytest.ini",
    "**/pyproject.toml",
    "**/ruff.toml",
    "**/.ruff.toml",
    "**/.ignore",
    "tox.ini",
    "setup.cfg",
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    # Interpreter startup files: python imports sitecustomize from sys.path at
    # startup, and a .pth file runs code when its directory is a site dir.
    "**/sitecustomize.py",
    "**/usercustomize.py",
    "**/*.pth",
    "**/.pytest.ini",
)

# The floor's conftest (see its docstring), by exact content: it refuses a
# plugin that registers during collection and writes the run record. Changing
# it is a change to this file, which base pins catch.
FLOOR_CONFTEST_SHA256 = (
    "45795ef6e04b4e937e4485d270a60bed18041759be8541af5205921752f8d986"
)

ALLOWED_COMMANDS = frozenset(
    {
        "[",
        "test",
        "echo",
        "printf",
        "git",
        "python",
        "python3",
        "pytest",
        "ruff",
        "exit",
        "cp",
        "grep",
        "sha256sum",
        "tar",
        "curl",
        "mkdir",
        "true",
        "false",
        "/tmp/actionlint",
    }
)
# Commands that run other code, change shell behaviour, or hide what runs.
INDIRECT = frozenset(
    {
        "eval",
        "exec",
        "source",
        ".",
        "bash",
        "sh",
        "zsh",
        "dash",
        "env",
        "sudo",
        "xargs",
        "command",
        "builtin",
        "alias",
        "unalias",
        "trap",
        "shopt",
        "enable",
        "unset",
        "declare",
        "typeset",
        "readonly",
        "local",
        "export",
        "hash",
        "set",
        "pip",
        "pip3",
        "uv",
        "poetry",
        "conda",
        "npm",
        "apt",
        "apt-get",
        "tee",
        "dd",
        "install",
        "ln",
        "mv",
        "sed",
        "awk",
        "perl",
        "ruby",
        "node",
        "nohup",
        "time",
    }
)
SENSITIVE_VARS = re.compile(
    r"^(?:BASH_ENV|ENV|SHELLOPTS|BASHOPTS|IFS|PS4|PROMPT_COMMAND|PATH|HOME|LD_\w*|"
    r"DYLD_\w*|PYTHON\w*|PIP_\w*|UV_\w*|PYTEST_\w*|GIT_\w*|GITHUB_\w*|RUNNER_\w*|"
    r"NODE_OPTIONS|NODE_PATH|PERL5\w*|RUBY\w*|CURL_\w*|SSL_\w*|REQUESTS_CA_BUNDLE|"
    r"http_proxy|https_proxy|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY|TMPDIR|"
    r"ACTIONS_\w*|CI)$"
)
GIT_READ_ONLY = frozenset(
    {
        "rev-parse",
        "show",
        "cat-file",
        "rev-list",
        "log",
        "fetch",
        "diff",
        "ls-files",
        "merge-base",
    }
)
# Files a guardrail step may never write: the guard, its pins, pytest and
# dependency configuration, and anything under .github, scripts or tests.
PROTECTED_NAMES = re.compile(
    r"(?:^|/)(?:pytest\.ini|conftest\.py|pyproject\.toml|tox\.ini|setup\.cfg|"
    r"requirements[\w.-]*|\.pre-commit-config\.yaml|\.gitleaks\.toml|floor-pins\.json|"
    r"sitecustomize\.py|usercustomize\.py|[\w.-]+\.pth)$"
)
PROTECTED_DIRS = (".github/", "scripts/", "tests/", ".floor/", "craft/", ".git/")
MASKS = frozenset({"true", ":", "echo", "printf"})
READ_ONLY = {"contents": "read"}
RUNNER_FILES = (
    "githubenv",
    "githubpath",
    "githuboutput",
    "githubstate",
    "githubstepsummary",
    "filecommands",
)
LINT_SOFTENERS = re.compile(
    r"^--?(?:exit-zero|exit-non-zero-on-fix|fix|unsafe-fixes|no-fail\w*|warn(?:-only)?|soft\w*|statistics|add-noqa)$"
)
ALLOWED_STEP_KEYS = frozenset(
    {
        "name",
        "uses",
        "with",
        "env",
        "run",
        "if",
        "shell",
        "working-directory",
        "id",
        "timeout-minutes",
    }
)
ALLOWED_JOB_KEYS = frozenset(
    {
        "name",
        "timeout-minutes",
        "runs-on",
        "if",
        "steps",
        "strategy",
        "permissions",
        "needs",
    }
)
CHECKOUT = "actions/checkout@"
CHECKOUT_WITH = frozenset({"persist-credentials", "fetch-depth"})
ALLOWED_ACTIONS = frozenset(
    {
        "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
        "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
        "gitleaks/gitleaks-action@e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e",
        "zizmorcore/zizmor-action@cc914d7f3750a2d13d75c7f184a1060aa0e9d482",
    }
)


# --- rules the pins cannot replace (brief 3b) --------------------------------
# A legitimate floor change regenerates the pins in the same pull request, so
# these tables are the only reviewer of that change. --update-pins never writes
# them; changing one is a change to this file, which base pins catch.

# Every job in the floor workflow, the check names it must produce, and the
# pinned actions it must use (matched against each step's uses value, never
# against run text, so a comment or a string cannot stand in). A job renamed
# away, a decoy that takes a protected check name, or a protected key reused
# for a trivial step all fail; REQUIRED_COMMANDS below holds the run side.
PROTECTED_JOBS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "secrets": (("secrets (gitleaks)",), ("gitleaks/gitleaks-action@",)),
    "leak-denylist": (("secrets (names and personal paths)",), ()),
    "kat-lint": (("tests (known-answer tests call the gate)",), ()),
    "kat-swap": (("tests (KAT answers follow the gate, advisory)",), ()),
    "authorship": (("authorship (no AI trailers)",), ()),
    "tests": (("tests (3.11)", "tests (3.12)"), ()),
    "lint": (("lint (ruff)",), ()),
    "craft-voice": (("craft (voice)",), ()),
    "craft-changelog": (("craft (changelog)",), ()),
    "craft-comments": (("craft (comments)",), ()),
    "craft-empty-diff": (("craft (empty-diff)",), ()),
    "floor-guard": (("floor (guard from base)",), ()),
    "workflow-lint": (
        ("workflow (zizmor + actionlint)",),
        ("zizmorcore/zizmor-action@",),
    ),
}

# Every simple command each job may run, written exactly as the run text holds
# it: each word with its quotes and backslashes kept, then each redirect. A
# word the shell would not expand ('$X', \$X) therefore never matches a shape
# that expects the variable, and a command outside its job's set fails, so
# each allowed command has one exact argument shape: git gets no upload-pack,
# output, external diff, textconv, no-index, refspec or URL, tar runs only in
# workflow-lint with its pinned arguments, and no cp, mkdir or redirect can
# create a file pytest would load. The only temp writes are the listed git
# show and git log lines, the actionlint download and its tar.
_PIP = "python -I -m pip install --require-hashes --no-deps -r"
_CRAFT_RANGE = (
    'python -I .floor/craft/empty_range.py --base "$CRAFT_BASE" '
    '--head "$CRAFT_HEAD" --event "$EVENT_NAME"'
)
_REV = 'git rev-parse --verify "${}^{{commit}}"'
_LEAK_CI = 'python -I "$RUNNER_TEMP/leak_scan.py" --ci --base "$SCAN_BASE" --head HEAD'
_LEAK_TEXT = (
    'python -I "$RUNNER_TEMP/leak_scan.py" --text "pull request title and body"'
)
_HISTORY = 'git log --all --format=%B > "$RUNNER_TEMP/history.txt"'
_TRAILERS = 'python -I scripts/no_ai_trailers.py "$RUNNER_TEMP/history.txt"'
_RUN_CHECK = 'python -I scripts/run_record_check.py "$FLOOR_RUN_RECORD"'
_VOICE = (
    'python -I .floor/craft/voice_lint.py --commits --base "$CRAFT_BASE" '
    "--head HEAD --prose --fail-on-warn"
)
_CHANGELOG = 'python -I .floor/craft/changelog_gate.py --base "$CRAFT_BASE" --head HEAD'
_COMMENTS = 'python -I .floor/craft/comment_craft.py --base "$CRAFT_BASE" --head HEAD'
_EMPTY_DIFF = 'python -I .floor/craft/empty_diff_gate.py --base "$PR_BASE" --head HEAD'
_GUARD = (
    'python -I "$RUNNER_TEMP/floor/floor_guard.py" --root . '
    '--pins "$RUNNER_TEMP/floor/floor-pins.json"'
)
_TAR = "tar -C /tmp -xzf /tmp/actionlint.tgz actionlint"
_ACTIONLINT = "/tmp/actionlint -color"
JOB_COMMANDS: dict[str, frozenset[str]] = {
    "secrets": frozenset(),
    "leak-denylist": frozenset(
        {
            "git cat-file -e origin/main:scripts/leak_denylist_scan.py",
            "git show origin/main:scripts/leak_denylist_scan.py"
            ' > "$RUNNER_TEMP/leak_scan.py"',
            _REV.format("SCAN_BASE"),
            _LEAK_CI,
            'printf \'%s\\n\\n%s\\n\' "$PR_TITLE" "$PR_BODY"',
            _LEAK_TEXT,
        }
    ),
    "kat-lint": frozenset({"python -I scripts/kat_lint.py"}),
    "kat-swap": frozenset({f"{_PIP} {LOCK}", "python -I scripts/kat_swap.py"}),
    "authorship": frozenset({_HISTORY, _TRAILERS}),
    "tests": frozenset({f"{_PIP} {LOCK}", "pytest -q", _RUN_CHECK}),
    "lint": frozenset({f"{_PIP} {LOCK}", "ruff check .", "ruff format --check ."}),
    "craft-voice": frozenset({_REV.format("CRAFT_BASE"), _CRAFT_RANGE, _VOICE}),
    "craft-changelog": frozenset({_REV.format("CRAFT_BASE"), _CRAFT_RANGE, _CHANGELOG}),
    "craft-comments": frozenset({_REV.format("CRAFT_BASE"), _CRAFT_RANGE, _COMMENTS}),
    "craft-empty-diff": frozenset({_REV.format("PR_BASE"), _EMPTY_DIFF}),
    "floor-guard": frozenset(
        {
            _REV.format("GUARD_BASE"),
            'mkdir -p "$RUNNER_TEMP/floor"',
            *(
                f'git cat-file -e "$GUARD_BASE:{src}"'
                for src in ("scripts/floor_guard.py", ".github/floor-pins.json", LOCK)
            ),
            *(
                f'git show "$GUARD_BASE:{src}" > "$RUNNER_TEMP/floor/{dest}"'
                for src, dest in (
                    ("scripts/floor_guard.py", "floor_guard.py"),
                    (".github/floor-pins.json", "floor-pins.json"),
                    (LOCK, LOCK),
                )
            ),
            'echo "guard from base $GUARD_BASE"',
            f'{_PIP} "$RUNNER_TEMP/floor/{LOCK}"',
            _GUARD,
        }
    ),
    "workflow-lint": frozenset(
        {
            'curl -sSL "https://github.com/rhysd/actionlint/releases/download/'
            "v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz"
            '" -o /tmp/actionlint.tgz',
            'echo "${ACTIONLINT_SHA256}  /tmp/actionlint.tgz"',
            "sha256sum -c -",
            _TAR,
            _ACTIONLINT,
        }
    ),
}
# Each job's required commands: each line here must run as a parsed command,
# written exactly so, so an echo, a printf, a comment or an unexpanded copy of
# the text never counts.
REQUIRED_COMMANDS: dict[str, tuple[str, ...]] = {
    "leak-denylist": (_LEAK_CI, _LEAK_TEXT),
    "kat-lint": ("python -I scripts/kat_lint.py",),
    "kat-swap": ("python -I scripts/kat_swap.py",),
    "authorship": (_HISTORY, _TRAILERS),
    "tests": ("pytest -q", _RUN_CHECK),
    "lint": ("ruff check .", "ruff format --check ."),
    "craft-voice": (_VOICE,),
    "craft-changelog": (_CHANGELOG,),
    "craft-comments": (_COMMENTS,),
    "craft-empty-diff": (_EMPTY_DIFF,),
    "floor-guard": (_GUARD,),
    "workflow-lint": ("sha256sum -c -", _TAR, _ACTIONLINT),
}
# Commands that do nothing with their arguments. Naming a guarded tool to one of
# them is how a step can look as if it runs that tool.
NO_OPS = frozenset({"echo", "printf", "true", ":", "test", "["})
TOOL_NAMES = frozenset(
    {
        "pytest",
        "ruff",
        "python",
        "python3",
        "git",
        "gitleaks",
        "actionlint",
        "zizmor",
        "sha256sum",
        "curl",
        "tar",
        "kat_lint",
        "no_ai_trailers",
        "voice_lint",
        "changelog_gate",
        "comment_craft",
        "empty_diff_gate",
        "run_record_check",
        "empty_range",
        "floor_guard",
        "leak_scan",
        "leak_denylist_scan",
    }
)
FLOOR_SHELL = "bash --noprofile --norc -eo pipefail {0}"
# The only conditions a job may carry; any other job condition, and any needs,
# is a violation. Step conditions are allowlisted the same way.
JOB_CONDITIONS = {
    "leak-denylist": "github.event_name == 'pull_request' || github.event_name == 'push'",
    "craft-empty-diff": "github.event_name == 'pull_request'",
}
STEP_CONDITIONS = frozenset({"github.event_name == 'pull_request'"})
RUNNER = "ubuntu-latest"
MAX_TIMEOUT = 30
# The floor workflow's triggers, exactly. A pull request trigger that ignores
# paths, or a missing synchronize, would let a change skip the floor.
FLOOR_TRIGGERS = {
    "push": {"branches": ["main"]},
    "pull_request": {"types": ["opened", "synchronize", "reopened", "edited"]},
    "workflow_dispatch": None,
    "schedule": [{"cron": "17 9 * * 1"}],
}
# Triggers that run with secrets or write access on code the pull request
# controls. No workflow file may use them.
PRIVILEGED_TRIGGERS = frozenset(
    {
        "pull_request_target",
        "workflow_run",
        "issue_comment",
        "pull_request_review",
        "pull_request_review_comment",
        "discussion_comment",
    }
)
# A workflow that holds any write permission may run only on these triggers.
WRITE_SAFE_TRIGGERS = frozenset(
    {"push", "workflow_dispatch", "schedule", "branch_protection_rule"}
)
# Environment a guardrail step may set, with its exact value.
STEP_ENV = {
    "GITHUB_TOKEN": "${{ secrets.GITHUB_TOKEN }}",
    "LEAK_DENYLIST": "${{ secrets.LEAK_DENYLIST }}",
    "EVENT_NAME": "${{ github.event_name }}",
    "SCAN_BASE": (
        "${{ github.event_name == 'push' && github.event.before || 'origin/main' }}"
    ),
    "CRAFT_BASE": (
        "${{ github.event.pull_request.base.sha || github.event.before || github.sha }}"
    ),
    "CRAFT_HEAD": "${{ github.sha }}",
    "GUARD_BASE": (
        "${{ github.event.pull_request.base.sha || github.event.before || github.sha }}"
    ),
    "PR_BASE": "${{ github.event.pull_request.base.sha }}",
    "PR_TITLE": "${{ github.event.pull_request.title }}",
    "PR_BODY": "${{ github.event.pull_request.body }}",
    "AEGIS_ATOMS_ROOT": "${{ github.workspace }}/aegis-atoms",
    "ISOLATION_LAYER_ROOT": "${{ github.workspace }}/isolation-layer",
    "FLOOR_RUN_RECORD": "${{ runner.temp }}/pytest-run.json",
    "ACTIONLINT_VERSION": "1.7.12",
    "ACTIONLINT_SHA256": "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",
}
# What python may run in a guardrail step: these scripts, or -m pytest and -m
# pip with the lock. A variable that names a script may only hold these paths.
PY_SCRIPTS = frozenset(
    {
        "scripts/kat_lint.py",
        "scripts/kat_swap.py",
        "scripts/no_ai_trailers.py",
        "scripts/run_record_check.py",
        ".floor/craft/empty_range.py",
        ".floor/craft/voice_lint.py",
        ".floor/craft/changelog_gate.py",
        ".floor/craft/comment_craft.py",
        ".floor/craft/empty_diff_gate.py",
        "$RUNNER_TEMP/leak_scan.py",
        "$RUNNER_TEMP/floor/floor_guard.py",
    }
)
# The exact arguments each allowlisted script is run with (quotes removed).
# A guard that gains, loses or changes an argument is a different guard.
SCRIPT_ARGS: dict[str, frozenset[tuple[str, ...]]] = {
    "scripts/kat_lint.py": frozenset({()}),
    "scripts/kat_swap.py": frozenset({()}),
    "scripts/no_ai_trailers.py": frozenset({("$RUNNER_TEMP/history.txt",)}),
    "scripts/run_record_check.py": frozenset({("$FLOOR_RUN_RECORD",)}),
    ".floor/craft/empty_range.py": frozenset(
        {("--base", "$CRAFT_BASE", "--head", "$CRAFT_HEAD", "--event", "$EVENT_NAME")}
    ),
    ".floor/craft/voice_lint.py": frozenset(
        {
            (
                "--commits",
                "--base",
                "$CRAFT_BASE",
                "--head",
                "HEAD",
                "--prose",
                "--fail-on-warn",
            )
        }
    ),
    ".floor/craft/changelog_gate.py": frozenset(
        {("--base", "$CRAFT_BASE", "--head", "HEAD")}
    ),
    ".floor/craft/comment_craft.py": frozenset(
        {("--base", "$CRAFT_BASE", "--head", "HEAD")}
    ),
    ".floor/craft/empty_diff_gate.py": frozenset(
        {("--base", "$PR_BASE", "--head", "HEAD")}
    ),
    "$RUNNER_TEMP/leak_scan.py": frozenset(
        {
            ("--ci", "--base", "$SCAN_BASE", "--head", "HEAD"),
            ("--text", "pull request title and body"),
        }
    ),
    "$RUNNER_TEMP/floor/floor_guard.py": frozenset(
        {("--root", ".", "--pins", "$RUNNER_TEMP/floor/floor-pins.json")}
    ),
}
RUFF_ARGS = frozenset({("check", "."), ("format", "--check", ".")})
# The floor workflow's top-level keys and concurrency, exactly.
WORKFLOW_KEYS = frozenset(
    {"name", "on", "concurrency", "permissions", "defaults", "jobs"}
)
FLOOR_CONCURRENCY = {
    "group": "floor-${{ github.workflow }}-${{ github.ref }}",
    "cancel-in-progress": True,
}
JOB_TIMEOUT = 10
# pytest options a guardrail run may not add: they select, deselect, skip,
# collect only, change config or root, disable plugins or relax xfail.
PYTEST_OPTIONS = frozenset({"-q"})
# pytest.ini keys and their required values; no other pytest config may exist.
PYTEST_INI_KEYS = frozenset({"norecursedirs", "xfail_strict", "filterwarnings"})
# Commands whose failure a pipe, && or || could hide.
GUARDED = frozenset(
    {"python", "python3", "pytest", "ruff", "git", "sha256sum", "curl", "tar"}
)
TEMP_PREFIXES = ("$RUNNER_TEMP", "${RUNNER_TEMP}", "/tmp/")


# --- pins -------------------------------------------------------------------


class WorkflowFormatError(ValueError):
    pass


def _strict_loader():
    import yaml

    class Strict(yaml.SafeLoader):
        """Safe loading that refuses a repeated key, like the pin file does."""

        def construct_mapping(self, node, deep=False):
            self.flatten_mapping(node)
            seen = set()
            for key_node, _value in node.value:
                key = self.construct_object(key_node, deep=deep)
                if key in seen:
                    raise WorkflowFormatError(f"duplicate key {key!r}")
                seen.add(key)
            return super().construct_mapping(node, deep=deep)

    Strict.add_constructor(
        "tag:yaml.org,2002:map",
        lambda loader, node: loader.construct_mapping(node, deep=True),
    )
    return Strict


def _check_types(obj, depth: int = 0) -> None:
    """Only what JSON can hold: a date, bytes, set or any other tag fails closed."""
    if depth > 100:
        raise WorkflowFormatError("nested too deeply")
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, (str, bool, int)) or isinstance(key, float):
                raise WorkflowFormatError(f"key of type {type(key).__name__}")
            _check_types(value, depth + 1)
    elif isinstance(obj, list):
        for value in obj:
            _check_types(value, depth + 1)
    elif not (obj is None or isinstance(obj, (str, bool, int, float))):
        raise WorkflowFormatError(f"value of type {type(obj).__name__}")


def _load_yaml(text: str):
    """Load a workflow strictly; every failure is a WorkflowFormatError."""
    import yaml

    try:
        doc = yaml.load(text, Loader=_strict_loader())  # noqa: S506 (SafeLoader subclass)
    except WorkflowFormatError:
        raise
    except (yaml.YAMLError, ValueError, TypeError, RecursionError) as exc:
        raise WorkflowFormatError(type(exc).__name__) from None
    _check_types(doc)
    return doc


def _normalise(obj):
    if isinstance(obj, dict):
        return {("on" if k is True else str(k)): _normalise(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalise(v) for v in obj]
    return obj


def canonical(obj) -> str:
    return json.dumps(
        _normalise(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def sha(text: str | bytes) -> str:
    data = text.encode("utf-8") if isinstance(text, str) else text
    return hashlib.sha256(data).hexdigest()


# Directories the globs skip. Each one is also in pytest's norecursedirs
# (tests/test_floor_config.py proves it), so nothing pytest loads is skipped.
# .tmp/ holds the pinned sibling checkouts that scripts/run_full_suite.py makes.
GUARD_SKIP_DIRS = (".git/", ".venv/", ".tmp/")


def guard_files(root: Path) -> list[str]:
    found = {f for f in GUARD_FILES if (root / f).is_file()}
    for pattern in GUARD_GLOBS:
        for path in root.glob(pattern):
            rel = path.relative_to(root).as_posix()
            if path.is_file() and not rel.startswith(GUARD_SKIP_DIRS):
                found.add(rel)
    return sorted(found)


def compute_pins(root: Path) -> dict:
    wf = _load_yaml((root / WORKFLOW).read_text(encoding="utf-8"))
    if not isinstance(wf, dict) or not isinstance(wf.get("jobs") or {}, dict):
        raise WorkflowFormatError("not a mapping")
    top = {k: v for k, v in wf.items() if k != "jobs"}
    return {
        "workflow": sha(canonical(top)),
        "jobs": {
            name: sha(canonical(job)) for name, job in (wf.get("jobs") or {}).items()
        },
        # CRLF is folded to LF so a checkout's line-ending setting cannot move a pin.
        "files": {
            rel: sha((root / rel).read_bytes().replace(b"\r\n", b"\n"))
            for rel in guard_files(root)
        },
    }


# On disk every digest sits under a field named "sha256", never under a job or
# file name: a job named "secrets" next to a 64-hex value reads as a credential
# to secret scanners. In memory the groups stay name -> digest maps.
PIN_GROUPS = (("files", "path"), ("jobs", "job"))
_HEX64 = re.compile(r"[0-9a-f]{64}")


class PinFormatError(ValueError):
    pass


def pins_to_file(pins: dict) -> dict:
    out: dict = {"workflow": {"sha256": pins["workflow"]}}
    for group, field in PIN_GROUPS:
        out[group] = [
            {field: name, "sha256": digest}
            for name, digest in sorted(pins[group].items())
        ]
    return out


def _digest(value, where: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise PinFormatError(f"{where}: sha256 must be 64 lowercase hex")
    return value


def pins_from_file(data) -> dict:
    """Parse the on-disk form exactly; any other shape is an error, never a default."""
    if not isinstance(data, dict) or set(data) != {"workflow", "files", "jobs"}:
        raise PinFormatError("top level must hold exactly workflow, files and jobs")
    workflow = data["workflow"]
    if not isinstance(workflow, dict) or set(workflow) != {"sha256"}:
        raise PinFormatError("workflow must hold exactly sha256")
    pins: dict = {"workflow": _digest(workflow["sha256"], "workflow")}
    for group, field in PIN_GROUPS:
        entries = data[group]
        if not isinstance(entries, list):
            raise PinFormatError(f"{group} must be a list")
        seen: dict[str, str] = {}
        for index, entry in enumerate(entries):
            where = f"{group}[{index}]"
            if not isinstance(entry, dict) or set(entry) != {field, "sha256"}:
                raise PinFormatError(f"{where} must hold exactly {field} and sha256")
            name = entry[field]
            if not isinstance(name, str) or not name:
                raise PinFormatError(f"{where}: {field} must be a non-empty string")
            if name in seen:
                raise PinFormatError(f"{where}: duplicate {field}")
            seen[name] = _digest(entry["sha256"], where)
        pins[group] = seen
    return pins


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    seen: dict[str, object] = {}
    for key, value in pairs:
        if key in seen:
            raise PinFormatError(f"duplicate key {key!r}")
        seen[key] = value
    return seen


def pins_text(pins: dict) -> str:
    """The one byte form of the pin file: what --update-pins writes."""
    return json.dumps(pins_to_file(pins), indent=2, sort_keys=True) + "\n"


def load_pins(path: Path) -> dict:
    """Parse a pin file strictly; every failure is a PinFormatError."""
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8").replace("\r\n", "\n")
        pins = pins_from_file(json.loads(text, object_pairs_hook=_no_duplicate_keys))
    except PinFormatError:
        raise
    except (ValueError, RecursionError, UnicodeDecodeError) as exc:
        raise PinFormatError(f"does not parse ({type(exc).__name__})") from None
    if text != pins_text(pins):
        raise PinFormatError("not in the canonical form --update-pins writes")
    return pins


def pin_violations(root: Path, pins: dict) -> list[str]:
    now = compute_pins(root)
    found: list[str] = []
    if now["workflow"] != pins["workflow"]:
        found.append("pin: workflow settings changed")
    for group in ("jobs", "files"):
        want, have = pins[group], now[group]
        for name in sorted(set(want) | set(have)):
            if name not in have:
                found.append(f"pin: {group[:-1]} {name} removed")
            elif name not in want:
                found.append(f"pin: {group[:-1]} {name} added")
            elif want[name] != have[name]:
                found.append(f"pin: {group[:-1]} {name} changed")
    return found


# --- shell rules -------------------------------------------------------------


def _compact(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _word_is_literal(word: str) -> bool:
    return not re.search(r"[$`\\\"'*?\[\]{}~]", word)


def _as_written(node, src: str) -> str:
    """A word as the run text holds it: quotes and backslashes kept."""
    pos = getattr(node, "pos", None)
    return src[pos[0] : pos[1]] if pos else str(getattr(node, "word", node))


def _render(node, src: str) -> str:
    """One simple command as written: assignments, words, then redirects."""
    out = []
    for part in node.parts:
        if part.kind in {"assignment", "word"}:
            out.append(_as_written(part, src))
        elif part.kind == "redirect":
            target = getattr(part, "output", None)
            target = (
                _as_written(target, src) if hasattr(target, "kind") else str(target)
            )
            source = "" if getattr(part, "input", None) is None else str(part.input)
            out.append(f"{source}{part.type} {target}")
        else:
            out.append(f"<{part.kind}>")
    return " ".join(out)


def _unexpanded_dollar(word: str) -> bool:
    """A $ the shell keeps literal: inside single quotes, after a backslash, or
    opening $'...' quoting. Such a word reads like a variable and is not one."""
    quote = None
    i = 0
    while i < len(word):
        c = word[i]
        if quote == "'":
            if c == "'":
                quote = None
            elif c == "$":
                return True
        elif c == "\\":
            if word[i + 1 : i + 2] == "$":
                return True
            i += 2
            continue
        elif c == "'" and quote is None:
            quote = "'"
        elif c == '"':
            quote = None if quote == '"' else '"'
        elif c == "$" and quote is None and word[i + 1 : i + 2] == "'":
            return True
        i += 1
    return False


class _Collector:
    def __init__(self, src: str = "") -> None:
        self.src = src
        self.written: list[str] = []
        self.rendered: list[tuple[list[str], str]] = []
        self.shaping: set[str] = set()
        self.commands: list[list] = []
        self.redirects: list[str] = []
        self.assignments: list[str] = []
        self.masked: list[str] = []
        self.negated = False
        self.chains: list[tuple[str, list[str]]] = []
        self.pipelines: list[list[list[str]]] = []
        self.writes: list[tuple[list[str], str]] = []
        self.hiding: set[str] = set()
        self._condition = 0

    def _head(self, node) -> list[str]:
        if getattr(node, "kind", None) == "command":
            return [p.word for p in node.parts if p.kind == "word"]
        if getattr(node, "kind", None) == "pipeline":
            return self._head(node.parts[-1])
        return []

    def walk(self, node) -> None:
        kind = getattr(node, "kind", None)
        if kind in {"commandsubstitution", "processsubstitution"}:
            self.hiding.add("uses command substitution")
        if kind == "operator" and getattr(node, "op", None) == "&":
            self.hiding.add("runs a command in the background")
        if kind == "operator" and getattr(node, "op", None) == "&&":
            self.hiding.add("uses &&")
        if kind == "operator" and getattr(node, "op", None) == "||":
            self.hiding.add("uses ||")
        if kind in {"if", "while", "until"}:
            self.hiding.add("uses a condition")
        if kind == "function":
            self.shaping.add("defines a function, which can shadow a command")
        if kind in {"for", "while", "until"}:
            self.shaping.add("uses a loop, which can skip a command")
        if kind == "compound" and any(
            getattr(p, "kind", None) == "reservedword" and p.word in {"(", "{"}
            for p in getattr(node, "list", [])
        ):
            self.shaping.add(
                "uses a subshell or command group, which can wrap a command"
            )
        if kind == "list":
            parts = node.parts
            for i, part in enumerate(parts):
                if (
                    getattr(part, "kind", None) == "operator"
                    and part.op == "||"
                    and i + 1 < len(parts)
                    and not self._condition
                ):
                    words = self._head(parts[i + 1])
                    if words and not (
                        words[0] == "exit" and words[1:2] in (["1"], ["2"], ["3"])
                    ):
                        self.masked.append(" ".join(words[:2]))
                if (
                    getattr(part, "kind", None) == "operator"
                    and part.op in {"&&", "||"}
                    and i + 1 < len(parts)
                    and not self._condition
                ):
                    self.chains.append((part.op, self._head(parts[i + 1])))
        if kind == "pipeline" and not self._condition:
            self.pipelines.append(
                [
                    [w.word for w in p.parts if w.kind == "word"]
                    for p in node.parts
                    if getattr(p, "kind", None) == "command"
                ]
            )
            if any(
                getattr(p, "kind", None) == "reservedword" and p.word == "!"
                for p in node.parts
            ):
                self.negated = True
        if kind in {"if", "while", "until"}:
            in_condition = False
            for part in node.parts:
                if getattr(part, "kind", None) == "reservedword" and isinstance(
                    part.word, str
                ):
                    in_condition = part.word in {"if", "elif", "while", "until"}
                    continue
                self._condition += in_condition
                self.walk(part)
                self._condition -= in_condition
            return
        if kind == "command":
            parts = getattr(node, "parts", [])
            words = [p for p in parts if p.kind == "word"]
            for p in parts:
                if p.kind in {"assignment", "word"}:
                    self.written.append(_as_written(p, self.src))
                if p.kind == "assignment":
                    self.assignments.append(p.word)
                if p.kind == "redirect":
                    target = getattr(p, "output", None)
                    if target is not None and getattr(target, "kind", None) == "word":
                        self.written.append(_as_written(target, self.src))
                        self.redirects.append(target.word)
                        self.writes.append(([w.word for w in words], target.word))
            self.commands.append([w.word for w in words])
            self.rendered.append(([w.word for w in words], _render(node, self.src)))
        for attr in ("parts", "list"):
            for child in getattr(node, attr, None) or []:
                if hasattr(child, "kind"):
                    self.walk(child)
        for attr in ("command", "output"):
            child = getattr(node, attr, None)
            if child is not None and hasattr(child, "kind") and attr == "command":
                self.walk(child)


def parsed_commands(run: str) -> list[str]:
    """Every simple command in run text, as written; empty if it does not parse.
    Comments are not commands, so text in a comment never appears here."""
    import bashlex

    run = re.sub(r"\$\{\{.*?\}\}", "X", run, flags=re.S)
    try:
        trees = bashlex.parse(run)
    except Exception:  # judged as a violation by run_violations
        return []
    col = _Collector(run)
    for tree in trees:
        col.walk(tree)
    return [text for _words, text in col.rendered]


def _shape_violations(col: _Collector, where: str, job: str) -> list[str]:
    # An assignment-only command has no words but is still a command: it is
    # judged against the table like any other, so none is allowed.
    found: list[str] = []
    allowed = JOB_COMMANDS.get(job, frozenset())
    for words, text in col.rendered:
        if text in allowed:
            continue
        found.append(
            f"{where}: `{text}` is not an allowlisted command shape for job {job}"
        )
        head = words[0] if words else ""
        if head == "git":
            found.append(
                f"{where}: git arguments are not an allowlisted shape for job {job}"
            )
        if head == "tar":
            if job != "workflow-lint":
                found.append(f"{where}: tar is allowed only in the workflow-lint job")
            else:
                found.append(f"{where}: tar arguments are not the pinned ones")
    return found


def _names_a_tool(words: list[str]) -> bool:
    for word in words[1:]:
        for token in word.split():
            base = token.rsplit("/", 1)[-1]
            if base.removesuffix(".py") in TOOL_NAMES:
                return True
    return False


def run_violations(run: str, where: str, job: str | None = None) -> list[str]:
    import bashlex

    found: list[str] = []
    if "${{" in run:
        found.append(f"{where}: expression interpolated into run text")
        run = re.sub(r"\$\{\{.*?\}\}", "X", run, flags=re.S)
    if any(token in _compact(run) for token in RUNNER_FILES):
        found.append(f"{where}: names a runner environment, path, output or state file")
    try:
        trees = bashlex.parse(run)
    except Exception as exc:  # unparseable is a violation, not a skip
        return found + [f"{where}: shell text does not parse ({type(exc).__name__})"]
    col = _Collector(run)
    for tree in trees:
        col.walk(tree)
    if not col.commands and run.strip():
        found.append(f"{where}: no command found")
    if any(_unexpanded_dollar(word) for word in col.written):
        found.append(
            f"{where}: a $ the shell does not expand (single quotes or a backslash)"
        )
    for masked in col.masked:
        found.append(f"{where}: failure masked by || {masked}")
    for op, words in col.chains:
        if op == "&&" and words and words[0] in GUARDED:
            found.append(f"{where}: {words[0]} runs only after &&")
    for construct in sorted(col.hiding):
        found.append(f"{where}: {construct}, which can hide a failing command")
    for construct in sorted(col.shaping):
        found.append(f"{where}: {construct}")
    if job is not None:
        found += _shape_violations(col, where, job)
    for words, target in col.writes:
        clean = target.strip("\"'")
        if clean.startswith(TEMP_PREFIXES) and not (
            words[:1] == ["git"] and words[1:2] and words[1] in GIT_READ_ONLY
        ):
            found.append(
                f"{where}: only a read-only git command may write into the temp dir"
            )
    if col.negated:
        found.append(f"{where}: exit status negated with !")
    for name in col.assignments:
        var = name.split("=", 1)[0]
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", var) or SENSITIVE_VARS.match(
            var
        ):
            found.append(f"{where}: assignment to {var}")
    for target in col.redirects:
        if not (
            target.startswith(("/dev/null", "/dev/stderr", "/dev/stdout"))
            or _safe_path(target)
        ):
            found.append(
                f"{where}: redirect target {target!r} is not a plain workspace or temp path"
            )
    for words in col.commands:
        if not words:
            continue
        head = words[0]
        if head in NO_OPS and _names_a_tool(words):
            found.append(f"{where}: {head} names a guarded tool as an argument")
        if not _word_is_literal(head) and head not in ALLOWED_COMMANDS:
            found.append(f"{where}: constructed command name")
            continue
        if head in INDIRECT:
            if head == "set" and _set_ok(words[1:]):
                continue
            found.append(f"{where}: {head} is not allowed in a guardrail step")
            continue
        if head not in ALLOWED_COMMANDS:
            found.append(f"{where}: command {head} is not allowlisted")
            continue
        if head in {"python", "python3"}:
            found += _python_violations(words, where)
            plain = _without_isolation(words)
            if plain[1:3] == ["-m", "pytest"]:
                found += _pytest_violations(plain[3:], where)
        if head == "pytest":
            found += _pytest_violations(words[1:], where)
        if head == "ruff" and any(LINT_SOFTENERS.match(w) for w in words[1:]):
            found.append(f"{where}: lint made non-failing")
        if head == "ruff" and tuple(words[1:]) not in RUFF_ARGS:
            found.append(f"{where}: ruff arguments are not the allowlisted ones")
        if head == "exit" and (len(words) < 2 or words[1] not in {"1", "2", "3"}):
            found.append(f"{where}: exit with a success code")
        if head == "git" and (len(words) < 2 or words[1] not in GIT_READ_ONLY):
            found.append(
                f"{where}: git {words[1] if len(words) > 1 else ''} can change the tree"
            )
        if head == "cp" and not all(
            _safe_path(w) for w in words[1:] if not w.startswith("-")
        ):
            found.append(f"{where}: cp to a non-workspace path")
        if head == "curl" and not all(
            re.match(
                r"^(-[A-Za-z]+|https://github\.com/rhysd/actionlint/|\"?\$\{?RUNNER_TEMP|/tmp/actionlint)",
                w,
            )
            for w in words[1:]
        ):
            found.append(f"{where}: curl outside the pinned download")
    return found


def _safe_path(word: str) -> bool:
    word = word.strip("\"'")
    if ".." in word.split("/"):
        return False
    in_temp = bool(re.match(r"^(?:\$\{?RUNNER_TEMP\}?|/tmp)/", word))
    if not in_temp and (
        PROTECTED_NAMES.search(word) or word.startswith(PROTECTED_DIRS)
    ):
        return False
    if re.fullmatch(r"\$\{?RUNNER_TEMP\}?(?:/[\w.-]+)+", word):
        return True
    if re.fullmatch(r"/tmp/[\w.-]+", word):
        return True
    return bool(re.fullmatch(r"[\w.-]+(?:/[\w.-]+)*", word)) and not word.startswith(
        ".git"
    )


def _set_ok(args: list[str]) -> bool:
    """set may only switch strictness on, never off."""
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in {"-o", "-eo", "-euo", "-eux", "-euxo"} or (
            arg.startswith("-") and arg.endswith("o")
        ):
            if i + 1 >= len(args) or args[i + 1] not in {
                "pipefail",
                "errexit",
                "nounset",
            }:
                return False
            i += 2
            continue
        if not re.fullmatch(r"-[euxo]+", arg):
            return False
        i += 1
    return True


def _without_isolation(words: list[str]) -> list[str]:
    return [words[0], *words[2:]] if words[1:2] == ["-I"] else list(words)


def _python_violations(words: list[str], where: str) -> list[str]:
    """Python runs isolated (-I, so neither the script's folder nor the working
    directory is importable, and no PYTHON* variable or user site applies), and
    only the listed scripts, -m pytest, or -m pip with the lock."""
    found = []
    if words[1:2] != ["-I"]:
        found.append(f"{where}: python does not run isolated (-I)")
    installs = " ".join(words)
    words = _without_isolation(words)
    if any(
        w in {"-c", "-"}
        or (
            w.startswith("-")
            and not w.startswith("--")
            and "c" in w[1:]
            and w not in {"-m"}
        )
        for w in words[1:3]
    ):
        found.append(f"{where}: python runs code from the command line")
    if len(words) >= 3 and words[1] == "-m" and words[2] == "pip":
        if installs not in LOCKED_INSTALLS:
            found.append(f"{where}: install outside the hash-locked lock file")
    for w in words:
        if re.match(
            r"^--?(?:i|index-url|extra-index-url|find-links|trusted-host)\b", w
        ):
            found.append(f"{where}: package index override")
    if len(words) < 2:
        found.append(f"{where}: python runs no script")
    elif words[1] == "-m":
        if words[2:3] not in (["pytest"], ["pip"]):
            found.append(f"{where}: python -m runs a module other than pytest or pip")
    elif words[1] not in PY_SCRIPTS:
        found.append(f"{where}: python runs a script that is not allowlisted")
    elif tuple(words[2:]) not in SCRIPT_ARGS.get(words[1], frozenset()):
        found.append(
            f"{where}: python {words[1]} arguments are not the allowlisted ones"
        )
    return found


def _pytest_violations(args: list[str], where: str) -> list[str]:
    return [
        f"{where}: pytest argument {a!r} is not allowed"
        for a in args
        if a not in PYTEST_OPTIONS
    ]


# The only shell values a guardrail may set, compared as exact strings. Flags
# are never parsed: an option after the placeholder, a parse-only or
# command-string option, an end-of-options marker or an extra file all fail by
# not being one of these. Both values stop on error and on a failing pipe.
# Every run step in the floor must run under one of them (see job_violations).
SHELL_ALLOWLIST = frozenset(
    {
        "bash -eo pipefail {0}",
        "bash --noprofile --norc -eo pipefail {0}",
    }
)


def shell_ok(shell: object) -> bool:
    return shell is None or (isinstance(shell, str) and shell in SHELL_ALLOWLIST)


# --- jobs, steps, names ------------------------------------------------------


def _matrix_combos(job: dict) -> list[dict]:
    matrix = ((job.get("strategy") or {}).get("matrix")) or {}
    if not matrix:
        return [{}]
    keys = [k for k in matrix if k not in {"include", "exclude"}]
    combos = (
        [
            dict(zip(keys, values))
            for values in itertools.product(*(matrix[k] for k in keys))
        ]
        if keys
        else [{}]
    )
    for extra in matrix.get("include") or []:
        combos.append(dict(extra))
    exclude = matrix.get("exclude") or []
    return [
        c
        for c in combos
        if not any(all(c.get(k) == v for k, v in e.items()) for e in exclude)
    ]


def check_names(key: str, job: dict) -> list[str]:
    name = str(job.get("name") or key)
    names = []
    for combo in _matrix_combos(job):
        shown = re.sub(
            r"\$\{\{\s*matrix\.([\w-]+)\s*\}\}",
            lambda m: str(combo.get(m.group(1), "")),
            name,
        )
        if combo and "matrix." not in name:
            shown = f"{name} ({', '.join(str(v) for v in combo.values())})"
        names.append(" ".join(shown.split()).casefold())
    return names


def job_violations(wf: dict, extra_workflows: list[dict] = ()) -> list[str]:
    found: list[str] = []
    if wf.get("env"):
        found.append("workflow: env at workflow level")
    for key in wf:
        name = "on" if key is True else str(key)
        if name not in WORKFLOW_KEYS:
            found.append(f"workflow: key {name} is not allowed")
    if wf.get("concurrency") != FLOOR_CONCURRENCY:
        found.append("workflow: concurrency is not the floor's pinned value")
    if wf.get("permissions") != READ_ONLY:
        found.append("workflow: permissions beyond contents: read")
    defaults = wf.get("defaults")
    run_defaults = defaults.get("run") if isinstance(defaults, dict) else None
    if defaults is not None and not (
        isinstance(defaults, dict)
        and set(defaults) == {"run"}
        and isinstance(run_defaults, dict)
        and set(run_defaults) == {"shell"}
    ):
        # The same judgment as a step: only an allowlisted shell, never a
        # working directory or any other default.
        found.append("workflow: defaults are not exactly the floor's shell")
        defaults = {}
    if not shell_ok(((defaults or {}).get("run") or {}).get("shell")):
        found.append("workflow: default shell is not an allowlisted value")
    seen: dict[str, str] = {}
    for doc in [wf, *extra_workflows]:
        for key, job in (doc.get("jobs") or {}).items():
            for name in check_names(key, job):
                if name in seen and seen[name] != key:
                    found.append(f"check name {name!r} produced by more than one job")
                seen.setdefault(name, key)
    for key, job in (wf.get("jobs") or {}).items():
        where = f"job {key}"
        if set(job) - ALLOWED_JOB_KEYS:
            found.append(f"{where}: keys {sorted(set(job) - ALLOWED_JOB_KEYS)}")
        if job.get("continue-on-error"):
            found.append(f"{where}: continue-on-error")
        if job.get("if") != JOB_CONDITIONS.get(key):
            found.append(f"{where}: job condition is not allowlisted")
        if "needs" in job:
            found.append(f"{where}: needs")
        if job.get("runs-on") != RUNNER:
            found.append(f"{where}: runner is not {RUNNER}")
        timeout = job.get("timeout-minutes")
        if not (
            isinstance(timeout, int)
            and not isinstance(timeout, bool)
            and 1 <= timeout <= MAX_TIMEOUT
        ):
            found.append(f"{where}: timeout is not 1 to {MAX_TIMEOUT} minutes")
        if timeout != JOB_TIMEOUT:
            found.append(f"{where}: timeout is not the pinned {JOB_TIMEOUT} minutes")
        if not _matrix_combos(job):
            found.append(f"{where}: matrix expands to no runs")
        if not shell_ok(((job.get("defaults") or {}).get("run") or {}).get("shell")):
            found.append(f"{where}: default shell is not an allowlisted value")
        if job.get("env"):
            found.append(f"{where}: env at job level")
        if "permissions" in job and job["permissions"] != READ_ONLY:
            found.append(f"{where}: permissions beyond contents: read")
        if (job.get("strategy") or {}).get("fail-fast") not in (None, False):
            pass
        for i, step in enumerate(job.get("steps") or []):
            sw = f"{where} step {i + 1}"
            if set(step) - ALLOWED_STEP_KEYS:
                found.append(f"{sw}: keys {sorted(set(step) - ALLOWED_STEP_KEYS)}")
            if not shell_ok(step.get("shell")):
                found.append(f"{sw}: shell is not an allowlisted value")
            effective = (
                step.get("shell")
                or ((job.get("defaults") or {}).get("run") or {}).get("shell")
                or ((defaults or {}).get("run") or {}).get("shell")
            )
            if "run" in step and effective not in SHELL_ALLOWLIST:
                found.append(f"{sw}: no explicit pipefail shell")
            uses = step.get("uses")
            if "if" in step and step["if"] not in STEP_CONDITIONS:
                found.append(f"{sw}: step condition is not allowlisted")
            for var, value in (step.get("env") or {}).items():
                token_ok = uses is not None and TOKEN_ENV.get(str(var)) == value
                if str(var) == "GITHUB_TOKEN":
                    if not token_ok:
                        found.append(f"{sw}: env sets {var}")
                elif STEP_ENV.get(str(var)) != value:
                    found.append(f"{sw}: env sets {var}")
            if uses is not None:
                if uses not in ALLOWED_ACTIONS:
                    found.append(f"{sw}: action {uses} is not allowlisted")
                if str(uses).startswith(CHECKOUT):
                    found += _checkout_violations(step.get("with") or {}, sw)
            if step.get("working-directory") not in (None, "capability-gate"):
                found.append(f"{sw}: working directory {step.get('working-directory')}")
            run = step.get("run")
            if run:
                found += run_violations(str(run), sw, str(key))
    return found


def symlink_violations(root: Path) -> list[str]:
    """Any link the guard could be asked to judge.

    In a git checkout: every tracked link (index mode 120000, whatever the
    platform did with it on checkout) and every untracked, unignored path that
    is a link. A pull request can supply only tracked content, and an ignored
    path cannot come from it. Outside a checkout: every link on disk outside
    the skipped directories.
    """
    import os
    import subprocess

    found: list[str] = []
    if (root / ".git").exists():
        for args, label in (
            (["ls-files", "-s", "-z"], "tracked"),
            (["ls-files", "-o", "--exclude-standard", "-z"], "untracked"),
        ):
            listed = subprocess.run(
                ["git", *args], cwd=root, capture_output=True, check=False
            )
            if listed.returncode != 0:
                found.append("symlinks: git ls-files failed; links cannot be ruled out")
                continue
            for entry in listed.stdout.decode("utf-8", "replace").split("\0"):
                if label == "tracked":
                    meta, _, path = entry.partition("\t")
                    if meta.startswith("120000 "):
                        found.append(
                            f"tracked symlink {path}: the guard does not follow links"
                        )
                elif entry and (root / entry).is_symlink():
                    found.append(f"symlink {entry}: the guard does not follow links")
        return sorted(set(found))
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        rel_dir = here.relative_to(root).as_posix()
        prefix = "" if rel_dir == "." else rel_dir + "/"
        dirnames[:] = [
            d for d in dirnames if not (prefix + d + "/").startswith(GUARD_SKIP_DIRS)
        ]
        for name in [*dirnames, *filenames]:
            if (here / name).is_symlink():
                found.append(f"symlink {prefix}{name}: the guard does not follow links")
    return sorted(set(found))


def protected_job_violations(wf: dict) -> list[str]:
    found: list[str] = []
    jobs = wf.get("jobs") or {}
    for key in sorted(set(jobs) - set(PROTECTED_JOBS)):
        found.append(f"job {key}: not in the protected jobs table")
    for key, (names, actions) in PROTECTED_JOBS.items():
        job = jobs.get(key)
        if not isinstance(job, dict):
            found.append(f"job {key}: protected job is missing")
            continue
        if sorted(check_names(key, job)) != sorted(n.casefold() for n in names):
            found.append(f"job {key}: check names are not {list(names)}")
        uses = [
            str(s["uses"])
            for s in job.get("steps") or []
            if isinstance(s, dict) and "uses" in s
        ]
        for action in actions:
            if not any(u.startswith(action) and u in ALLOWED_ACTIONS for u in uses):
                found.append(f"job {key}: required action {action!r} is missing")
        ran = {
            command
            for s in job.get("steps") or []
            if isinstance(s, dict) and s.get("run")
            for command in parsed_commands(str(s["run"]))
        }
        for command in REQUIRED_COMMANDS.get(key, ()):
            if command not in ran:
                found.append(f"job {key}: required command {command!r} is missing")
    return found


def _test_modules(root: Path) -> list[Path]:
    """Files pytest collects as test modules by default (no python_files key)."""
    import os

    out = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        rel_dir = here.relative_to(root).as_posix()
        prefix = "" if rel_dir == "." else rel_dir + "/"
        dirnames[:] = [
            d for d in dirnames if not (prefix + d + "/").startswith(GUARD_SKIP_DIRS)
        ]
        out += [
            here / n
            for n in filenames
            if n.endswith(".py") and (n.startswith("test_") or n.endswith("_test.py"))
        ]
    return sorted(out)


def plugin_violations(root: Path) -> list[str]:
    """No test module names pytest_plugins: the list loads plugin modules, and a
    plugin's hooks can rewrite every result. Any use of the name counts: an
    assignment, an annotation, an attribute, the name as a string or a sum of
    strings, or a module __getattr__ that could return it. A name built any
    other way is refused at run time by the floor's conftest, which fails the
    run when a plugin registers once collection starts."""
    found = []
    for path in _test_modules(root):
        rel = path.relative_to(root).as_posix()
        try:
            tree = ast.parse(path.read_bytes())
        except (SyntaxError, ValueError):
            found.append(f"{rel}: does not parse as Python")
            continue
        for node in ast.walk(tree):
            if (
                (isinstance(node, ast.Name) and node.id == "pytest_plugins")
                or (isinstance(node, ast.Attribute) and node.attr == "pytest_plugins")
                or _folded_str(node) == "pytest_plugins"
            ):
                found.append(f"{rel}: declares pytest_plugins")
                break
        else:
            if any(
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == "__getattr__"
                for node in tree.body
            ):
                found.append(
                    f"{rel}: declares pytest_plugins (a module __getattr__ can supply it)"
                )
    return found


def _names_xfail(node, aliases: set[str]) -> bool:
    """An expression that reaches pytest's xfail mark: one whose attribute chain
    holds xfail, or a name this module binds to such an expression."""
    while isinstance(node, (ast.Attribute, ast.Call, ast.Subscript)):
        if isinstance(node, ast.Attribute) and node.attr == "xfail":
            return True
        node = node.func if isinstance(node, ast.Call) else node.value
    return isinstance(node, ast.Name) and (node.id == "xfail" or node.id in aliases)


def xfail_strict_violations(root: Path) -> list[str]:
    """No test module gives an xfail mark a strict other than True. pytest.ini
    sets xfail_strict, but a mark's own strict= wins over it, so strict=False on
    one mark keeps a passing test green under its xfail. A strict that is not the
    constant True, or keywords passed with **, count."""
    found = []
    for path in _test_modules(root):
        rel = path.relative_to(root).as_posix()
        try:
            tree = ast.parse(path.read_bytes())
        except (SyntaxError, ValueError):
            continue  # plugin_violations reports it
        aliases: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and _names_xfail(node.value, set()):
                aliases |= {t.id for t in node.targets if isinstance(t, ast.Name)}
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and _names_xfail(node.func, aliases)):
                continue
            for kw in node.keywords:
                if kw.arg is None or (
                    kw.arg == "strict"
                    and not (
                        isinstance(kw.value, ast.Constant) and kw.value.value is True
                    )
                ):
                    found.append(
                        f"{rel}: an xfail mark sets strict to something other than "
                        f"True (line {node.lineno})"
                    )
                    break
    return found


def _folded_str(node) -> str | None:
    """A string constant, or a + of string constants, folded to its value. Names
    built any other way are caught at run time by the floor's conftest."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _folded_str(node.left), _folded_str(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _triggers(doc: dict) -> object:
    return doc.get("on", doc.get(True))


def _trigger_names(on: object) -> set[str]:
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(x) for x in on}
    if isinstance(on, dict):
        return {str(k) for k in on}
    return set()


def _writes(permissions: object) -> bool:
    if isinstance(permissions, str):
        return permissions != "read-all"
    if isinstance(permissions, dict):
        return any(str(v) != "read" and str(v) != "none" for v in permissions.values())
    return False


def trigger_violations(wf: dict, extra_workflows: list[dict] = ()) -> list[str]:
    found: list[str] = []
    if _normalise(_triggers(wf)) != FLOOR_TRIGGERS:
        found.append("workflow: triggers are not exactly the floor's triggers")
    for doc in [wf, *extra_workflows]:
        name = str(doc.get("name") or "?")
        names = _trigger_names(_triggers(doc))
        for trig in sorted(names & PRIVILEGED_TRIGGERS):
            found.append(f"workflow {name}: privileged trigger {trig}")
        writes = _writes(doc.get("permissions")) or any(
            _writes((job or {}).get("permissions"))
            for job in (doc.get("jobs") or {}).values()
            if isinstance(job, dict)
        )
        if writes and names - WRITE_SAFE_TRIGGERS:
            found.append(
                f"workflow {name}: write permission with trigger(s) {sorted(names - WRITE_SAFE_TRIGGERS)}"
            )
    return found


_LOCK_REQ = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9_.-]*==[A-Za-z0-9_.+!-]+(?: ; [^\\#]+?)?"
    r"(?: --hash=sha256:[0-9a-f]{64})+"
)


def lock_violations(root: Path) -> list[str]:
    path = root / LOCK
    if not path.is_file():
        return [f"lock: {LOCK} is missing"]
    text = path.read_bytes().decode("utf-8").replace("\r\n", "\n")
    logical = re.sub(r"\\\n\s*", " ", text)
    found, reqs = [], 0
    for n, line in enumerate(logical.splitlines(), 1):
        line = " ".join(line.split())
        if not line or line.startswith("#"):
            continue
        if not _LOCK_REQ.fullmatch(line):
            found.append(
                f"lock: entry {n} is not a version-pinned, hash-locked requirement"
            )
        reqs += 1
    if not reqs:
        found.append("lock: no requirements")
    return found


def pytest_config_violations(root: Path) -> list[str]:
    import configparser
    import fnmatch

    found: list[str] = []
    ini = configparser.ConfigParser()
    try:
        ini.read_string((root / "pytest.ini").read_text(encoding="utf-8"))
    except (OSError, configparser.Error):
        return ["pytest config: pytest.ini is missing or does not parse"]
    if ini.sections() != ["pytest"]:
        found.append("pytest config: pytest.ini holds a section other than [pytest]")
        return found
    cfg = ini["pytest"]
    for key in sorted(set(cfg) - PYTEST_INI_KEYS):
        found.append(f"pytest config: key {key} is not allowed")
    if cfg.get("xfail_strict", "").strip().lower() != "true":
        found.append("pytest config: xfail_strict is not true")
    warn = [w.strip() for w in cfg.get("filterwarnings", "").splitlines() if w.strip()]
    if "error::SyntaxWarning" not in warn or any(w.startswith("ignore") for w in warn):
        found.append(
            "pytest config: filterwarnings does not keep SyntaxWarning an error"
        )
    for pattern in cfg.get("norecursedirs", "").split():
        if fnmatch.fnmatch("tests", pattern) or fnmatch.fnmatch("scripts", pattern):
            found.append(
                f"pytest config: norecursedirs pattern {pattern!r} hides tests"
            )
    for rel, marker in (
        ("pyproject.toml", "[tool.pytest"),
        ("tox.ini", "[pytest]"),
        ("setup.cfg", "[tool:pytest]"),
    ):
        path = root / rel
        if path.is_file() and marker in path.read_text(
            encoding="utf-8", errors="replace"
        ):
            found.append(f"pytest config: {rel} configures pytest")
    # Every spelling of the same headers: TOML allows spaces and quotes inside a
    # table header, and ini section names can carry spaces.
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        import tomllib

        try:
            tool = tomllib.loads(pyproject.read_text(encoding="utf-8")).get("tool")
        except (tomllib.TOMLDecodeError, UnicodeDecodeError):
            found.append("pytest config: pyproject.toml does not parse")
        else:
            if isinstance(tool, dict) and "pytest" in tool:
                found.append("pytest config: pyproject.toml configures pytest")
    for rel, header in (
        ("tox.ini", r"(?m)^\s*\[\s*pytest\s*\]"),
        ("setup.cfg", r"(?m)^\s*\[\s*tool\s*:\s*pytest\s*\]"),
    ):
        path = root / rel
        if path.is_file() and re.search(
            header, path.read_text(encoding="utf-8", errors="replace")
        ):
            found.append(f"pytest config: {rel} configures pytest")
    conftest = root / "conftest.py"
    if not conftest.is_file():
        found.append("pytest config: conftest.py, the floor's conftest, is missing")
    elif sha(conftest.read_bytes().replace(b"\r\n", b"\n")) != FLOOR_CONFTEST_SHA256:
        found.append("pytest config: conftest.py is not the floor's conftest")
    for rel in guard_files(root):
        name = rel.rsplit("/", 1)[-1]
        if name == "conftest.py" and rel != "conftest.py":
            found.append(f"pytest config: {rel} is not allowed")
        if name == ".pytest.ini":
            found.append(f"pytest config: {rel} configures pytest")
        # Inert today (no guardrail python reads the checkout's folders: every
        # one runs with -I), and refused so that stays true.
        if name in {"sitecustomize.py", "usercustomize.py"} or name.endswith(".pth"):
            found.append(f"{rel}: interpreter startup file")
    return sorted(set(found), key=found.index)


def _repo_files(root: Path) -> tuple[list[str], list[str]]:
    """Every path a pull request can supply, and any problem listing them.

    In a git checkout: every tracked path (from the index, so a name the
    platform cannot create on disk still counts) and every untracked,
    unignored file. Outside a checkout: every file on disk outside the skipped
    directories."""
    import os
    import subprocess

    if (root / ".git").exists():
        names: set[str] = set()
        problems: list[str] = []
        for args in (
            ["ls-files", "-z"],
            ["ls-files", "-o", "--exclude-standard", "-z"],
        ):
            listed = subprocess.run(
                ["git", *args], cwd=root, capture_output=True, check=False
            )
            if listed.returncode != 0:
                problems.append("git ls-files failed; paths cannot be judged")
                continue
            listed_names = {
                n for n in listed.stdout.decode("utf-8", "replace").split("\0") if n
            }
            if "-o" in args:
                # Local only: a pull request cannot add an untracked file.
                listed_names = {
                    n for n in listed_names if not n.startswith(GUARD_SKIP_DIRS)
                }
            names |= listed_names
        return sorted(names), problems
    out = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        prefix = "" if rel_dir == "." else rel_dir + "/"
        dirnames[:] = [
            d for d in dirnames if not (prefix + d + "/").startswith(GUARD_SKIP_DIRS)
        ]
        out += [prefix + n for n in filenames]
    return sorted(out), []


# A $, backtick or backslash in a path is shell syntax: a run line that names
# the path literally can be made to read like a variable or a substitution.
_SHELL_SYNTAX_PATH = re.compile(r"[$`\\]")


def path_violations(root: Path) -> list[str]:
    files, found = _repo_files(root)
    for rel in files:
        if _SHELL_SYNTAX_PATH.search(rel):
            found.append(f"path {rel!r}: holds $, a backtick or a backslash")
    return found


# The lint configuration, exactly: ruff.toml must parse to this. Loosening it
# (an ignore, an exclude, a narrower select or include, an extend) is a change
# to this file, which base pins catch. ruff reads its configuration from the
# nearest ruff.toml, .ruff.toml or pyproject.toml with a [tool.ruff] table, and
# skips files git or an .ignore file excludes, so each of those is judged too.
RUFF_CONFIG = {
    "lint": {
        "ignore": [
            "N999",
            "BLE001",
            "S102",
            "TRY203",
            "SIM102",
            "SIM118",
            "F402",
            "EXE001",
            "EXE002",
            "FURB167",
        ]
    }
}
_FILE_EXEMPTION = re.compile(r"(?i)^#\s*(?:ruff|flake8)\s*:\s*noqa\b")
# Every per-line exemption the floor accepts, as "path:code" -> count. A new
# one, one more of an existing code, or a blanket one with no code is a
# violation, so silencing ruff on any line is a change to this file, which
# base pins catch.
NOQA_INVENTORY: dict[str, int] = {
    "harness/d15_hermes_faithful.py:E402": 1,
    "scripts/floor_guard.py:S506": 1,
    "test_e2_mode_staleness.py:F401": 1,
    "tests/grind01_util.py:E402": 1,
    "tests/test_alias_class.py:E402": 2,
    "tests/test_arg_schemas.py:E402": 1,
    "tests/test_base_dir.py:E402": 2,
    "tests/test_cases_table.py:E402": 2,
    "tests/test_d15_hermes_faithful.py:E402": 1,
    "tests/test_floor_config.py:E402": 1,
    "tests/test_floor_fixes.py:E402": 1,
    "tests/test_gate_boundary.py:E402": 1,
    "tests/test_gate_files.py:E402": 1,
    "tests/test_glob_regex.py:E402": 1,
    "tests/test_glob_separators.py:E402": 1,
    "tests/test_halt_marker.py:E402": 1,
    "tests/test_harness_tally.py:E402": 1,
    "tests/test_hook_behavior.py:E402": 1,
    "tests/test_issue33_shapes.py:E402": 1,
    "tests/test_kill_switch.py:E402": 1,
    "tests/test_path_escapes_hook.py:E402": 2,
    "tests/test_receipt_paths.py:E402": 1,
    "tests/test_s1_distinguish.py:E402": 2,
    "tests/test_secondary_path_key.py:E402": 1,
    "tests/test_witness_tamper.py:E402": 1,
}


def _strings(obj) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for k, v in obj.items() for s in (*_strings(k), *_strings(v))]
    if isinstance(obj, list):
        return [s for v in obj for s in _strings(v)]
    return []


# A per-line exemption: the noqa marker alone (every code) or with a code
# list. ruff finds it anywhere in a comment, so it is searched, not matched at
# the start.
_LINE_EXEMPTION = re.compile(
    r"(?i)#\s*noqa\b(?:\s*:\s*([a-z]+[0-9]+(?:[,\s]+[a-z]+[0-9]+)*))?"
)


def _comments(text: str) -> list[str]:
    """Every comment python's tokenizer finds; on a tokenize error, every line
    from its first # (so an unparsable file cannot hide an exemption)."""
    import io
    import tokenize

    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, SyntaxError):
        return [line[line.index("#") :] for line in text.splitlines() if "#" in line]
    return [tok.string for tok in tokens if tok.type == tokenize.COMMENT]


def _file_exemption(text: str) -> bool:
    return any(_FILE_EXEMPTION.match(c.lstrip()) for c in _comments(text))


def _line_exemptions(text: str) -> list[str]:
    """The codes each per-line noqa names; "*" for a blanket one."""
    out: list[str] = []
    for comment in _comments(text):
        if _FILE_EXEMPTION.match(comment.lstrip()):
            continue
        for m in _LINE_EXEMPTION.finditer(comment):
            codes = m.group(1)
            # ruff separates codes by commas, spaces or both.
            out += (
                [c.upper() for c in re.split(r"[,\s]+", codes) if c] if codes else ["*"]
            )
    return out


def _notebook_code(path: Path) -> str | None:
    """The code cells of a notebook as one text; None if it does not parse."""
    try:
        nb = json.loads(path.read_text(encoding="utf-8"))
        cells = nb["cells"]
        parts = []
        for cell in cells:
            if cell.get("cell_type") != "code":
                continue
            source = cell.get("source", "")
            parts.append("".join(source) if isinstance(source, list) else str(source))
    except (
        OSError,
        UnicodeDecodeError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
    ):
        return None
    return "\n".join(parts)


def _lint_texts(root: Path, files: list[str]) -> tuple[dict[str, str], list[str]]:
    """Text ruff lints in each Python file and notebook, and parse problems."""
    texts: dict[str, str] = {}
    problems: list[str] = []
    for rel in files:
        if rel.endswith((".py", ".pyi")):
            try:
                texts[rel] = (root / rel).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
        elif rel.endswith(".ipynb"):
            code = _notebook_code(root / rel)
            if code is None:
                problems.append(f"{rel}: notebook does not parse")
            else:
                texts[rel] = code
    return texts, problems


def noqa_inventory(root: Path) -> dict[str, int]:
    """Per-line exemptions in the tree, as "path:code" -> count."""
    files, _problems = _repo_files(root)
    texts, _parse = _lint_texts(root, files)
    found: dict[str, int] = {}
    for rel, text in texts.items():
        for code in _line_exemptions(text):
            key = f"{rel}:{code}"
            found[key] = found.get(key, 0) + 1
    return dict(sorted(found.items()))


def lint_config_violations(root: Path) -> list[str]:
    import subprocess
    import tomllib

    found: list[str] = []
    try:
        cfg = tomllib.loads((root / "ruff.toml").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        found.append("lint config: ruff.toml is missing or does not parse")
        cfg = None
    if cfg is not None and cfg != RUFF_CONFIG:
        found.append("lint config: ruff.toml is not the floor's ruff config")
        if any(s == "ALL" or "*" in s for s in _strings(cfg)):
            found.append("lint config: ruff.toml skips everything (ALL or *)")
        lint = cfg.get("lint") if isinstance(cfg.get("lint"), dict) else {}
        if "select" in cfg or "select" in lint:
            found.append("lint config: ruff.toml sets select, which can narrow it")
    files, problems = _repo_files(root)
    found += [f"lint config: {p}" for p in problems]
    for rel in files:
        name = rel.rsplit("/", 1)[-1]
        if name == ".ruff.toml" or (name == "ruff.toml" and rel != "ruff.toml"):
            found.append(f"lint config: {rel} is a ruff config the floor does not pin")
        elif name == ".ignore":
            found.append(f"lint config: {rel} hides files from ruff")
        elif name == "pyproject.toml":
            try:
                tool = tomllib.loads((root / rel).read_text(encoding="utf-8")).get(
                    "tool"
                )
            except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
                found.append(f"lint config: {rel} does not parse")
            else:
                if isinstance(tool, dict) and "ruff" in tool:
                    found.append(f"lint config: {rel} configures ruff")
    texts, parse_problems = _lint_texts(root, files)
    found += parse_problems
    have: dict[str, int] = {}
    for rel, text in texts.items():
        if _file_exemption(text):
            found.append(f"{rel}: file-level lint exemption")
        for code in _line_exemptions(text):
            key = f"{rel}:{code}"
            have[key] = have.get(key, 0) + 1
    for key, count in sorted(have.items()):
        if count > NOQA_INVENTORY.get(key, 0):
            rel, _, code = key.rpartition(":")
            found.append(
                f"{rel}: per-line lint exemption ({code}) beyond the floor's inventory"
            )
    if (root / ".git").exists():
        ignored = subprocess.run(
            ["git", "ls-files", "-ci", "--exclude-standard", "-z"],
            cwd=root,
            capture_output=True,
            check=False,
        )
        if ignored.returncode != 0:
            found.append("lint config: git ls-files failed; ignored files unknown")
        elif ignored.stdout.strip(b"\0"):
            found.append(
                "lint config: a tracked file is ignored by git, so ruff skips it"
            )
    return found


def _checkout_violations(inputs: dict, where: str) -> list[str]:
    """The tree under test is checked out as pushed; siblings only at a fixed commit."""
    found = []
    if inputs.get("persist-credentials") is not False:
        found.append(f"{where}: checkout keeps credentials")
    repo = inputs.get("repository")
    if repo is None:
        extra = set(inputs) - {"persist-credentials", "fetch-depth", "path"}
        if extra or inputs.get("path") not in (None, "capability-gate"):
            found.append(f"{where}: checkout inputs change ref, repository or file set")
        return found
    name = str(repo).split("/")[-1]
    ok = (
        re.fullmatch(r"Steck43/[\w.-]+", str(repo))
        and str(repo) != REPO
        and SIBLING_REF.fullmatch(str(inputs.get("ref", "")))
        and inputs.get("path") == name
        and set(inputs) <= {"repository", "ref", "path", "persist-credentials"}
    )
    if not ok:
        found.append(
            f"{where}: sibling checkout must be a fixed commit of another repository into its own folder"
        )
    return found


def violations(root: Path, pins_path: Path | None = None) -> list[str]:
    docs = {}
    for path in [
        root / WORKFLOW,
        *sorted((root / ".github" / "workflows").glob("*.y*ml")),
    ]:
        rel = path.relative_to(root).as_posix()
        if rel in docs:
            continue
        try:
            doc = _load_yaml(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError) as exc:
            return [f"workflow {rel}: does not load ({type(exc).__name__})"]
        except WorkflowFormatError as exc:
            return [f"workflow {rel}: does not load ({exc})"]
        if path != root / WORKFLOW and not isinstance(doc, (dict, type(None))):
            return [f"workflow {rel}: does not load (not a mapping)"]
        if path == root / WORKFLOW and not isinstance(doc, dict):
            return [f"workflow {rel}: does not load (not a mapping)"]
        docs[rel] = doc or {}
    wf = docs.pop(WORKFLOW.as_posix())
    others = list(docs.values())
    found: list[str] = []
    in_tree = root / PINS
    if pins_path is not None and pins_path.resolve() != in_tree.resolve():
        if not in_tree.is_file():
            found.append("pin: in-tree .github/floor-pins.json is missing")
        else:
            try:
                load_pins(in_tree)
            except PinFormatError as exc:
                found.append(
                    f"pin: in-tree .github/floor-pins.json is malformed ({exc})"
                )
    pins_path = pins_path or in_tree
    if not pins_path.is_file():
        return found + ["pin: .github/floor-pins.json is missing"]
    try:
        pins = load_pins(pins_path)
    except PinFormatError as exc:
        return found + [f"pin: .github/floor-pins.json is malformed ({exc})"]
    return (
        found
        + pin_violations(root, pins)
        + job_violations(wf, others)
        + protected_job_violations(wf)
        + symlink_violations(root)
        + trigger_violations(wf, others)
        + lock_violations(root)
        + pytest_config_violations(root)
        + plugin_violations(root)
        + xfail_strict_violations(root)
        + path_violations(root)
        + lint_config_violations(root)
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=ROOT)
    ap.add_argument("--update-pins", action="store_true")
    ap.add_argument(
        "--pins",
        type=Path,
        default=None,
        help="pins to judge against (CI passes the base copy)",
    )
    args = ap.parse_args(argv)
    root = args.root.resolve()
    try:
        pins = compute_pins(root)
    except (WorkflowFormatError, OSError, UnicodeDecodeError) as exc:
        print(f"floor guard: the workflow does not load ({exc or type(exc).__name__})")
        return 1
    if args.update_pins:
        (root / PINS).write_bytes(pins_text(pins).encode("utf-8"))
        print(f"pins written: {root / PINS}")
        return 0
    found = violations(root, args.pins)
    print(
        f"floor guard: {len(pins['jobs'])} jobs and {len(pins['files'])} guard files checked, {len(found)} violation(s)"
    )
    for line in found:
        print(line)
    return 0 if pins["jobs"] and pins["files"] and not found else 1


if __name__ == "__main__":
    sys.exit(main())
