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
   A protected-jobs table fixes each job's key, check names and required step
   text; job and step conditions, environment, runner, timeout, matrix and
   every workflow's triggers and write permissions are allowlisted. The pin
   file loads strictly, the lock and pytest configuration are judged by rule,
   and any symlink fails the guard, which never follows links.

The guard runs from the pull request's base branch in CI (see floor.yml). For
a stacked pull request that base is another feature branch.

Usage: python scripts/floor_guard.py [--root DIR] [--update-pins] [--pins FILE]
"""

from __future__ import annotations

import argparse
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
        f"python -m pip install --require-hashes --no-deps -r {LOCK}",
        f"python -m pip install --require-hashes --no-deps -r $RUNNER_TEMP/floor/{LOCK}",
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
    "scripts/leak_denylist_scan.py",
    "scripts/gh_pr.py",
    "scripts/no_ai_trailers.py",
    "tests/test_floor_config.py",
    LOCK,
    ".pre-commit-config.yaml",
    ".gitleaks.toml",
    ".gitleaksignore",
)
GUARD_GLOBS = (
    ".floor/**/*.py",
    "craft/**/*.py",
    "**/conftest.py",
    "pytest.ini",
    "pyproject.toml",
    "tox.ini",
    "setup.cfg",
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    # Interpreter startup files: python imports sitecustomize from sys.path at
    # startup, and a .pth file runs code when its directory is a site dir.
    "**/sitecustomize.py",
    "**/usercustomize.py",
    "**/*.pth",
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

# Every job in the floor workflow, the check names it must produce, and text
# each of its steps must still contain. A job renamed away, a decoy that takes
# a protected check name, or a protected key reused for a trivial step all fail.
PROTECTED_JOBS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "secrets": (("secrets (gitleaks)",), ("gitleaks/gitleaks-action@",)),
    "leak-denylist": (
        ("secrets (names and personal paths)",),
        ('python "$RUNNER_TEMP/leak_scan.py" --ci', "--text"),
    ),
    "kat-lint": (("tests (known-answer tests call the gate)",), ("kat_lint.py",)),
    "authorship": (
        ("authorship (no AI trailers)",),
        ("git log --all --format=%B", "python scripts/no_ai_trailers.py"),
    ),
    "tests": (("tests (3.11)", "tests (3.12)"), ("pytest -q",)),
    "lint": (("lint (ruff)",), ("ruff check .", "ruff format --check .")),
    "craft-voice": (
        ("craft (voice)",),
        ("python .floor/craft/voice_lint.py --commits",),
    ),
    "craft-changelog": (
        ("craft (changelog)",),
        ("python .floor/craft/changelog_gate.py --base",),
    ),
    "craft-comments": (
        ("craft (comments)",),
        ("python .floor/craft/comment_craft.py --base",),
    ),
    "craft-empty-diff": (
        ("craft (empty-diff)",),
        ("python .floor/craft/empty_diff_gate.py --base",),
    ),
    "floor-guard": (
        ("floor (guard from base)",),
        ('python "$RUNNER_TEMP/floor/floor_guard.py" --root . --pins',),
    ),
    "workflow-lint": (
        ("workflow (zizmor + actionlint)",),
        ("zizmorcore/zizmor-action@", "/tmp/actionlint"),
    ),
}
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
    "ACTIONLINT_VERSION": "1.7.12",
    "ACTIONLINT_SHA256": "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",
}
# What python may run in a guardrail step: these scripts, or -m pytest and -m
# pip with the lock. A variable that names a script may only hold these paths.
PY_SCRIPTS = frozenset(
    {
        "scripts/kat_lint.py",
        "scripts/no_ai_trailers.py",
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
    "scripts/no_ai_trailers.py": frozenset({("$RUNNER_TEMP/history.txt",)}),
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


def _load_yaml(text: str):
    import yaml

    return yaml.safe_load(text)


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


class _Collector:
    def __init__(self) -> None:
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
                if p.kind == "assignment":
                    self.assignments.append(p.word)
                if p.kind == "redirect":
                    target = getattr(p, "output", None)
                    if target is not None and getattr(target, "kind", None) == "word":
                        self.redirects.append(target.word)
                        self.writes.append(([w.word for w in words], target.word))
            self.commands.append([w.word for w in words])
        for attr in ("parts", "list"):
            for child in getattr(node, attr, None) or []:
                if hasattr(child, "kind"):
                    self.walk(child)
        for attr in ("command", "output"):
            child = getattr(node, attr, None)
            if child is not None and hasattr(child, "kind") and attr == "command":
                self.walk(child)


def run_violations(run: str, where: str) -> list[str]:
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
    col = _Collector()
    for tree in trees:
        col.walk(tree)
    if not col.commands and run.strip():
        found.append(f"{where}: no command found")
    for masked in col.masked:
        found.append(f"{where}: failure masked by || {masked}")
    for op, words in col.chains:
        if op == "&&" and words and words[0] in GUARDED:
            found.append(f"{where}: {words[0]} runs only after &&")
    for construct in sorted(col.hiding):
        found.append(f"{where}: {construct}, which can hide a failing command")
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
            if words[1:3] == ["-m", "pytest"]:
                found += _pytest_violations(words[3:], where)
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


def _python_violations(words: list[str], where: str) -> list[str]:
    found = []
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
        if " ".join(words) not in LOCKED_INSTALLS:
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
    if not shell_ok(((wf.get("defaults") or {}).get("run") or {}).get("shell")):
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
                or ((wf.get("defaults") or {}).get("run") or {}).get("shell")
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
                found += run_violations(str(run), sw)
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
    for key, (names, needles) in PROTECTED_JOBS.items():
        job = jobs.get(key)
        if not isinstance(job, dict):
            found.append(f"job {key}: protected job is missing")
            continue
        if sorted(check_names(key, job)) != sorted(n.casefold() for n in names):
            found.append(f"job {key}: check names are not {list(names)}")
        text = "\n".join(
            f"{s.get('run', '')}\n{s.get('uses', '')}"
            for s in job.get("steps") or []
            if isinstance(s, dict)
        )
        for needle in needles:
            if needle not in text:
                found.append(f"job {key}: required step text {needle!r} is missing")
    return found


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
    for rel in guard_files(root):
        if rel.rsplit("/", 1)[-1] == "conftest.py":
            found.append(f"pytest config: {rel} is not allowed")
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
    wf = _load_yaml((root / WORKFLOW).read_text(encoding="utf-8"))
    others = []
    for path in sorted((root / ".github" / "workflows").glob("*.y*ml")):
        if path.name != WORKFLOW.name:
            others.append(_load_yaml(path.read_text(encoding="utf-8")) or {})
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
    if args.update_pins:
        (root / PINS).write_bytes(pins_text(compute_pins(root)).encode("utf-8"))
        print(f"pins written: {root / PINS}")
        return 0
    found = violations(root, args.pins)
    pins = compute_pins(root)
    print(
        f"floor guard: {len(pins['jobs'])} jobs and {len(pins['files'])} guard files checked, {len(found)} violation(s)"
    )
    for line in found:
        print(line)
    return 0 if pins["jobs"] and pins["files"] and not found else 1


if __name__ == "__main__":
    sys.exit(main())
