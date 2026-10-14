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

2. Rules, so the pinned values themselves cannot be weak. Every run block is
   parsed as shell (bashlex) and every command in it is checked, including
   after separators, pipes, substitutions, conditionals and env prefixes:
   nothing may switch off stop-on-error, write a runner environment, path,
   output or state file by any spelling, run constructed or indirect commands,
   install anything but the hash-locked lock file, or make a lint step
   non-failing. Check names are compared after matrix expansion and case
   folding, and no two jobs may produce the same one. Checkout inputs may not
   change ref, repository, or file set.

Usage: python scripts/floor_guard.py [--root DIR] [--update-pins]
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
    "tests/test_floor_config.py",
    LOCK,
    ".pre-commit-config.yaml",
    ".gitleaks.toml",
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


def guard_files(root: Path) -> list[str]:
    found = {f for f in GUARD_FILES if (root / f).is_file()}
    for pattern in GUARD_GLOBS:
        for path in root.glob(pattern):
            rel = path.relative_to(root).as_posix()
            if path.is_file() and not rel.startswith(
                (".git/", ".venv/", "node_modules/")
            ):
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
        self._condition = 0

    def _head(self, node) -> list[str]:
        if getattr(node, "kind", None) == "command":
            return [p.word for p in node.parts if p.kind == "word"]
        if getattr(node, "kind", None) == "pipeline":
            return self._head(node.parts[-1])
        return []

    def walk(self, node) -> None:
        kind = getattr(node, "kind", None)
        if kind == "list":
            parts = node.parts
            for i, part in enumerate(parts):
                if (
                    getattr(part, "kind", None) == "operator"
                    and part.op == "||"
                    and i + 1 < len(parts)
                ):
                    words = self._head(parts[i + 1])
                    if words and (
                        words[0] in MASKS
                        or (words[0] == "exit" and words[1:2] in ([], ["0"]))
                    ):
                        self.masked.append(" ".join(words[:2]))
        if kind == "pipeline" and not self._condition:
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
        if head == "ruff" and any(LINT_SOFTENERS.match(w) for w in words[1:]):
            found.append(f"{where}: lint made non-failing")
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
    return found


def shell_ok(shell: object) -> bool:
    if shell is None:
        return True
    text = str(shell).strip()
    parts = text.split()
    if not parts or parts[0] not in {"bash", "sh"}:
        return False
    flags = [p for p in parts[1:] if p.startswith(("-", "+"))]
    on = any(re.fullmatch(r"-[A-Za-z]*e[A-Za-z]*", f) for f in flags)
    off = any(f.startswith("+") for f in flags) or "{0}" not in parts
    return on and not off


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
    if wf.get("permissions") != READ_ONLY:
        found.append("workflow: permissions beyond contents: read")
    if not shell_ok(((wf.get("defaults") or {}).get("run") or {}).get("shell")):
        found.append("workflow: default shell without stop-on-error")
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
        if not shell_ok(((job.get("defaults") or {}).get("run") or {}).get("shell")):
            found.append(f"{where}: default shell without stop-on-error")
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
                found.append(f"{sw}: shell without stop-on-error")
            uses = step.get("uses")
            for var, value in (step.get("env") or {}).items():
                token_ok = uses is not None and TOKEN_ENV.get(str(var)) == value
                if SENSITIVE_VARS.match(str(var)) and not token_ok:
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
    pins_path = pins_path or root / PINS
    if not pins_path.is_file():
        return ["pin: .github/floor-pins.json is missing"]
    try:
        pins = pins_from_file(json.loads(pins_path.read_text(encoding="utf-8")))
    except ValueError as exc:  # JSONDecodeError and PinFormatError
        return [f"pin: .github/floor-pins.json is malformed ({exc})"]
    return pin_violations(root, pins) + job_violations(wf, others)


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
        (root / PINS).write_bytes(
            (
                json.dumps(pins_to_file(compute_pins(root)), indent=2, sort_keys=True)
                + "\n"
            ).encode("utf-8")
        )
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
