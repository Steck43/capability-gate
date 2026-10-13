"""Every known-answer test fails against a deliberately naive gate.

A KAT that still passes when the gate allows everything is not testing the
gate. The repository is copied twice into a scratch folder. In one copy
``capability_gate.py`` is left alone; in the other a naive ``_decide`` that
allows every call, and a kill switch that never fires, are appended to it.
Each KAT file runs in both copies. Because the naive gate is in the module
file itself, a hook started as a subprocess imports it too.

Per file:

- every test must pass in the real copy;
- a file in which no test ran (all skipped on this platform) is reported as
  skipped, not as checked;
- at least one test that passed in the real copy must fail, as a test
  failure rather than a collection or setup error, in the naive copy.
"""

from __future__ import annotations

import atexit
import functools
import io
import re
import shutil
import subprocess
import sys
import tempfile
import tokenize
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOF = Path(__file__).resolve().parents[1]

_NAIVE_PATCH = """

# Appended by tests/test_naive_gate_check.py in a scratch copy only.
def _decide(policy, skill, tool, paths, *_args, **_kwargs):
    return Decision(
        Verdict.ALLOW, "naive gate: allows everything", skill, tool, tuple(paths)
    )


Gate._kill_switch = lambda self, *_args, **_kwargs: None
"""

_MARKER = re.compile(r"^#\s*KAT\b")
_IGNORE = shutil.ignore_patterns(
    ".git",
    "__pycache__",
    ".pytest_cache",
    "decisions.jsonl*",
    ".capability-gate-folder",
)


def _has_marker(path: Path) -> bool:
    src = path.read_text(encoding="utf-8", errors="replace")
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(src).readline))
    except (tokenize.TokenError, SyntaxError):
        return False
    return any(t.type == tokenize.COMMENT and _MARKER.match(t.string) for t in tokens)


# The same name and marker rules as scripts/kat_lint.py, which arrives with
# the KAT linter change. The linter's own tests build bad KATs as fixtures and
# do not test the gate.
_NAME = re.compile(r"^test_k.*\.py$|kat", re.I)
_EXEMPT = {"tests/test_kat_lint.py"}


def _kat_files() -> list[Path]:
    return sorted(
        p
        for p in (ROOF / "tests").rglob("test*.py")
        if p.is_file()
        and p.relative_to(ROOF).as_posix() not in _EXEMPT
        and (_NAME.search(p.name) or _has_marker(p))
    )


KATS = _kat_files()


@functools.cache
def _copies() -> tuple[Path, Path]:
    scratch = Path(tempfile.mkdtemp(prefix="kat-naive-"))
    atexit.register(shutil.rmtree, scratch, True)
    real = scratch / "real"
    naive = scratch / "naive"
    for dest in (real, naive):
        shutil.copytree(ROOF, dest, ignore=_IGNORE)
    gate = naive / "capability_gate.py"
    gate.write_text(gate.read_text(encoding="utf-8") + _NAIVE_PATCH, encoding="utf-8")
    return real, naive


def _outcomes(root: Path, name: str) -> tuple[int, dict[str, str], str]:
    report = root.parent / f"{root.name}-{name}.xml"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            f"--junitxml={report}",
            str(Path("tests") / name),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    outcomes: dict[str, str] = {}
    if report.exists():
        for case in ET.parse(report).getroot().iter("testcase"):
            key = f"{case.get('classname')}::{case.get('name')}"
            kinds = {child.tag for child in case}
            if "error" in kinds:
                outcomes[key] = "error"
            elif "failure" in kinds:
                outcomes[key] = "failed"
            elif "skipped" in kinds:
                outcomes[key] = "skipped"
            else:
                outcomes[key] = "passed"
    return proc.returncode, outcomes, proc.stdout[-2000:]


@functools.cache
def _check(kat: str) -> tuple[str, str]:
    """Return (status, detail). Status is ok, skipped, hollow, or broken."""
    src = Path(kat)
    real_root, naive_root = _copies()
    for root in (real_root, naive_root):
        if src.parent != root / "tests":
            shutil.copyfile(src, root / "tests" / src.name)

    code, real, out = _outcomes(real_root, src.name)
    bad = sorted(k for k, v in real.items() if v in ("failed", "error"))
    if code not in (0, 5) or bad:
        return "broken", f"fails against the real gate ({code}): {bad}\n{out}"
    ran = {k for k, v in real.items() if v == "passed"}
    if not ran:
        return "skipped", f"no test in {src.name} ran on this platform"

    code, naive, out = _outcomes(naive_root, src.name)
    missing = sorted(ran - naive.keys())
    if missing:
        return "broken", f"not collected under the naive gate: {missing}\n{out}"
    caught = sorted(k for k in ran if naive[k] == "failed")
    if not caught:
        passed = sorted(k for k in ran if naive[k] == "passed")
        return "hollow", (
            f"{src.name}: no test failed against a gate that allows "
            f"everything; still passing: {passed}\n{out}"
        )
    return "ok", f"{len(caught)} of {len(ran)} tests fail under the naive gate"


def test_there_are_known_answer_tests_to_check() -> None:
    assert KATS, "no KAT files found; the naive-gate run would check nothing"
    checked = [p.name for p in KATS if _check(str(p))[0] == "ok"]
    assert checked, (
        "no KAT file ran a test on this platform; the naive-gate run would "
        "check nothing"
    )


@pytest.mark.parametrize("kat", KATS, ids=[p.name for p in KATS])
def test_kat_fails_against_a_naive_gate(kat: Path) -> None:
    status, detail = _check(str(kat))
    if status == "skipped":
        pytest.skip(detail)
    assert status == "ok", detail


# The checks below run the checker itself on small known inputs.

_HOOK_KAT = """# KAT
import json
import os
import subprocess
import sys
from pathlib import Path

ROOF = Path(__file__).resolve().parents[1]


def test_hook_denies_read_outside_the_grant(tmp_path):
    grant = tmp_path / "grant"
    grant.mkdir()
    allow = tmp_path / "allowlist.yaml"
    allow.write_text(
        "skills:\\n  UNLABELED:\\n    tools: [Read]\\n"
        f"    paths: ['{grant.as_posix()}/**']\\n",
        encoding="utf-8",
    )
    env = {
        **os.environ,
        "CG_CC_ALLOWLIST": str(allow),
        "CG_CC_LOG": str(tmp_path / "log" / "claude-code.jsonl"),
    }
    payload = {
        "tool_name": "Read",
        "tool_input": {"file_path": str(tmp_path / "outside.txt")},
    }
    r = subprocess.run(
        [sys.executable, str(ROOF / "adapters" / "claude_code_hook.py")],
        input=json.dumps(payload),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert r.returncode == 2, r.stderr
"""


def test_checker_flags_a_kat_that_ignores_the_gate(tmp_path: Path) -> None:
    hollow = tmp_path / "test_k99_hollow.py"
    hollow.write_text("# KAT\n\n\ndef test_hollow():\n    assert True\n", "utf-8")
    assert _check(str(hollow))[0] == "hollow"


def test_checker_does_not_count_a_fully_skipped_kat(tmp_path: Path) -> None:
    skipped = tmp_path / "test_k99_all_skipped.py"
    skipped.write_text(
        "# KAT\nimport pytest\n\n\n@pytest.mark.skip(reason='x')\n"
        "def test_never_runs():\n    assert False\n",
        "utf-8",
    )
    assert _check(str(skipped))[0] == "skipped"


def test_checker_reaches_a_hook_run_as_a_subprocess(tmp_path: Path) -> None:
    # Under the in-process plugin this file used before, the hook subprocess
    # imported the real gate, so a hook-level KAT could not fail there.
    hook = tmp_path / "test_k99_hook_level.py"
    hook.write_text(_HOOK_KAT, encoding="utf-8")
    status, detail = _check(str(hook))
    assert status == "ok", detail
