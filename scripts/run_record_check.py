"""Fail the tests job unless pytest finished and ran every test module.

pytest can exit 0 without running the suite: a test module that calls
os._exit(0) while it is imported, or while one of its tests runs, ends the
process before any summary. The floor's conftest writes a run record only from
a finished session, and this check requires that:

- the record exists and says the session finished with exit status 0;
- every test the session collected reported an outcome;
- every file pytest would collect that defines a test (test_*.py or
  *_test.py with a top-level test function or Test class, outside
  pytest.ini's norecursedirs) was collected and run;
- no module was skipped as a whole, except the ones SKIPPABLE_MODULES names,
  since a whole-module skip runs none of its tests.

A test module runs arbitrary code inside pytest, so one that writes a forged
record before it ends the process is not caught here; see CHANGELOG.

Usage: python -I scripts/run_record_check.py RECORD (run from the repo root)
"""

from __future__ import annotations

import ast
import configparser
import fnmatch
import json
import os
import sys
from pathlib import Path


# Modules CI skips as a whole by design, with the reason. Each one runs no
# test in CI, so adding to this list is a change review must see.
SKIPPABLE_MODULES = {
    "test_e2_mode_staleness.py": "needs a Hermes install the tests job leaves out",
}


def _defines_tests(path: Path) -> bool:
    try:
        tree = ast.parse(path.read_bytes())
    except (SyntaxError, ValueError):
        return True  # pytest reports it as a collection error; expect it
    return any(
        (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test")
        )
        or (isinstance(node, ast.ClassDef) and node.name.startswith("Test"))
        for node in tree.body
    )


def expected_modules(root: Path) -> set[str]:
    ini = configparser.ConfigParser()
    ini.read(root / "pytest.ini", encoding="utf-8")
    skip = ini.get("pytest", "norecursedirs", fallback="").split()
    found: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [
            d for d in dirnames if not any(fnmatch.fnmatch(d, p) for p in skip)
        ]
        for name in filenames:
            if not name.endswith(".py"):
                continue
            if not (name.startswith("test_") or name.endswith("_test.py")):
                continue
            path = Path(dirpath) / name
            if _defines_tests(path):
                found.add(path.relative_to(root).as_posix())
    return found


def problems(record: dict, root: Path) -> list[str]:
    out: list[str] = []
    if record.get("finished") is not True:
        out.append("the session did not finish")
    if record.get("exitstatus") != 0:
        out.append(f"exit status {record.get('exitstatus')!r}, not 0")
    collected, reported = record.get("collected"), record.get("reported")
    if not isinstance(collected, int) or isinstance(collected, bool) or collected < 1:
        out.append("no tests collected")
    if reported != collected:
        out.append(f"{reported!r} tests reported of {collected!r} collected")
    modules = record.get("modules")
    if not isinstance(modules, list):
        out.append("the record lists no modules")
        modules = []
    skipped = record.get("skipped_modules", [])
    if not isinstance(skipped, list):
        out.append("the record's skipped modules are not a list")
        skipped = []
    skipped = set(map(str, skipped))
    for name in sorted(skipped - set(SKIPPABLE_MODULES)):
        out.append(f"{name}: skipped as a whole module")
    ran = set(map(str, modules)) | (skipped & set(SKIPPABLE_MODULES))
    for missing in sorted(expected_modules(root) - ran):
        out.append(f"{missing}: did not run")
    return out


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: run_record_check.py RECORD")
        return 2
    try:
        record = json.loads(Path(args[0]).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        print("pytest run check: no run record; the session ended before it finished")
        return 1
    if not isinstance(record, dict):
        print("pytest run check: no run record; the file is not a record")
        return 1
    found = problems(record, Path.cwd())
    for line in found:
        print(f"pytest run check: {line}")
    if found:
        return 1
    print(
        f"pytest run check: {record['collected']} tests in "
        f"{len(record['modules'])} modules, exit status 0"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
