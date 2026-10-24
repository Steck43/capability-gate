"""Mutants for control_check.py: each one removes or inverts one clause, and
tests/test_control_check.py must fail under every one of them.

Run from the repository root:

    python design/required-controls/mutants.py

Each mutant is an exact text swap that must match once, so a refactor that
moves a clause fails here loudly instead of leaving a mutant that changes
nothing. The mutated module is loaded in memory; no file is written.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "control_check.py"
TESTS = "tests/test_control_check.py"

MUTANTS = [
    (
        "mandatory unmet is ASK",
        '"DENY" if req.level == "mandatory" else "ASK"',
        '"ASK"',
    ),
    (
        "strictest becomes mildest",
        "max(verdict, v, key=_RANK.get)",
        "min(verdict, v, key=_RANK.get)",
    ),
    ("load error exits 1", "        return 2\n", "        return 1\n"),
    (
        "PolicyError alone fails closed",
        "except Exception as e:",
        "except PolicyError as e:",
    ),
    (
        "version type not checked",
        "type(version) is int and version == 1",
        "version == 1",
    ),
    (
        "unknown top-level keys pass",
        '_need(not extra, f"{where}',
        '_need(True, f"{where}',
    ),
    (
        "empty tool list passes",
        "        and value\n        and all(",
        "        and all(",
    ),
    ("catalog field missing passes", "_need(not missing,", "_need(True,"),
    ("catalog extra field passes", "            not extra,\n", "            True,\n"),
    ("catalog binding not checked", 'row["binding"] in BINDINGS,', "True,"),
    (
        "catalog http source passes",
        'row["source_url"].startswith("https://"),',
        "True,",
    ),
    ("catalog duplicate key passes", '_need(row["key"] not in out,', "_need(True,"),
    (
        "profile unknown control passes",
        "_need(key in catalog,",
        "_need(key in catalog or True,",
    ),
    ("profile control twice passes", "_need(key not in out,", "_need(True,"),
    ("profile level not checked", "            level in LEVELS,", "            True,"),
    (
        "mandatory law as adopted passes",
        'not (catalog[key]["binding"] == "mandatory" and level != "mandatory")',
        "True",
    ),
    (
        "unknown obligation passes",
        "            set(obs) <= OBLIGATIONS,",
        "            True,",
    ),
    ("no_new_grants not true passes", 'obs["no_new_grants"] is True,', "True,"),
    ("new skill not widening", 'found.append(f"new skill {name!r}")', "pass"),
    (
        "new tool not widening",
        "for t in sorted(rule.tools - before.tools)",
        "for t in ()",
    ),
    ("new path not widening", "if g not in before.path_globs", "if False"),
    (
        "approval drop not widening",
        "for t in sorted(old.require_approval - new.require_approval)",
        "for t in ()",
    ),
    (
        "leaving isolate not widening",
        "for t in sorted(old.isolate - new.isolate)",
        "for t in ()",
    ),
    (
        "approval_for not checked",
        "if t in granted and t not in policy.require_approval:",
        "if False:",
    ),
    (
        "never_granted not checked",
        '        if t in granted:\n            why.append(f"tool {t!r} is granted")',
        '        if False:\n            why.append(f"tool {t!r} is granted")',
    ),
    (
        "no_new_grants not checked",
        'if req.obligations.get("no_new_grants") and old is not None:',
        "if False:",
    ),
    ("UNMET reads as DROPPED", '("UNMET" if before else "DROPPED")', '"DROPPED"'),
    (
        "profile removal passes",
        "            cur is None\n            or",
        "            False\n            or",
    ),
    (
        "profile downgrade passes",
        "            or LEVELS.index(cur.level) < LEVELS.index(req.level)\n            or not",
        "            or not",
    ),
    (
        "weakened obligations pass",
        "            or not _covers(cur.obligations, req.obligations)\n",
        "",
    ),
    ("fewer tools still covers", "val <= cur[name]", "True"),
    ("no warning for ungranted approval", "if t not in either", "if False"),
]

RUN = (
    "import sys, types; src = sys.stdin.read(); m = types.ModuleType('control_check');"
    " m.__file__ = sys.argv[1]; sys.modules['control_check'] = m;"
    " exec(compile(src, sys.argv[1], 'exec'), m.__dict__); import pytest;"
    " sys.exit(pytest.main(['-q', '-x', '-p', 'no:cacheprovider', sys.argv[2]]))"
)


def _run(src: str) -> int:
    return subprocess.run(
        [sys.executable, "-c", RUN, str(SOURCE), TESTS],
        input=src,
        text=True,
        cwd=ROOT,
        capture_output=True,
        check=False,
    ).returncode


def main() -> int:
    original = SOURCE.read_text(encoding="utf-8")
    if _run(original) != 0:
        print("baseline: tests fail on the unmutated module")
        return 2
    survived = 0
    for name, old, new in MUTANTS:
        if original.count(old) != 1:
            print(f"NOT APPLIED  {name}: text matches {original.count(old)} times")
            return 2
        mutated = original.replace(old, new)
        # A mutant that does not compile would count as killed for no reason.
        compile(mutated, str(SOURCE), "exec")
        killed = _run(mutated) != 0
        survived += not killed
        print(f"{'killed  ' if killed else 'SURVIVED'}  {name}")
    print(f"{len(MUTANTS) - survived} of {len(MUTANTS)} mutants killed")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
