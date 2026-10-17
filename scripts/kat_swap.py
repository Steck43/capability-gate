#!/usr/bin/env python3
"""Every known-answer test must change its answer when the gate changes.

A KAT that passes whatever the gate decides is not testing the gate. This
copies the tree into a scratch folder once per column and runs each KAT file
in every copy:

  real     the tree as it is, with the beacon wrapper added (decision logic unchanged)
  allow    Gate.evaluate replaced in the module file: every call is ALLOW
  deny     the same, every call is DENY
  invert   Gate.evaluate wrapped: the real decision with ALLOW and DENY
           swapped and ASK read as ALLOW (the unsafe direction)
  mut:*    one copy per constant-verdict Decision(...) in capability_gate.py
           with that one verdict flipped; the rest of the gate is real

The substitute sits in the module file of the copy, so every way a test
reaches the gate (an import, a reload, a hook started as a subprocess) runs
it, and no code in the test file decides whether it is there. Every column,
real included, appends a beacon row (column, pid, argv[0]) whenever evaluate
runs, so a column that never reached the gate is visible, unless the test
writes a row itself or another test in the same file reaches the gate.

Verdict per test, exactly one:

  not-run  skipped under the real gate (a strict xfail, a skip mark)
  broken   failed, errored or missing under the real gate, or a column wrote
           no junit report, or a duplicate test id (one <module> row on no report)
  tamper   the gate module, an adapter, conftest.py or pytest.ini changed on
           disk during a run (each copy is restored before every run)
  hollow   passed under the real gate, and the real column or a substitute
           column has no beacon row, or the inverted gate did not fail it, or
           neither allow-all nor deny-all failed it, or (with mutants) it
           killed no mutant
  real     passed under the real gate and none of the above

Only a reported test failure, from any exception in the test body, counts
against a column: an error, a skip, a missing test or a missing report never
makes a test real. A mutant no KAT kills is listed as an
uncovered branch; it fails the run only with --strict-branches, since it says
a branch has no KAT, not that a KAT is hollow.

Children run with a minimal environment (no PYTEST_ADDOPTS, plugin autoload
off, a temp folder inside each copy). conftest files stay on, since CI runs
them.

Strip condition: --strip allow|deny|invert|mutants|all installs nothing in
that column. Stripping any column must turn real tests hollow.

Known gaps (each can read real without testing the gate):
- G1 beacon rows can be written by the test itself; reach is per file, not per test.
- G2 the copy's column is detectable from its gate module (.kat-swap-gate, `_KAT_SWAP_MODE`, the mode string in the beacon call).
- G3 only the root conftest.py and pytest.ini are hashed; a report hook added by a nested conftest, or registered mid-run from a test (request.config.pluginmanager.register), can rewrite reports.
- G4 any failure under a column counts as a kill, so a test that fails for the wrong reason, or raises after the gate call, reads real; one such test kills every mutant and hides every uncovered branch.
- G5 each column runs once; a test whose outcome varies gets an unstable verdict.
- G6 not-run passes the run; a KAT file wholly skipped or of non-strict xfails exits 0.
- G7 a test that relabels Verdict members reads as the relabel, not the gate.
- G8 a test that reads the gate module and branches on what it finds.
- G9 a branch no KAT reaches is listed, not failed (--strict-branches fails it).

Advisory only: kat-swap must not become a required check until G1, G2, G3 and G4 are fixed, because until then a hollow KAT can read real.

Usage: python -I scripts/kat_swap.py [--only FILE ...] [--strip MODE ...]
       [--no-mutants] [--strict-branches] [--json OUT]
Exit 0 = every KAT test is real or not-run. Exit 1 = a hollow, broken or
tampering test, no KAT file, or an uncovered branch with --strict-branches.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import tokenize
import xml.etree.ElementTree as ET
from pathlib import Path

ROOF = Path(__file__).resolve().parents[1]
FIXED = ("real", "allow", "deny", "invert")
FLIP = {"ALLOW": "DENY", "DENY": "ALLOW", "ASK": "ALLOW"}

_BEACON = """

# --- behavioral KAT beacon, present only in a scratch copy ---
import os as _kat_os
import sys as _kat_sys


def _kat_beacon(mode):
    path = _kat_os.environ.get("KAT_SWAP_BEACON")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            argv0 = _kat_os.path.basename(_kat_sys.argv[0])
            fh.write(f"{mode}\\t{_kat_os.getpid()}\\t{argv0}\\n")
"""

_SUBSTITUTE = """
_KAT_SWAP_MODE = {mode!r}
_KAT_ORIG_EVALUATE = Gate.evaluate


def _kat_swap_evaluate(
    self, skill, tool, paths=(), *, trace=None, args=None, refuse=None, base_dir=None
):
    _kat_beacon(_KAT_SWAP_MODE)
    path_list = [str(p) for p in paths]
    if _KAT_SWAP_MODE == "invert":
        d = _KAT_ORIG_EVALUATE(
            self, skill, tool, path_list, trace=trace, args=args,
            refuse=refuse, base_dir=base_dir,
        )
        flip = {{
            Verdict.ALLOW: Verdict.DENY,
            Verdict.DENY: Verdict.ALLOW,
            Verdict.ASK: Verdict.ALLOW,
        }}
        return replace(d, verdict=flip.get(d.verdict, d.verdict), reason="substitute gate")
    v = Verdict.ALLOW if _KAT_SWAP_MODE == "allow" else Verdict.DENY
    d = Decision(v, "substitute gate", str(skill), str(tool), tuple(path_list))
    d = replace(d, enforced=(self._mode == ENFORCE))
    self._log(d, trace=None, arg_summary=None)
    return d


Gate.evaluate = _kat_swap_evaluate
"""

_MUTANT_TAIL = """
_KAT_ORIG_EVALUATE = Gate.evaluate


def _kat_mut_evaluate(self, *a, **k):
    _kat_beacon({mode!r})
    return _KAT_ORIG_EVALUATE(self, *a, **k)


Gate.evaluate = _kat_mut_evaluate
"""

_MARKER = re.compile(r"^#\s*KAT\b")
_NAME = re.compile(r"^test_k.*\.py$|kat", re.I)
# The KAT lint's own tests build rejected KATs as fixtures; they test the lint.
EXEMPT = {"tests/test_kat_lint.py", "tests/test_public_text_paths.py"}
_IGNORE = shutil.ignore_patterns(
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".tmp",
    "build",
    "dist",
    "decisions.jsonl*",
    ".capability-gate-folder",
)
# Files a test could change to undo the swap; hashed around every run.
INTEGRITY = (
    "capability_gate.py",
    "adapters",
    "__init__.py",
    "conftest.py",
    "pytest.ini",
)
_ENV_KEEP = (
    "PATH",
    "SYSTEMROOT",
    "COMSPEC",
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "LANG",
    "LC_ALL",
)


def _has_marker(src: str) -> bool:
    try:
        toks = tokenize.generate_tokens(io.StringIO(src).readline)
        return any(t.type == tokenize.COMMENT and _MARKER.match(t.string) for t in toks)
    except (tokenize.TokenError, SyntaxError):
        return False


def kat_files(root: Path) -> list[Path]:
    """The same name and marker rules as the KAT lint."""
    out = []
    for p in sorted((root / "tests").rglob("test*.py")):
        if p.relative_to(root).as_posix() in EXEMPT:
            continue
        if _NAME.search(p.name) or _has_marker(p.read_text("utf-8", errors="replace")):
            out.append(p)
    return out


def mutant_sites(src: str) -> list[tuple[str, int, int, int, str]]:
    """(label, line, col, end col, verdict) for each Decision(Verdict.X, ...)
    whose verdict is a constant ALLOW, DENY or ASK; the label names the
    enclosing function so a survivor says which branch has no KAT."""
    tree = ast.parse(src)
    owner: dict[int, str] = {}
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for n in ast.walk(fn):
                owner.setdefault(id(n), fn.name)
    sites = []
    for n in ast.walk(tree):
        if (
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id == "Decision"
            and n.args
            and isinstance(n.args[0], ast.Attribute)
            and isinstance(n.args[0].value, ast.Name)
            and n.args[0].value.id == "Verdict"
            and n.args[0].attr in FLIP
        ):
            a = n.args[0]
            where = owner.get(id(n), "<module>")
            label = f"mut:{where}:{a.lineno}:{a.attr}>{FLIP[a.attr]}"
            sites.append((label, a.lineno, a.col_offset, a.end_col_offset, a.attr))
    return sorted(sites, key=lambda s: s[1])


def mutate(src: str, site: tuple[str, int, int, int, str]) -> str:
    _, lineno, col, end_col, verdict = site
    lines = src.splitlines(keepends=True)
    line = lines[lineno - 1]
    if line[col:end_col] != f"Verdict.{verdict}":
        raise ValueError(f"mutant site moved: {site[0]}")
    lines[lineno - 1] = line[:col] + f"Verdict.{FLIP[verdict]}" + line[end_col:]
    return "".join(lines)


def _tree_hash(root: Path) -> str:
    h = hashlib.sha256()
    for name in INTEGRITY:
        p = root / name
        if not p.exists():
            h.update(f"absent:{name}".encode())
            continue
        files = sorted(p.rglob("*.py")) if p.is_dir() else [p]
        for f in files:
            h.update(f.relative_to(root).as_posix().encode())
            h.update(f.read_bytes())
    return h.hexdigest()


def make_copies(
    strip: set[str], mutants: bool = True
) -> tuple[dict[str, Path], list[str]]:
    """One scratch copy per column, each with its gate module written; the
    module text is kept so every run starts from it."""
    scratch = Path(tempfile.mkdtemp(prefix="kat-swap-"))
    gate_src = (ROOF / "capability_gate.py").read_text("utf-8")
    sites = mutant_sites(gate_src) if mutants else []
    modes = list(FIXED) + [s[0] for s in sites]
    copies: dict[str, Path] = {}
    for mode in modes:
        dest = scratch / secrets.token_hex(4)
        shutil.copytree(ROOF, dest, ignore=_IGNORE)
        stripped = (
            "all" in strip
            or mode in strip
            or (mode.startswith("mut:") and "mutants" in strip)
        )
        if mode == "real":
            text = gate_src + _BEACON + _MUTANT_TAIL.format(mode="real")
        elif stripped:
            text = gate_src
        elif mode in FIXED:
            text = gate_src + _BEACON + _SUBSTITUTE.format(mode=mode)
        else:
            site = next(s for s in sites if s[0] == mode)
            text = mutate(gate_src, site) + _BEACON + _MUTANT_TAIL.format(mode=mode)
        (dest / "capability_gate.py").write_text(text, "utf-8")
        (dest / ".kat-swap-gate").write_text(text, "utf-8")
        copies[mode] = dest
    return copies, modes


def _restore(root: Path) -> None:
    """Put the copy's integrity files back as written, so a test that changed
    them cannot reach the next file's run."""
    (root / "capability_gate.py").write_text(
        (root / ".kat-swap-gate").read_text("utf-8"), "utf-8"
    )
    for name in INTEGRITY[1:]:
        src, dst = ROOF / name, root / name
        if dst.is_dir():
            shutil.rmtree(dst, ignore_errors=True)
        elif dst.exists():
            dst.unlink()
        if src.is_dir():
            shutil.copytree(src, dst, ignore=_IGNORE)
        elif src.exists():
            shutil.copyfile(src, dst)


def clean_env(beacon: Path) -> dict[str, str]:
    env = {k: os.environ[k] for k in _ENV_KEEP if k in os.environ}
    tmp = beacon.parent / "tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    env.update(
        TEMP=str(tmp),
        TMP=str(tmp),
        TMPDIR=str(tmp),
        PYTHONDONTWRITEBYTECODE="1",
        PYTHONHASHSEED="0",
        PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
        KAT_SWAP_BEACON=str(beacon),
    )
    return env


def run_file(root: Path, kat: Path) -> tuple[dict[str, str], list[list[str]]]:
    """(outcome per test name, beacon rows) for one KAT file in one copy."""
    _restore(root)
    if kat.is_relative_to(ROOF / "tests"):
        rel = kat.relative_to(ROOF)
    else:
        rel = Path("tests") / kat.name
        shutil.copyfile(kat, root / rel)
    run = root / ".kat-swap-run" / secrets.token_hex(4)
    run.mkdir(parents=True)
    report, beacon = run / "report.xml", run / "beacon.tsv"
    beacon.write_text("", "utf-8")
    before = _tree_hash(root)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            f"--junitxml={report}",
            rel.as_posix(),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        env=clean_env(beacon),
    )
    tampered = _tree_hash(root) != before
    outcomes: dict[str, str] = {}
    if not report.exists():
        outcomes["<module>"] = "no-report"
    else:
        for case in ET.parse(report).getroot().iter("testcase"):
            cls = case.get("classname", "").rsplit(".", 1)[-1]
            cls = cls if cls[:1].isupper() else ""
            tid = f"{cls}::{case.get('name')}" if cls else case.get("name")
            kinds = {c.tag for c in case}
            if tid in outcomes:
                outcomes[tid] = "duplicate"
            elif "error" in kinds:
                outcomes[tid] = "error"
            elif "failure" in kinds:
                outcomes[tid] = "failed"
            elif "skipped" in kinds:
                outcomes[tid] = "skipped"
            else:
                outcomes[tid] = "passed"
    if tampered:
        outcomes = {k: "tamper" for k in outcomes} or {"<module>": "tamper"}
    rows = [ln.split("\t") for ln in beacon.read_text("utf-8").splitlines() if ln]
    return outcomes, rows


def _verdict(o: dict[str, str], kills: list[str], reach: dict, mutants: list[str]):
    if any(v == "tamper" for v in o.values()):
        return "tamper", "the gate module, an adapter or the pytest config changed"
    if any(v == "no-report" for v in o.values()):
        cols = sorted(m for m, v in o.items() if v == "no-report")
        return "broken", f"no junit report under {', '.join(cols)}"
    if any(v == "duplicate" for v in o.values()):
        return "broken", "duplicate test id in the junit report"
    if o["real"] == "skipped":
        return "not-run", "skipped under the real gate"
    if o["real"] != "passed":
        return "broken", f"{o['real']} under the real gate"
    if reach["real"]["lines"] == 0:
        return "hollow", "the real gate was never reached"
    if any(reach[m]["lines"] == 0 for m in FIXED[1:]):
        return "hollow", "a substitute column never reached the gate"
    if o["invert"] != "failed":
        return "hollow", "passes under the inverted gate"
    if "failed" not in (o["allow"], o["deny"]):
        return "hollow", "passes under allow-all and deny-all"
    if mutants and not kills:
        return "hollow", "kills no decision-branch mutant"
    if mutants:
        return "real", f"kills {len(kills)} of {len(mutants)} mutants"
    return "real", "follows the swapped gate"


def judge(kat: Path, copies: dict[str, Path], modes: list[str]) -> dict:
    per_mode, reach = {}, {}
    for m in modes:
        outcomes, rows = run_file(copies[m], kat)
        per_mode[m] = outcomes
        reach[m] = {
            "lines": len(rows),
            "pids": len({r[1] for r in rows if len(r) > 1}),
            "argv0": sorted({r[2] for r in rows if len(r) > 2}),
        }
    mutants = [m for m in modes if m.startswith("mut:")]
    tests = []
    for tid in sorted(set().union(*per_mode.values())):
        o = {m: per_mode[m].get(tid, "missing") for m in modes}
        kills = [m for m in mutants if o[m] == "failed"]
        verdict, why = _verdict(o, kills, reach, mutants)
        tests.append(
            {"id": tid, "outcomes": o, "kills": kills, "verdict": verdict, "why": why}
        )
    if any("<module>" in per_mode[m] for m in modes):
        tests = [t for t in tests if t["id"] == "<module>"][:1]
    return {"file": kat.name, "tests": tests, "reach": reach}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--only", nargs="*", type=Path, default=[])
    ap.add_argument(
        "--strip",
        nargs="*",
        default=[],
        choices=["allow", "deny", "invert", "mutants", "all"],
    )
    ap.add_argument("--no-mutants", action="store_true")
    ap.add_argument("--strict-branches", action="store_true")
    ap.add_argument("--json", type=Path)
    a = ap.parse_args(argv)
    kats = [p.resolve() for p in a.only] or kat_files(ROOF)
    if not kats:
        print("kat swap: no KAT file found")
        return 1
    copies, modes = make_copies(set(a.strip), mutants=not a.no_mutants)
    mutants = [m for m in modes if m.startswith("mut:")]
    try:
        results = [judge(kat, copies, modes) for kat in kats]
    finally:
        shutil.rmtree(next(iter(copies.values())).parent, ignore_errors=True)
    killed: set[str] = set()
    bad = 0
    print(f"strip={sorted(a.strip) or '-'} mutants={len(mutants)}")
    for r in results:
        for t in r["tests"]:
            o = t["outcomes"]
            killed.update(t["kills"])
            bad += t["verdict"] in ("hollow", "broken", "tamper")
            cols = " ".join(f"{m}={o[m]}" for m in FIXED)
            print(f"{r['file']}::{t['id']}: {t['verdict']} ({t['why']}) {cols}")
        for m in FIXED[1:]:
            rc = r["reach"][m]
            print(
                f"  reach {r['file']} {m}: {rc['lines']} row(s),"
                f" {rc['pids']} pid(s), argv0={rc['argv0']}"
            )
    survivors = [m for m in mutants if m not in killed]
    for m in survivors:
        print(f"uncovered branch: {m}")
    print(
        f"kat swap: {bad} problem(s), {len(survivors)} uncovered branch(es),"
        f" {len(kats)} KAT file(s)"
    )
    if a.json:
        a.json.write_text(
            json.dumps(
                {"strip": sorted(a.strip), "survivors": survivors, "results": results},
                indent=1,
            ),
            "utf-8",
        )
    return 1 if bad or (a.strict_branches and survivors) else 0


if __name__ == "__main__":
    sys.exit(main())
