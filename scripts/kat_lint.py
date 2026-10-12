#!/usr/bin/env python3
"""Known-answer tests must be red because of the gate, not because they say so.

A known-answer test (KAT) runs a named attack through the gate and asserts the
known decision. Two shapes look like that and prove nothing:

* a test whose first statement is an unconditional pytest.fail(...): it is red
  on every commit, fixed or not, so "failing first" carries no information;
* a test that never calls the gate and only checks that a receipt file exists.

KAT files are tests/test_k*.py, tests/test_*kat*.py, and any test file with a
"# KAT" comment line. Files named on the command line are linted as KATs
whatever their name.

A test passes rule (b) when it, a helper defined in the same file, or a fixture
defined in the same file calls one of: an .evaluate(...) or .throw(...) method
(Gate.evaluate, gate.evaluate, the kill switch), pre_tool_call, the Claude Code
hook's main or _pre, or open_authorized_read. The receiver is not type-checked,
so this is a lint against the two shapes above, not proof the call reaches the
real gate; review still reads the test.

Exit 0 = clean. Exit 1 = violation. Exit 2 = a file did not parse.
"""

from __future__ import annotations

import argparse
import ast
import io
import re
import sys
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# The linter's own tests build rejected KATs as fixtures; they test the linter,
# not the gate, and only match the KAT file pattern by name.
EXEMPT = {"tests/test_kat_lint.py"}
_MARKER = re.compile(r"^#\s*KAT\b")
_GATE_METHODS = {"evaluate", "throw"}
_GATE_FUNCS = {"pre_tool_call", "open_authorized_read", "_pre"}
_HOOK_MAIN = re.compile(r"hook", re.I)


def _has_marker(src: str) -> bool:
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type == tokenize.COMMENT and _MARKER.match(tok.string):
                return True
    except (tokenize.TokenError, SyntaxError):
        return False
    return False


def discover(root: Path) -> list[Path]:
    found: set[Path] = set()
    tests = root / "tests"
    found.update(tests.glob("test_k*.py"))
    found.update(tests.glob("test_*kat*.py"))
    for p in [*tests.rglob("*.py"), *root.glob("test_*.py")]:
        if _has_marker(p.read_text(encoding="utf-8", errors="replace")):
            found.add(p)
    return sorted(p for p in found if p.relative_to(root).as_posix() not in EXEMPT)


def _is_gate_call(call: ast.Call) -> bool:
    f = call.func
    if isinstance(f, ast.Attribute):
        if f.attr in _GATE_METHODS or f.attr in _GATE_FUNCS:
            return True
        if f.attr == "main":
            recv = f.value
            name = (
                recv.attr
                if isinstance(recv, ast.Attribute)
                else getattr(recv, "id", "")
            )
            return bool(_HOOK_MAIN.search(name or ""))
        return False
    return isinstance(f, ast.Name) and f.id in _GATE_FUNCS


def _called_names(fn: ast.AST) -> set[str]:
    out = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            if isinstance(n.func, ast.Name):
                out.add(n.func.id)
            elif isinstance(n.func, ast.Attribute) and isinstance(
                n.func.value, ast.Name
            ):
                if n.func.value.id in ("self", "cls"):
                    out.add(n.func.attr)
    return out


def _calls_gate_directly(fn: ast.AST) -> bool:
    return any(isinstance(n, ast.Call) and _is_gate_call(n) for n in ast.walk(fn))


def _subprocess_runs_hook(fn: ast.AST) -> bool:
    """A subprocess call that names the Claude Code hook script drives the real hook."""
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            for c in ast.walk(n):
                if isinstance(c, ast.Constant) and isinstance(c.value, str):
                    if "claude_code_hook" in c.value:
                        return True
    return False


def _first_statement(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.stmt | None:
    body = list(fn.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
    ):
        if isinstance(body[0].value.value, str):
            body = body[1:]
    return body[0] if body else None


def _is_pytest_fail(stmt: ast.stmt | None) -> bool:
    if not isinstance(stmt, ast.Expr) or not isinstance(stmt.value, ast.Call):
        return False
    f = stmt.value.func
    if isinstance(f, ast.Attribute) and f.attr == "fail":
        return isinstance(f.value, ast.Name) and f.value.id == "pytest"
    return isinstance(f, ast.Name) and f.id == "fail"


def lint_source(src: str, label: str) -> list[str]:
    tree = ast.parse(src, filename=label)
    funcs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    tests: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs.setdefault(n.name, n)
            if n.name.startswith("test"):
                tests.append(n)

    reaches: dict[str, bool] = {}

    def reaches_gate(name: str, seen: frozenset[str]) -> bool:
        if name in reaches:
            return reaches[name]
        fn = funcs[name]
        hit = _calls_gate_directly(fn) or _subprocess_runs_hook(fn)
        if not hit:
            callees = _called_names(fn) | {a.arg for a in fn.args.args}
            hit = any(
                c in funcs and c not in seen and reaches_gate(c, seen | {c})
                for c in callees
            )
        reaches[name] = hit
        return hit

    problems = []
    for t in tests:
        where = f"{label}:{t.lineno} {t.name}"
        if _is_pytest_fail(_first_statement(t)):
            problems.append(f"{where}: first statement is an unconditional pytest.fail")
        if not reaches_gate(t.name, frozenset({t.name})):
            problems.append(
                f"{where}: never calls the gate (directly, via helper, or fixture)"
            )
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("files", nargs="*", type=Path)
    ap.add_argument("--root", type=Path, default=ROOT)
    a = ap.parse_args(argv)
    files = a.files or discover(a.root)

    problems = []
    for f in files:
        try:
            problems += lint_source(f.read_text(encoding="utf-8"), f.as_posix())
        except SyntaxError as exc:
            print(f"kat lint: {f}: does not parse: {exc}", file=sys.stderr)
            return 2
    for p in problems:
        print(p)
    print(f"kat lint: {len(problems)} problem(s) in {len(files)} KAT file(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
