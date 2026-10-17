#!/usr/bin/env python3
"""Known-answer tests must be red because of the gate, not because they say so.

A known-answer test (KAT) runs a named attack through the gate and asserts the
known decision. Shapes that look like that and prove nothing:

* a test that fails by fiat: any ``pytest.fail`` (under any import alias) or
  ``raise AssertionError`` in a KAT file is red on every commit, fixed or not;
* a test that never reaches the gate, or returns before it does, and only
  checks that a receipt file exists.

KAT files are found among test files: those under tests/ and at the top level
whose names start with test, and every file pytest itself collects (its
testpaths, python_files and norecursedirs from pytest.ini, or pytest's
defaults), so a KAT pytest runs is never skipped. Among them, case-
insensitively: names like test_k*.py or containing "kat", any file with a
"# KAT" comment, and any test file that names a receipts/ path. Files named on
the command line are linted as KATs whatever their name.

Every file is read as Python reads it: a coding cookie other than UTF-8, or
bytes that are not UTF-8, is a lint problem, never a traceback.

A test reaches the gate when its straight-line path (try, with, and for bodies
count; if branches, except handlers, and constant-guarded code do not), before
any return or raise, calls one of: an .evaluate(...) or .throw(...) method,
pre_tool_call, the Claude Code hook's main or _pre, or open_authorized_read.
A call into a same-file helper, or a same-file fixture the test takes, counts
when that helper or fixture reaches the gate the same way. The receiver of the
call is not type-checked, so a local class with an evaluate method passes; this
is a lint against placeholder shapes, not proof the call reaches the real gate.

Exit 0 = clean. Exit 1 = violation. Exit 2 = a file did not parse.
"""

from __future__ import annotations

import argparse
import ast
import codecs
import io
import re
import sys
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# The linter's own tests build rejected KATs as fixtures; they test the linter,
# not the gate, and only match the KAT patterns by name and content.
# Test files that match the name or receipts/ heuristics without being
# known-answer tests: the lint's own tests, and the check that public text cites
# no path into another repository's receipt tree (it reads text and calls no
# gate). The exemption covers those two heuristics only: a "# KAT" marker still
# makes either file a KAT. Each one is a pinned floor guard file.
EXEMPT = {"tests/test_kat_lint.py", "tests/test_public_text_paths.py"}
_MARKER = re.compile(r"^#\s*KAT\b")
_NAME = re.compile(r"^test_k.*\.py$|kat", re.I)
_RECEIPTS = re.compile(r"(^|[\\/])receipts([\\/]|$)", re.I)
_GATE_METHODS = {"evaluate", "throw"}
_GATE_FUNCS = {"pre_tool_call", "open_authorized_read", "_pre"}
_HOOK_MAIN = re.compile(r"hook", re.I)
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


def _has_marker(src: str) -> bool:
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type == tokenize.COMMENT and _MARKER.match(tok.string):
                return True
    except (tokenize.TokenError, SyntaxError):
        return False
    return False


def _names_receipts(src: str) -> bool:
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return False
    return any(
        isinstance(n, ast.Constant)
        and isinstance(n.value, str)
        and _RECEIPTS.search(n.value)
        for n in ast.walk(tree)
    )


# pytest's defaults when pytest.ini does not set the key.
_PYTEST_FILES = ("test_*.py", "*_test.py")
_PYTEST_NORECURSE = (
    "*.egg",
    ".*",
    "_darcs",
    "build",
    "CVS",
    "dist",
    "node_modules",
    "venv",
    "{arch}",
)


def _pytest_settings(root: Path) -> tuple[list[Path], list[str], list[str]]:
    """testpaths, python_files and norecursedirs as pytest reads them from
    pytest.ini, with pytest's defaults for any key it does not set."""
    import configparser

    ini = configparser.ConfigParser(interpolation=None)
    try:
        ini.read(root / "pytest.ini", encoding="utf-8")
    except (configparser.Error, UnicodeDecodeError):
        pass
    sec = ini["pytest"] if ini.has_section("pytest") else {}
    paths = [root / x for x in sec.get("testpaths", "").split()] or [root]
    files = sec.get("python_files", "").split() or list(_PYTEST_FILES)
    skip = sec.get("norecursedirs", "").split() or list(_PYTEST_NORECURSE)
    return paths, files, skip


def _pytest_collects(root: Path) -> set[Path]:
    """Every file pytest would collect from root with no arguments."""
    import fnmatch
    import os

    paths, files, skip = _pytest_settings(root)
    out: set[Path] = set()
    for base in paths:
        if base.is_file():
            out.add(base)
            continue
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            dirnames[:] = [
                d for d in dirnames if not any(fnmatch.fnmatch(d, s) for s in skip)
            ]
            for name in filenames:
                if any(fnmatch.fnmatch(name, pat) for pat in files):
                    out.add(Path(dirpath) / name)
    return out


def discover(root: Path) -> list[Path]:
    candidates = {
        p
        for p in (*root.joinpath("tests").rglob("*.py"), *root.glob("*.py"))
        if p.name.lower().startswith("test") and p.is_file()
    } | {p for p in _pytest_collects(root) if p.suffix == ".py" and p.is_file()}
    found = []
    for p in sorted(candidates):
        src = p.read_bytes().decode("utf-8", errors="replace")
        if _has_marker(src):
            found.append(p)
        elif p.relative_to(root).as_posix() in EXEMPT:
            continue
        elif _NAME.search(p.name) or _names_receipts(src):
            found.append(p)
    return sorted(found)


def _dotted(node: ast.expr) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _fail_names(tree: ast.Module) -> set[str]:
    """Every spelling of pytest.fail this file can use."""
    names = {"pytest.fail"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name == "pytest" and a.asname:
                    names.add(f"{a.asname}.fail")
        elif isinstance(n, ast.ImportFrom) and n.module in (
            "pytest",
            "_pytest.outcomes",
        ):
            for a in n.names:
                if a.name == "fail":
                    names.add(a.asname or "fail")
    return names


def _is_by_fiat(node: ast.AST, fail_names: set[str]) -> bool:
    if isinstance(node, ast.Call) and _dotted(node.func) in fail_names:
        return True
    if isinstance(node, ast.Raise) and node.exc is not None:
        exc = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
        return _dotted(exc) == "AssertionError"
    return False


def _const(node: ast.expr) -> tuple[bool, bool]:
    if isinstance(node, ast.Constant):
        return True, bool(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        known, value = _const(node.operand)
        return known, not value
    return False, False


def _live_calls(node: ast.AST) -> list[ast.Call]:
    """Calls under node that can run: no nested defs, no constant-dead branches."""
    out = []
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, ast.Call):
            out.append(n)
        if isinstance(n, ast.IfExp):
            known, value = _const(n.test)
            if known:
                stack.append(n.body if value else n.orelse)
                continue
        if isinstance(n, ast.BoolOp):
            for v in n.values:
                stack.append(v)
                known, value = _const(v)
                if known and value == isinstance(n.op, ast.Or):
                    break
            continue
        stack.extend(c for c in ast.iter_child_nodes(n) if not isinstance(c, _SCOPES))
    return out


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


def _runs_hook_script(call: ast.Call) -> bool:
    """A subprocess call that names the Claude Code hook script drives the real hook."""
    return any(
        isinstance(c, ast.Constant)
        and isinstance(c.value, str)
        and "claude_code_hook" in c.value
        for c in ast.walk(call)
    )


class _File:
    def __init__(self, tree: ast.Module) -> None:
        self.funcs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.funcs.setdefault(n.name, n)
        self._memo: dict[str, bool] = {}

    def _call_reaches(self, call: ast.Call, seen: frozenset[str]) -> bool:
        if _is_gate_call(call) or _runs_hook_script(call):
            return True
        callee = call.func
        name = None
        if isinstance(callee, ast.Name):
            name = callee.id
        elif (
            isinstance(callee, ast.Attribute)
            and isinstance(callee.value, ast.Name)
            and callee.value.id in ("self", "cls")
        ):
            name = callee.attr
        return bool(
            name in self.funcs
            and name not in seen
            and self.reaches(name, seen | {name})
        )

    def first_reach(
        self, stmts: list[ast.stmt], seen: frozenset[str]
    ) -> tuple[bool, ast.stmt | None]:
        """(gate reached, the return/raise that ended the path first, if any)."""
        for s in stmts:
            if isinstance(s, _SCOPES):
                continue
            if isinstance(s, ast.If):
                known, value = _const(s.test)
                if known:
                    hit, end = self.first_reach(s.body if value else s.orelse, seen)
                    if hit or end:
                        return hit, end
                    continue
                if any(self._call_reaches(c, seen) for c in _live_calls(s.test)):
                    return True, None
                continue
            if isinstance(s, ast.Try):
                hit, end = self.first_reach(s.body, seen)
                if hit or end:
                    return hit, end
                continue
            if isinstance(s, (ast.With, ast.AsyncWith, ast.For, ast.AsyncFor)):
                head = (
                    [i.context_expr for i in s.items]
                    if isinstance(s, (ast.With, ast.AsyncWith))
                    else [s.iter]
                )
                if any(
                    self._call_reaches(c, seen) for h in head for c in _live_calls(h)
                ):
                    return True, None
                hit, end = self.first_reach(s.body, seen)
                if hit or end:
                    return hit, end
                continue
            if isinstance(s, (ast.While, ast.Match)):
                continue
            if any(self._call_reaches(c, seen) for c in _live_calls(s)):
                return True, None
            if isinstance(s, (ast.Return, ast.Raise)):
                return False, s
        return False, None

    def reaches(self, name: str, seen: frozenset[str]) -> bool:
        if name not in self._memo:
            self._memo[name] = False
            fn = self.funcs[name]
            hit = any(
                a.arg in self.funcs
                and a.arg not in seen
                and self.reaches(a.arg, seen | {a.arg})
                for a in fn.args.args
            )
            if not hit:
                hit, _ = self.first_reach(fn.body, seen)
            self._memo[name] = hit
        return self._memo[name]


def lint_source(src: str, label: str) -> list[str]:
    tree = ast.parse(src, filename=label)
    fail_names = _fail_names(tree)
    problems = []
    for n in ast.walk(tree):
        if _is_by_fiat(n, fail_names):
            what = "raise AssertionError" if isinstance(n, ast.Raise) else "pytest.fail"
            problems.append(f"{label}:{n.lineno}: {what} in a KAT file fails by fiat")

    f = _File(tree)
    for name, fn in f.funcs.items():
        if not name.startswith("test"):
            continue
        where = f"{label}:{fn.lineno} {name}"
        seen = frozenset({name})
        by_fixture = any(
            a.arg in f.funcs and f.reaches(a.arg, seen | {a.arg}) for a in fn.args.args
        )
        if by_fixture:
            continue
        hit, end = f.first_reach(fn.body, seen)
        if hit:
            continue
        if end is not None:
            problems.append(
                f"{where}: returns or raises at line {end.lineno} before reaching the gate"
            )
        else:
            problems.append(
                f"{where}: never reaches the gate on its straight-line path"
            )
    return problems


def _source(path: Path) -> tuple[str | None, str | None]:
    """The file's text as Python reads it, or the problem that stops it. A
    coding cookie other than UTF-8 makes Python read different text than the
    lint would, so it is refused rather than followed."""
    data = path.read_bytes()
    lines = iter(data.splitlines(keepends=True))
    try:
        encoding, _ = tokenize.detect_encoding(lambda: next(lines, b""))
    except SyntaxError:
        return None, "declares a source encoding Python does not know"
    if codecs.lookup(encoding).name not in ("utf-8", "utf-8-sig"):
        return None, f"declares a source encoding other than UTF-8 ({encoding})"
    try:
        return data.decode(encoding), None
    except UnicodeDecodeError:
        return None, "is not valid UTF-8"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("files", nargs="*", type=Path)
    ap.add_argument("--root", type=Path, default=ROOT)
    a = ap.parse_args(argv)
    files = a.files or discover(a.root)

    problems = []
    for path in files:
        src, why = _source(path)
        if src is None:
            problems.append(f"{path.as_posix()}:1: {why}")
            continue
        try:
            problems += lint_source(src, path.as_posix())
        except SyntaxError as exc:
            print(f"kat lint: {path}: does not parse: {exc}", file=sys.stderr)
            return 2
    for p in problems:
        print(p)
    print(f"kat lint: {len(problems)} problem(s) in {len(files)} KAT file(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
