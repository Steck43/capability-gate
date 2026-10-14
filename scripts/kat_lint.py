#!/usr/bin/env python3
"""Known-answer tests must be red because of the gate, not because they say so.

A known-answer test (KAT) runs a named attack through the gate and asserts the
known decision. Shapes that look like that and prove nothing:

* a test that fails by fiat: any ``pytest.fail`` (under any import alias or
  through ``getattr``), ``raise AssertionError``, or ``assert`` on a constant
  false value in a KAT file is red on every commit, fixed or not;
* a test that never runs its check: imperative ``pytest.skip`` or
  ``pytest.xfail`` outside a platform check, or an unconditional skip mark;
* a test that never reaches the gate, or returns before it does, and only
  checks that a receipt file exists.

Every test file, KAT or not, is also checked for the two escape hatches that
defeat ``xfail_strict``: an xfail mark with ``strict=False`` and an imperative
``pytest.xfail``.

KAT files are found recursively under tests/ and among top-level test files,
case-insensitively: names like test_k*.py or containing "kat", any file with a
"# KAT" comment, and any test file that names a receipts/ path. Files named on
the command line are linted as KATs whatever their name.

A test reaches the gate when its straight-line path (try, with, and for bodies
count; if branches, except handlers, and constant-guarded code do not), before
any return or raise, calls one of: .evaluate(...) or .throw(...) on a gate,
pre_tool_call, the Claude Code hook's main or _pre, or open_authorized_read.
A gate is a ``Gate(...)`` or ``_build_gate(...)`` result, a same-file fixture or
helper that returns one, a parameter named after such a fixture or annotated
``Gate``, or a local name assigned from any of those. A call into a same-file
helper, or a same-file fixture the test takes, counts when that helper or
fixture reaches the gate the same way. This is a lint against placeholder
shapes, not proof the call reaches the real gate: a gate built from a class
named Gate in the test file itself still passes.

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
# not the gate, and only match the KAT patterns by name and content.
EXEMPT = {"tests/test_kat_lint.py"}
_MARKER = re.compile(r"^#\s*KAT\b")
_NAME = re.compile(r"^test_k.*\.py$|kat", re.I)
_RECEIPTS = re.compile(r"(^|[\\/])receipts([\\/]|$)", re.I)
_GATE_METHODS = {"evaluate", "throw"}
_GATE_BUILDERS = {"Gate", "_build_gate"}
_PLATFORM = re.compile(r"\bsys\.platform\b|\bos\.name\b|\bplatform\.")
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


def test_files(root: Path) -> list[Path]:
    return sorted(
        p
        for p in (*root.joinpath("tests").rglob("*.py"), *root.glob("*.py"))
        if p.name.lower().startswith("test")
        and p.is_file()
        and p.relative_to(root).as_posix() not in EXEMPT
    )


def discover(root: Path) -> list[Path]:
    found = []
    for p in test_files(root):
        src = p.read_text(encoding="utf-8", errors="replace")
        if _NAME.search(p.name) or _has_marker(src) or _names_receipts(src):
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


def _pytest_aliases(tree: ast.Module) -> set[str]:
    names = {"pytest"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name == "pytest" and a.asname:
                    names.add(a.asname)
    return names


def _outcome_names(tree: ast.Module, outcome: str) -> set[str]:
    """Every spelling of pytest.<outcome> (fail, skip, xfail) this file can use."""
    names = {f"{alias}.{outcome}" for alias in _pytest_aliases(tree)}
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module in ("pytest", "_pytest.outcomes"):
            for a in n.names:
                if a.name == outcome:
                    names.add(a.asname or outcome)
    return names


def _call_name(node: ast.AST) -> str:
    if not isinstance(node, ast.Call):
        return ""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _fiat(
    node: ast.AST,
    fail_names: set[str],
    aliases: set[str],
    bindings: dict[str, object] | None = None,
) -> str | None:
    """Name of the fail-by-fiat form node is, if any."""
    if isinstance(node, ast.Call) and _dotted(node.func) in fail_names:
        return "pytest.fail"
    if isinstance(node, ast.Call) and _dotted(node.func) in {"sys.exit", "os._exit"}:
        return "forced exit"
    if isinstance(node, ast.Call) and _call_name(node) in {"eval", "exec"}:
        return "dynamic code"
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) >= 2
        and _dotted(node.args[0]) in aliases
    ):
        return "getattr(pytest, ...)"
    if isinstance(node, ast.Raise) and node.exc is not None:
        exc = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
        if _dotted(exc) == "AssertionError":
            return "raise AssertionError"
        return "forced failure"
    if isinstance(node, ast.Assert):
        known, value = _const(node.test, bindings)
        if known and isinstance(node.test, ast.Compare):
            return "constant comparison"
        if known and not value:
            return "assert False"
        if known:
            return "constant comparison"
    return None


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}


def _under_platform_check(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    while node in parents:
        node = parents[node]
        if isinstance(node, ast.If) and _PLATFORM.search(ast.unparse(node.test)):
            return True
    return False


def _is_mark(node: ast.expr, mark: str) -> bool:
    target = node.func if isinstance(node, ast.Call) else node
    name = _dotted(target) or ""
    return name == mark or name.endswith("." + mark)


def _xfail_hides_the_check(
    node: ast.Call, parents: dict[ast.AST, ast.AST], tree: ast.AST
) -> bool:
    """An xfail that never reaches the gate is the outcome. One that does is a known hole."""
    owner: ast.AST | None = node
    while owner in parents:
        owner = parents[owner]
        if isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
            break
    else:
        return False
    if not owner.name.startswith("test"):
        return False
    parsed = _File(tree)
    hit, _end = parsed.first_reach_in(owner, frozenset({owner.name}))
    return not hit


def _call_is_in_test(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    owner: ast.AST | None = node
    while owner in parents:
        owner = parents[owner]
        if isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            break
    else:
        return False
    return isinstance(
        owner, (ast.FunctionDef, ast.AsyncFunctionDef)
    ) and owner.name.startswith("test")


def lint_hatches(src: str, label: str) -> list[str]:
    """Escape hatches that defeat xfail_strict, checked in every test file."""
    tree = ast.parse(src, filename=label)
    parents = _parents(tree)
    xfail_calls = _outcome_names(tree, "xfail")
    problems = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and _is_mark(n, "mark.xfail"):
            for kw in n.keywords:
                if kw.arg == "strict" and _const(kw.value) == (True, False):
                    problems.append(
                        f"{label}:{n.lineno}: xfail(strict=False) lets a fixed bug"
                        " pass silently"
                    )
        if isinstance(n, ast.Call) and _dotted(n.func) in xfail_calls:
            problems.append(
                f"{label}:{n.lineno}: imperative pytest.xfail is never strict"
            )
        if isinstance(n, ast.Call) and _dotted(n.func) in {"sys.exit", "os._exit"}:
            if _call_is_in_test(n, parents):
                problems.append(f"{label}:{n.lineno}: forced exit decides the test")
        if isinstance(n, ast.Call) and _call_name(n) in {"eval", "exec"}:
            if _call_is_in_test(n, parents):
                problems.append(f"{label}:{n.lineno}: dynamic code decides the test")
        if isinstance(n, ast.Call) and _is_mark(n, "mark.skipif") and n.args:
            known, value = _const(n.args[0])
            if known and value and not _PLATFORM.search(ast.unparse(n.args[0])):
                problems.append(
                    f"{label}:{n.lineno}: skipif on a constant never runs the check"
                )
        if isinstance(n, ast.Call) and _is_mark(n, "mark.xfail"):
            strict = any(
                kw.arg == "strict" and _const(kw.value) == (True, True)
                for kw in n.keywords
            )
            has_raises = any(kw.arg == "raises" for kw in n.keywords)
            if has_raises and not strict and _xfail_hides_the_check(n, parents, tree):
                problems.append(
                    f"{label}:{n.lineno}: xfail(raises=) decides the outcome by fiat"
                )
    return problems


def _value(
    node: ast.AST | None, bindings: dict[str, object] | None = None
) -> tuple[bool, object]:
    """Fold literals, bound names, and one comparison. Unknown stays unknown."""
    bound = bindings or {}
    if isinstance(node, ast.Name) and node.id in bound:
        return True, bound[node.id]
    if isinstance(node, ast.Constant):
        return True, node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        known, value = _value(node.operand, bound)
        return (True, not value) if known else (False, None)
    if (
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and len(node.comparators) == 1
    ):
        left_known, left = _value(node.left, bound)
        right_known, right = _value(node.comparators[0], bound)
        if not (left_known and right_known):
            return False, None
        op = node.ops[0]
        if isinstance(op, ast.Eq):
            return True, left == right
        if isinstance(op, ast.NotEq):
            return True, left != right
        try:
            if isinstance(op, ast.Lt):
                return True, left < right
            if isinstance(op, ast.LtE):
                return True, left <= right
            if isinstance(op, ast.Gt):
                return True, left > right
            if isinstance(op, ast.GtE):
                return True, left >= right
        except TypeError:
            return False, None
    return False, None


def _const(
    node: ast.expr, bindings: dict[str, object] | None = None
) -> tuple[bool, bool]:
    known, value = _value(node, bindings)
    return (True, bool(value)) if known else (False, False)


def _constants(fn: ast.AST) -> dict[str, object]:
    """Names assigned once to a folded value. A later unknown write drops the name."""
    env: dict[str, object] = {}
    killed: set[str] = set()

    def visit(stmts: list[ast.stmt]) -> None:
        for stmt in stmts:
            if isinstance(stmt, _SCOPES):
                continue
            if (
                isinstance(stmt, ast.Assign)
                and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)
            ):
                name = stmt.targets[0].id
                known, value = _value(stmt.value, env)
                if known and name not in killed:
                    env[name] = value
                else:
                    env.pop(name, None)
                    killed.add(name)
                continue
            for child in ast.iter_child_nodes(stmt):
                if isinstance(child, list):
                    continue
            body = getattr(stmt, "body", None)
            if isinstance(body, list):
                visit(body)
            orelse = getattr(stmt, "orelse", None)
            if isinstance(orelse, list):
                visit(orelse)

    body = getattr(fn, "body", [])
    if isinstance(body, list):
        visit(body)
    return {name: value for name, value in env.items() if name not in killed}


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


def _is_gate_call(call: ast.Call, is_gate) -> bool:
    f = call.func
    if isinstance(f, ast.Attribute):
        if f.attr in _GATE_FUNCS:
            return True
        if f.attr in _GATE_METHODS:
            return bool(is_gate(f.value)) or _dotted(f.value) in _GATE_BUILDERS
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
        self._typed: dict[str, set[str]] = {}
        self._current_typed: set[str] = set()
        # Same-file fixtures and helpers that return or yield a gate.
        self.local_classes = {
            n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)
        }
        self.gate_makers: set[str] = set()
        changed = True
        while changed:
            changed = False
            for name, fn in self.funcs.items():
                if name in self.gate_makers:
                    continue
                typed = self.typed_names(fn)
                for n in ast.walk(fn):
                    if isinstance(n, (ast.Return, ast.Yield)) and self.makes_gate(
                        n.value, typed
                    ):
                        self.gate_makers.add(name)
                        changed = True
                        break
            self._typed.clear()

    def makes_gate(self, expr: ast.AST | None, typed: set[str]) -> bool:
        if isinstance(expr, ast.Name):
            return expr.id in typed
        if isinstance(expr, ast.Call):
            name = _dotted(expr.func) or ""
            base = name.rsplit(".", 1)[-1]
            root = name.split(".", 1)[0]
            if base in _GATE_BUILDERS and root not in self.local_classes:
                return True
            return name in self.gate_makers
        return False

    def typed_names(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
        """Names in fn that hold a gate: matching params, then assignments."""
        if fn.name in self._typed:
            return self._typed[fn.name]
        typed = {
            a.arg
            for a in fn.args.args
            if a.arg in self.gate_makers
            or (
                a.annotation is not None
                and (_dotted(a.annotation) or "").endswith("Gate")
                and (_dotted(a.annotation) or "").split(".", 1)[0]
                not in self.local_classes
            )
        }
        changed = True
        while changed:
            changed = False
            for n in ast.walk(fn):
                if (
                    isinstance(n, ast.Assign)
                    and len(n.targets) == 1
                    and isinstance(n.targets[0], ast.Name)
                    and n.targets[0].id not in typed
                    and self.makes_gate(n.value, typed)
                ):
                    typed.add(n.targets[0].id)
                    changed = True
        self._typed[fn.name] = typed
        return typed

    def _call_reaches(self, call: ast.Call, seen: frozenset[str]) -> bool:
        typed = self._current_typed
        if _is_gate_call(call, lambda e: self.makes_gate(e, typed)):
            return True
        if _runs_hook_script(call):
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
        self,
        stmts: list[ast.stmt],
        seen: frozenset[str],
        bindings: dict[str, object] | None = None,
    ) -> tuple[bool, ast.stmt | None]:
        """(gate reached, the return/raise that ended the path first, if any)."""
        for s in stmts:
            if isinstance(s, _SCOPES):
                continue
            if isinstance(s, ast.If):
                known, value = _const(s.test, bindings)
                if known:
                    hit, end = self.first_reach(
                        s.body if value else s.orelse, seen, bindings
                    )
                    if hit or end:
                        return hit, end
                    continue
                if any(self._call_reaches(c, seen) for c in _live_calls(s.test)):
                    return True, None
                continue
            if isinstance(s, ast.Try):
                hit, end = self.first_reach(s.body, seen, bindings)
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
                hit, end = self.first_reach(s.body, seen, bindings)
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

    def first_reach_in(
        self, fn: ast.FunctionDef | ast.AsyncFunctionDef, seen: frozenset[str]
    ) -> tuple[bool, ast.stmt | None]:
        outer = self._current_typed
        self._current_typed = self.typed_names(fn)
        try:
            return self.first_reach(fn.body, seen, _constants(fn))
        finally:
            self._current_typed = outer

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
                hit, _ = self.first_reach_in(fn, seen)
            self._memo[name] = hit
        return self._memo[name]


def lint_source(src: str, label: str) -> list[str]:
    tree = ast.parse(src, filename=label)
    fail_names = _outcome_names(tree, "fail")
    aliases = _pytest_aliases(tree)
    parents = _parents(tree)
    skip_like = {o: _outcome_names(tree, o) for o in ("skip", "xfail", "importorskip")}
    problems = []
    for n in ast.walk(tree):
        what = _fiat(n, fail_names, aliases)
        if what in {
            "forced failure",
            "raise AssertionError",
            "forced exit",
            "dynamic code",
        }:
            owner = n
            while owner in parents:
                owner = parents[owner]
                if isinstance(
                    owner, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    break
            else:
                owner = None
            if not isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
                what = None
            elif not owner.name.startswith("test"):
                what = None
        if what:
            problems.append(f"{label}:{n.lineno}: {what} in a KAT file fails by fiat")
        for outcome, names in skip_like.items():
            if (
                isinstance(n, ast.Call)
                and _dotted(n.func) in names
                and not _under_platform_check(n, parents)
            ):
                problems.append(
                    f"{label}:{n.lineno}: pytest.{outcome} in a KAT file outside a"
                    " platform check never runs the check"
                )
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in n.decorator_list:
                if _is_mark(d, "mark.skip"):
                    problems.append(
                        f"{label}:{d.lineno}: unconditional skip mark in a KAT file"
                        " never runs the check"
                    )

    f = _File(tree)
    for fn in f.funcs.values():
        bindings = _constants(fn)
        for n in ast.walk(fn):
            if isinstance(n, _SCOPES) and n is not fn:
                continue
            if not isinstance(n, ast.Assert):
                continue
            if _fiat(n, fail_names, aliases) is not None:
                continue
            what = _fiat(n, fail_names, aliases, bindings)
            if what:
                problems.append(
                    f"{label}:{n.lineno}: {what} in a KAT file fails by fiat"
                )
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
        hit, end = f.first_reach_in(fn, seen)
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


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("files", nargs="*", type=Path)
    ap.add_argument("--root", type=Path, default=ROOT)
    a = ap.parse_args(argv)
    files = a.files or discover(a.root)
    every = a.files or test_files(a.root)

    problems = []
    try:
        for path in files:
            problems += lint_source(path.read_text(encoding="utf-8"), path.as_posix())
        for path in every:
            problems += lint_hatches(path.read_text(encoding="utf-8"), path.as_posix())
    except SyntaxError as exc:
        print(f"kat lint: does not parse: {exc}", file=sys.stderr)
        return 2
    for p in problems:
        print(p)
    print(
        f"kat lint: {len(problems)} problem(s) in {len(files)} KAT file(s),"
        f" {len(every)} test file(s) checked for xfail escape hatches"
    )
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
