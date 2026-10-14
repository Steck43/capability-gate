#!/usr/bin/env python3
"""Known-answer tests must be red because of the gate, not because they say so.

A known-answer test (KAT) runs a named attack through the gate and asserts the
known decision. The lint rejects every shape below in a KAT file. Each rule
lists what it sees through; anything it cannot read counts against the test.

Fiat outcomes, anywhere in the file (tests, helpers, nested functions, module):

* a fail, exit, or dynamic-code call under any spelling: ``pytest.fail``,
  ``pytest.exit``, ``sys.exit``, ``os._exit``, ``os.abort``, ``exit``,
  ``quit``, ``signal.raise_signal``, ``os.kill``, ``eval``, ``exec``,
  ``compile``, ``runpy.run_path`` and ``runpy.run_module``, reached through
  import aliases (``_pytest.outcomes`` included), assignment aliases,
  ``__import__`` or ``importlib.import_module`` with a constant name,
  ``getattr`` with a constant or folded name, ``vars(m)[...]``,
  ``m.__dict__[...]``, ``globals()[...]``, ``builtins`` and ``__builtins__``,
  or an element of a literal list or tuple. A plain reference counts as much
  as a call, so handing one to ``functools.partial`` counts. ``getattr`` with a name the lint cannot
  fold, on pytest, sys, os, builtins, importlib, runpy, unittest or signal, is
  a dynamic attribute; ``__import__`` or ``import_module`` with a name it
  cannot fold is a dynamic import;
* raising ``AssertionError``, ``SystemExit``, ``KeyboardInterrupt``, a pytest
  outcome exception or ``unittest.SkipTest``;
* an ``assert`` whose test folds to a constant, or always raises;
* a statement, return value, or assigned value that always raises;
* in a test function, a ``raise`` that runs on every path and nothing catches.

Constant folding sees literals, empty literals, names provably assigned once
(module, function, and tuple-unpacking bindings, annotated bindings, walrus),
ternaries, ``and`` and ``or`` with a constant side, ``not``, arithmetic,
comparisons and chains, membership in an empty container, subscripts, and the
pure builtins (``bool``, ``int``, ``len`` and the rest of ``_PURE``). A name
with a second binding of any kind (augmented, loop, handler, ``global`` or
``nonlocal`` from another scope, ``del``) is not folded, and a mutable literal
stops folding once it is passed anywhere it could change.

Skip and xfail forms:

* in a KAT file, any reference to ``pytest.mark.skip`` (decorator, class mark,
  ``pytestmark``, ``pytest.param(marks=...)``, ``add_marker``, alias,
  ``getattr``, ``with_args``, wrapper), ``unittest.skip``, ``skipIf``,
  ``skipUnless`` or ``expectedFailure``, and any imperative ``pytest.skip``,
  ``pytest.xfail``, ``pytest.importorskip``, ``self.skipTest`` or raised skip
  exception that is not under an ``if`` that is purely a platform check;
* in a KAT file, a ``skipif`` whose condition is not purely a platform check
  or a constant false;
* in every test file: ``skipif`` with no condition, or a condition that folds
  true (string conditions are parsed and folded too); a condition that mixes a
  platform check with anything else; a platform compared to a value no
  platform has; a condition taken from a function parameter (a marker
  wrapper); ``xfail(strict=...)`` that is not provably ``True``;
  ``xfail(run=False)``; ``**`` arguments to ``skipif`` or ``xfail``; an
  imperative ``pytest.xfail``; and in a test function, a forced exit or
  dynamic code.

A platform check is built only from ``sys.platform``, ``os.name``,
``platform.system()`` and the other ``platform`` calls, ``sys.version_info``,
names assigned once from those, and constants.

Reaching the real gate. A test reaches the gate when its straight-line path
(try, with, and for bodies count; if branches, except handlers, while loops,
and dead code do not), before any return or raise, calls:

* ``.evaluate`` or ``.throw`` on a gate: a ``capability_gate.Gate`` built in
  the test, a same-file pytest fixture that returns one (taken by name), a
  same-file helper that returns one, or a local name every binding of which is
  one of those. A helper's parameter is a gate only when the caller passes one;
* ``open_authorized_read``, ``_pre``, ``main`` or ``pre_tool_call`` imported
  from ``capability_gate`` or ``adapters``;
* a subprocess that runs ``adapters/claude_code_hook.py``;
* a same-file helper, or same-file fixture the test takes, that does one of
  those.

It does not count when the gate class or function comes from anywhere else (a
test helper module, conftest, a class defined or subclassed in the file,
``getattr``, ``type()``, ``importlib``), when a ``capability_gate.py`` or
``adapters`` folder sits beside the test file, when the test, its fixtures,
autouse fixtures, its helpers or the module patch the gate (``setattr`` or
``monkeypatch.setattr`` or ``mock.patch`` on a gate, the Gate class, or a gate
function, or assignment to one of their attributes), or when the call is dead:
under a constant-false branch, in a loop over an empty constant, in a
comprehension over one, in a generator expression nothing consumes, or inside
``pytest.raises``, ``contextlib.suppress`` or ``assertRaises``.

Every KAT that reaches the gate must also assert on its result: a live
``assert`` that uses a value derived from a gate call, directly, through a
name, through a flag or counter set under a branch or handler that depends on
one, through a list it was appended to, through a same-file fixture that
returns one, or through a same-file helper that asserts on the argument it is
given.

KAT files are found recursively under tests/ and among top-level test files,
case-insensitively: names like test_k*.py or containing "kat", any file with a
"# KAT" comment, and any test file that names a receipts/ path. Files named on
the command line are linted as KATs whatever their name.

Known gaps: the lint reads one file. A gate patched from conftest.py or another
module, a fixture supplied by conftest.py, a module loaded by file path, and a
condition read from the environment outside a skip mark are not judged.
Patching any attribute of a gate object or the Gate class counts as patching
the gate; fault injection anywhere else (for example
``monkeypatch.setattr(os, "lstat", ...)``, or a private helper in the
``capability_gate`` module) is allowed on purpose. A ``while`` body never
counts as reaching the gate. It proves the test asks the real gate and asserts
on the answer; it does not prove the assertion is the right one.

Exit 0 = clean. Exit 1 = violation. Exit 2 = a file did not parse.
"""

from __future__ import annotations

import argparse
import ast
import builtins
import io
import operator
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
_HOOK_SCRIPT = re.compile(r"(^|[\\/])adapters[\\/]claude_code_hook\.py$")
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
_FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)

REAL_GATE = "capability_gate.Gate"
REAL_ROOTS = {"capability_gate", "adapters"}
GATE_FUNCS = {"open_authorized_read", "_pre", "main", "pre_tool_call"}
GATE_METHODS = {"evaluate", "throw"}
GATE_ATTRS = GATE_METHODS | GATE_FUNCS | {"Gate"}

EXIT_CALLS = {
    "sys.exit",
    "os._exit",
    "os.abort",
    "os.kill",
    "signal.raise_signal",
    "builtins.exit",
    "builtins.quit",
}
DYNAMIC_CALLS = {
    "builtins.eval",
    "builtins.exec",
    "builtins.compile",
    "runpy.run_path",
    "runpy.run_module",
}
WATCHED = {
    "pytest",
    "_pytest",
    "sys",
    "os",
    "builtins",
    "importlib",
    "runpy",
    "unittest",
    "signal",
}
SKIP_CALLS = ("pytest.skip", "pytest.xfail", "pytest.importorskip", "unittest.SkipTest")
UNITTEST_MARKS = {
    "unittest.skip",
    "unittest.skipIf",
    "unittest.skipUnless",
    "unittest.expectedFailure",
}
EXPECTED_EXCEPTION = {"pytest.raises", "contextlib.suppress"}
SUBPROCESS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
}
_OUTCOME_ALIASES = {
    "_pytest.outcomes.fail": "pytest.fail",
    "_pytest.outcomes.exit": "pytest.exit",
    "_pytest.outcomes.skip": "pytest.skip",
    "_pytest.outcomes.xfail": "pytest.xfail",
    "_pytest.outcomes.importorskip": "pytest.importorskip",
    "_pytest.outcomes.Failed": "pytest.fail.Exception",
    "_pytest.outcomes.OutcomeException": "pytest.fail.Exception",
    "_pytest.outcomes.Skipped": "pytest.skip.Exception",
    "_pytest.outcomes.XFailed": "pytest.xfail.Exception",
    "_pytest.outcomes.Exit": "pytest.exit.Exception",
    "unittest.case.SkipTest": "unittest.SkipTest",
    "unittest.case.skip": "unittest.skip",
    "unittest.case.skipIf": "unittest.skipIf",
    "unittest.case.skipUnless": "unittest.skipUnless",
    "unittest.case.expectedFailure": "unittest.expectedFailure",
}
_PLATFORM_ATTRS = {"sys.platform", "os.name", "sys.version_info"}
_PLATFORM_VALUES = {
    "sys.platform": {
        "win32",
        "cygwin",
        "msys",
        "linux",
        "darwin",
        "aix",
        "freebsd",
        "openbsd",
        "netbsd",
        "sunos5",
        "emscripten",
        "wasi",
        "ios",
        "android",
    },
    "os.name": {"posix", "nt", "java"},
    "platform.system": {
        "Windows",
        "Linux",
        "Darwin",
        "Java",
        "FreeBSD",
        "OpenBSD",
        "AIX",
    },
}
_PURE = {
    "bool": bool,
    "int": int,
    "float": float,
    "str": str,
    "len": len,
    "abs": abs,
    "tuple": tuple,
    "list": list,
    "set": set,
    "frozenset": frozenset,
    "dict": dict,
    "min": min,
    "max": max,
    "sum": sum,
    "any": any,
    "all": all,
    "sorted": sorted,
    "repr": repr,
    "ord": ord,
    "chr": chr,
    "round": round,
}
_BUILTIN_NAMES = set(dir(builtins))
_BINOPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.LShift: operator.lshift,
    ast.RShift: operator.rshift,
    ast.BitOr: operator.or_,
    ast.BitXor: operator.xor,
    ast.BitAnd: operator.and_,
}
_CMPOPS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
}
_LIMIT = 10_000


# --------------------------------------------------------------------- discovery


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


# ----------------------------------------------------------------------- folding


class _Opaque:
    """A value whose truth is known and nothing else."""

    def __init__(self, truth: bool) -> None:
        self.truth = truth

    def __bool__(self) -> bool:
        return self.truth


UNKNOWN = ("unknown", None)
RAISES = ("raises", None)


def _known(v: object) -> tuple[str, object]:
    return ("value", v)


def _size_ok(v: object) -> bool:
    try:
        return not hasattr(v, "__len__") or len(v) <= _LIMIT  # type: ignore[arg-type]
    except Exception:
        return False


def _mutable(v: object) -> bool:
    if isinstance(v, (list, dict, set, bytearray)):
        return True
    if isinstance(v, (tuple, frozenset)):
        return any(_mutable(x) for x in v)
    return False


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}


def _scope_nodes(scope: ast.AST):
    """Nodes in scope, not inside nested functions, lambdas or classes."""
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        n = stack.pop()
        yield n
        if isinstance(n, _SCOPES):
            continue
        stack.extend(ast.iter_child_nodes(n))


def _target_pairs(target: ast.expr, value: ast.expr | None):
    """(name, value or None) for every name an assignment target binds."""
    if isinstance(target, ast.Name):
        yield target.id, value
    elif isinstance(target, (ast.Tuple, ast.List)):
        vals = None
        if isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(
            target.elts
        ):
            if not any(isinstance(e, ast.Starred) for e in value.elts):
                vals = value.elts
        for i, t in enumerate(target.elts):
            yield from _target_pairs(t, vals[i] if vals else None)
    elif isinstance(target, ast.Starred):
        yield from _target_pairs(target.value, None)


def _bindings(scope: ast.AST) -> dict[str, list[ast.expr | None]]:
    """Every binding in scope: name -> value expr, or None for an opaque one."""
    out: dict[str, list[ast.expr | None]] = {}

    def add(name: str, value: ast.expr | None) -> None:
        out.setdefault(name, []).append(value)

    if isinstance(scope, (*_FUNCS, ast.Lambda)):
        a = scope.args
        for arg in (*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg):
            if arg is not None:
                add(arg.arg, None)
    for n in _scope_nodes(scope):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                for name, v in _target_pairs(t, n.value):
                    add(name, v)
        elif isinstance(n, ast.AnnAssign) and n.value is not None:
            for name, v in _target_pairs(n.target, n.value):
                add(name, v)
        elif isinstance(n, ast.NamedExpr):
            add(n.target.id, n.value)
        elif isinstance(n, ast.AugAssign):
            for name, _ in _target_pairs(n.target, None):
                add(name, None)
        elif isinstance(n, (ast.For, ast.AsyncFor)):
            for name, _ in _target_pairs(n.target, None):
                add(name, None)
        elif isinstance(n, ast.withitem) and n.optional_vars is not None:
            for name, _ in _target_pairs(n.optional_vars, None):
                add(name, None)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            add(n.name, None)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for a in n.names:
                add((a.asname or a.name).split(".", 1)[0], None)
        elif isinstance(n, (*_FUNCS, ast.ClassDef)):
            add(n.name, None)
        elif isinstance(n, ast.Delete):
            for t in n.targets:
                for name, _ in _target_pairs(t, None):
                    add(name, None)
        elif isinstance(n, (ast.MatchAs, ast.MatchStar)) and n.name:
            add(n.name, None)
        elif isinstance(n, ast.MatchMapping) and n.rest:
            add(n.rest, None)
    return out


_READ_PARENTS = (
    ast.Compare,
    ast.BoolOp,
    ast.UnaryOp,
    ast.Assert,
    ast.If,
    ast.IfExp,
    ast.While,
)


class Folder:
    """Constant folding with per-scope environments of names bound once."""

    def __init__(self, tree: ast.Module) -> None:
        self.tree = tree
        self.parents = _parents(tree)
        self.file_bound = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                self.file_bound.add(n.id)
            elif isinstance(n, (*_FUNCS, ast.ClassDef)):
                self.file_bound.add(n.name)
            elif isinstance(n, (ast.Import, ast.ImportFrom)):
                for a in n.names:
                    self.file_bound.add((a.asname or a.name).split(".", 1)[0])
            elif isinstance(n, ast.arg):
                self.file_bound.add(n.arg)
        # A name declared global or nonlocal anywhere can change behind a scope.
        self.shared = {
            name
            for n in ast.walk(tree)
            if isinstance(n, (ast.Global, ast.Nonlocal))
            for name in n.names
        }
        self._envs: dict[ast.AST, dict[str, object]] = {}

    def scope_of(self, node: ast.AST) -> ast.AST:
        """The function whose body holds node. Decorators and defaults run outside."""
        child = node
        while child in self.parents:
            p = self.parents[child]
            if isinstance(p, (*_FUNCS, ast.Lambda)):
                body = p.body if isinstance(p.body, list) else [p.body]
                if child in body:
                    return p
            child = p
        return self.tree

    def env(self, scope: ast.AST) -> dict[str, object]:
        if scope in self._envs:
            return self._envs[scope]
        self._envs[scope] = {}
        outer: dict[str, object] = {}
        if scope is not self.tree:
            outer = dict(self.env(self.scope_of(scope)))
        binds = _bindings(scope)
        for name in binds:
            outer.pop(name, None)
        env = dict(outer)
        pending = {
            name: vals[0]
            for name, vals in binds.items()
            if len(vals) == 1 and vals[0] is not None and name not in self.shared
        }
        changed = True
        while changed:
            changed = False
            for name, value in list(pending.items()):
                kind, v = self.fold(value, env)
                if kind == "value":
                    env[name] = v
                    del pending[name]
                    changed = True
        for name, v in list(env.items()):
            if _mutable(v) and self._escapes(name, scope):
                del env[name]
        self._envs[scope] = env
        return env

    def _escapes(self, name: str, scope: ast.AST) -> bool:
        """A mutable binding stops being constant once it can be changed."""
        for n in ast.walk(scope):
            if not (isinstance(n, ast.Name) and n.id == name):
                continue
            if isinstance(n.ctx, ast.Store):
                continue
            p = self.parents.get(n)
            if isinstance(p, _READ_PARENTS):
                continue
            if (
                isinstance(p, (ast.For, ast.AsyncFor, ast.comprehension))
                and p.iter is n
            ):
                continue
            if (
                isinstance(p, ast.Call)
                and n in p.args
                and isinstance(p.func, ast.Name)
                and p.func.id in _PURE
                and p.func.id not in self.file_bound
            ):
                continue
            return True
        return False

    def at(self, node: ast.AST) -> dict[str, object]:
        return self.env(self.scope_of(node))

    def fold(self, node: ast.AST | None, env: dict[str, object]) -> tuple[str, object]:
        try:
            return self._fold(node, env, 0)
        except RecursionError:
            return UNKNOWN

    def _fold(self, node, env, depth):  # noqa: C901, PLR0911, PLR0912
        if node is None or depth > 50:
            return UNKNOWN
        d = depth + 1
        if isinstance(node, ast.Constant):
            return _known(node.value)
        if isinstance(node, ast.Name):
            if node.id in env:
                return _known(env[node.id])
            return UNKNOWN
        if isinstance(node, ast.Lambda):
            return _known(_Opaque(True))
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            vals = []
            for e in node.elts:
                if isinstance(e, ast.Starred):
                    return UNKNOWN
                kind, v = self._fold(e, env, d)
                if kind == "raises":
                    return RAISES
                if kind == "unknown" or isinstance(v, _Opaque):
                    return _known(_Opaque(True))
                vals.append(v)
            try:
                made = {ast.List: list, ast.Tuple: tuple, ast.Set: set}[type(node)](
                    vals
                )
            except TypeError:
                return RAISES
            return _known(made)
        if isinstance(node, ast.Dict):
            out = {}
            for k, v in zip(node.keys, node.values, strict=True):
                if k is None:
                    return UNKNOWN
                kk, kv = self._fold(k, env, d)
                vk, vv = self._fold(v, env, d)
                if "raises" in (kk, vk):
                    return RAISES
                if kk == "unknown" or vk == "unknown" or isinstance(kv, _Opaque):
                    return _known(_Opaque(True))
                try:
                    out[kv] = vv
                except TypeError:
                    return RAISES
            return _known(out)
        if isinstance(node, ast.JoinedStr):
            literal = "".join(
                v.value for v in node.values if isinstance(v, ast.Constant)
            )
            return _known(_Opaque(True)) if literal else UNKNOWN
        if isinstance(node, ast.NamedExpr):
            return self._fold(node.value, env, d)
        if isinstance(node, ast.UnaryOp):
            kind, v = self._fold(node.operand, env, d)
            if kind != "value":
                return kind, v
            if isinstance(node.op, ast.Not):
                return _known(not v)
            if isinstance(v, _Opaque):
                return UNKNOWN
            op = {
                ast.USub: operator.neg,
                ast.UAdd: operator.pos,
                ast.Invert: operator.invert,
            }
            try:
                return _known(op[type(node.op)](v))
            except Exception:
                return RAISES
        if isinstance(node, ast.BinOp):
            lk, lv = self._fold(node.left, env, d)
            rk, rv = self._fold(node.right, env, d)
            if lk == "raises" or (lk == "value" and rk == "raises"):
                return RAISES
            if lk != "value" or rk != "value":
                return UNKNOWN
            if isinstance(lv, _Opaque) or isinstance(rv, _Opaque):
                return UNKNOWN
            if not self._binop_safe(node.op, lv, rv):
                return UNKNOWN
            try:
                out = _BINOPS[type(node.op)](lv, rv)
            except Exception:
                return RAISES
            return _known(out) if _size_ok(out) else UNKNOWN
        if isinstance(node, ast.BoolOp):
            return self._fold_boolop(node, env, d)
        if isinstance(node, ast.IfExp):
            tk, tv = self._fold(node.test, env, d)
            if tk == "raises":
                return RAISES
            if tk == "value":
                return self._fold(node.body if tv else node.orelse, env, d)
            a = self._fold(node.body, env, d)
            b = self._fold(node.orelse, env, d)
            if a[0] == "value" and b[0] == "value" and bool(a[1]) == bool(b[1]):
                return _known(_Opaque(bool(a[1])))
            return UNKNOWN
        if isinstance(node, ast.Compare):
            return self._fold_compare(node, env, d)
        if isinstance(node, ast.Call):
            return self._fold_call(node, env, d)
        if isinstance(node, ast.Subscript):
            vk, vv = self._fold(node.value, env, d)
            sk, sv = self._fold(node.slice, env, d)
            if vk == "raises" or (vk == "value" and sk == "raises"):
                return RAISES
            if vk != "value" or sk != "value":
                return UNKNOWN
            if isinstance(vv, _Opaque) or isinstance(sv, _Opaque):
                return UNKNOWN
            try:
                return _known(vv[sv])
            except Exception:
                return RAISES
        if isinstance(node, ast.Slice):
            parts = []
            for p in (node.lower, node.upper, node.step):
                if p is None:
                    parts.append(None)
                    continue
                k, v = self._fold(p, env, d)
                if k != "value" or isinstance(v, _Opaque):
                    return UNKNOWN
                parts.append(v)
            return _known(slice(*parts))
        return UNKNOWN

    @staticmethod
    def _binop_safe(op: ast.operator, lv: object, rv: object) -> bool:
        if isinstance(op, ast.Pow) and isinstance(rv, (int, float)) and abs(rv) > 256:
            return False
        if isinstance(op, (ast.LShift,)) and isinstance(rv, int) and rv > 4096:
            return False
        if isinstance(op, ast.Mult):
            for a, b in ((lv, rv), (rv, lv)):
                if isinstance(a, (str, bytes, list, tuple)) and isinstance(b, int):
                    if b * max(len(a), 1) > _LIMIT:
                        return False
        return True

    def _fold_boolop(self, node: ast.BoolOp, env, d):
        is_and = isinstance(node.op, ast.And)
        all_known = True
        last = UNKNOWN
        for v in node.values:
            kind, val = self._fold(v, env, d)
            if kind == "raises":
                if all_known:
                    return RAISES
                # An earlier unknown side may short-circuit; for `and` every
                # outcome is still falsy or raising.
                return _known(_Opaque(False)) if is_and else UNKNOWN
            if kind == "unknown":
                all_known = False
                continue
            decides = (not val) if is_and else bool(val)
            if decides:
                return _known(val) if all_known else _known(_Opaque(bool(val)))
            last = (kind, val)
        return last if all_known else UNKNOWN

    def _fold_compare(self, node: ast.Compare, env, d):
        left = self._fold(node.left, env, d)
        if left[0] == "raises":
            return RAISES
        result = True
        unknown = False
        for op, comp in zip(node.ops, node.comparators, strict=True):
            right = self._fold(comp, env, d)
            if right[0] == "raises":
                return RAISES if not unknown and left[0] == "value" else UNKNOWN
            pair = self._compare(op, left, right)
            if pair[0] == "raises":
                return RAISES if not unknown else UNKNOWN
            if pair[0] == "unknown":
                unknown = True
            elif not pair[1]:
                if not unknown:
                    return _known(False)
                return _known(_Opaque(False))
            left = right
        return UNKNOWN if unknown else _known(result)

    @staticmethod
    def _compare(op: ast.cmpop, left, right):
        lk, lv = left
        rk, rv = right
        if isinstance(op, (ast.In, ast.NotIn)) and rk == "value":
            if (
                isinstance(rv, (list, tuple, set, frozenset, dict, str, bytes))
                and not rv
            ):
                if lk != "raises" and not (
                    isinstance(rv, (str, bytes)) and lk != "value"
                ):
                    return _known(isinstance(op, ast.NotIn))
        if lk != "value" or rk != "value":
            return UNKNOWN
        if isinstance(lv, _Opaque) or isinstance(rv, _Opaque):
            return UNKNOWN
        if isinstance(op, (ast.Is, ast.IsNot)):
            singletons = (None, True, False, Ellipsis)
            if any(lv is s for s in singletons) or any(rv is s for s in singletons):
                same = lv is rv
                return _known(same if isinstance(op, ast.Is) else not same)
            return UNKNOWN
        try:
            return _known(_CMPOPS[type(op)](lv, rv))
        except Exception:
            return RAISES

    def _fold_call(self, node: ast.Call, env, d):
        f = node.func
        if not (
            isinstance(f, ast.Name) and f.id in _PURE and f.id not in self.file_bound
        ):
            return UNKNOWN
        args = []
        for a in node.args:
            kind, v = self._fold(a, env, d)
            if kind == "raises":
                return RAISES
            if kind == "unknown":
                return UNKNOWN
            if isinstance(v, _Opaque):
                if f.id == "bool" and len(node.args) == 1:
                    return _known(v.truth)
                return UNKNOWN
            args.append(v)
        if node.keywords:
            return UNKNOWN
        if f.id in ("sum", "sorted", "min", "max", "any", "all") and any(
            not _size_ok(a) for a in args
        ):
            return UNKNOWN
        try:
            out = _PURE[f.id](*args)
        except Exception:
            return RAISES
        return _known(out) if _size_ok(out) else UNKNOWN

    def truth(self, node: ast.AST, env: dict[str, object] | None = None):
        """('true'|'false'|'raises'|'unknown')."""
        kind, v = self.fold(node, self.at(node) if env is None else env)
        if kind == "value":
            return "true" if v else "false"
        return kind


# --------------------------------------------------------------------- resolving


def _canon(name: str) -> str:
    for old, new in _OUTCOME_ALIASES.items():
        if name == old or name.startswith(old + "."):
            return new + name[len(old) :]
    return name


class Names:
    """What each spelling in a file can refer to, through imports and aliases."""

    def __init__(self, tree: ast.Module, folder: Folder) -> None:
        self.folder = folder
        self.binds: dict[str, list[tuple[str, object]]] = {}
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    if a.asname:
                        self._add(a.asname, ("import", a.name))
                    else:
                        root = a.name.split(".", 1)[0]
                        self._add(root, ("import", root))
            elif isinstance(n, ast.ImportFrom):
                mod = ("." * n.level) + (n.module or "")
                for a in n.names:
                    self._add(a.asname or a.name, ("import", f"{mod}.{a.name}"))
            elif isinstance(n, ast.Assign):
                for t in n.targets:
                    for name, v in _target_pairs(t, n.value):
                        self._add(
                            name, ("value", v) if v is not None else ("other", None)
                        )
            elif isinstance(n, ast.AnnAssign) and n.value is not None:
                for name, v in _target_pairs(n.target, n.value):
                    self._add(name, ("value", v) if v is not None else ("other", None))
            elif isinstance(n, ast.NamedExpr):
                self._add(n.target.id, ("value", n.value))
            elif isinstance(n, (*_FUNCS, ast.ClassDef)):
                self._add(n.name, ("local", n.name))
            elif isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                p = folder.parents.get(n)
                if not isinstance(p, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                    self._add(n.id, ("other", None))
            elif isinstance(n, ast.arg):
                self._add(n.arg, ("other", None))

    def _add(self, name: str, entry: tuple[str, object]) -> None:
        self.binds.setdefault(name, []).append(entry)

    def resolve(
        self, node: ast.AST, dynamic: bool = True, depth: int = 0
    ) -> set[str | None]:
        """Canonical dotted names node can be. None = something else."""
        if depth > 25:
            return {None}
        out = {_canon(r) if r else r for r in self._resolve(node, dynamic, depth + 1)}
        return out or {None}

    def _resolve(self, node, dynamic, depth):  # noqa: C901, PLR0911, PLR0912
        if isinstance(node, ast.Name):
            if node.id not in self.binds:
                if node.id == "__builtins__":
                    return {"builtins"}
                if node.id in _BUILTIN_NAMES:
                    return {f"builtins.{node.id}"}
                return {None}
            out: set[str | None] = set()
            for kind, val in self.binds[node.id]:
                if kind == "import":
                    out.add(val)
                elif kind == "value":
                    out |= self.resolve(val, dynamic, depth)
                elif kind == "local":
                    out.add(f"<local>.{val}")
                else:
                    out.add(None)
            return out
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value, dynamic, depth)
            return {f"{b}.{node.attr}" if b else None for b in base}
        if not dynamic:
            return {None}
        if isinstance(node, ast.Subscript):
            return self._resolve_subscript(node, depth)
        if isinstance(node, ast.Call):
            return self._resolve_call(node, depth)
        return {None}

    def _const_str(self, node: ast.AST) -> str | None:
        kind, v = self.folder.fold(node, self.folder.at(node))
        return v if kind == "value" and isinstance(v, str) else None

    def _resolve_subscript(self, node: ast.Subscript, depth: int) -> set[str | None]:
        v = node.value
        if isinstance(v, (ast.List, ast.Tuple)):
            kind, idx = self.folder.fold(node.slice, self.folder.at(node))
            if (
                kind == "value"
                and isinstance(idx, int)
                and -len(v.elts) <= idx < len(v.elts)
            ):
                return self.resolve(v.elts[idx], True, depth)
            return {None}
        key = self._const_str(node.slice)
        bases: set[str | None] = {None}
        if isinstance(v, ast.Attribute) and v.attr == "__dict__":
            bases = self.resolve(v.value, True, depth)
        elif isinstance(v, ast.Call):
            fn = self.resolve(v.func, True, depth)
            if "builtins.vars" in fn and v.args:
                bases = self.resolve(v.args[0], True, depth)
            elif fn & {"builtins.globals", "builtins.locals"}:
                if key is not None:
                    return self.resolve(ast.Name(id=key, ctx=ast.Load()), True, depth)
                return {"<dynamic-attr>"}
        else:
            bases = {b for b in self.resolve(v, True, depth) if b == "builtins"} or {
                None
            }
        if key is None:
            return (
                {"<dynamic-attr>"}
                if any(b and b.split(".")[0] in WATCHED for b in bases)
                else {None}
            )
        return {f"{b}.{key}" if b else None for b in bases}

    def _resolve_call(self, node: ast.Call, depth: int) -> set[str | None]:
        fn = self.resolve(node.func, True, depth)
        if "builtins.getattr" in fn and len(node.args) >= 2:
            bases = self.resolve(node.args[0], True, depth)
            key = self._const_str(node.args[1])
            if key is None:
                if any(b and b.split(".")[0] in WATCHED for b in bases):
                    return {"<dynamic-attr>"}
                return {None}
            return {f"{b}.{key}" if b else None for b in bases}
        if fn & {"builtins.__import__", "importlib.import_module"} and node.args:
            key = self._const_str(node.args[0])
            if key is None:
                return {"<dynamic-import>"}
            if "builtins.__import__" in fn and not (
                len(node.args) > 3 or node.keywords
            ):
                return {key.split(".", 1)[0]}
            return {key}
        return {None}

    def strictly(self, node: ast.AST) -> set[str | None]:
        return self.resolve(node, dynamic=False)


def _classify(name: str | None) -> str | None:
    """Fiat label for a referenced callable, or None."""
    if not name:
        return None
    if name == "<dynamic-attr>":
        return "dynamic attribute"
    if name == "<dynamic-import>":
        return "dynamic import"
    for prefix in ("pytest.fail", "pytest.exit"):
        if name == prefix or name.startswith(prefix + "."):
            return prefix
    if name in EXIT_CALLS:
        return "forced exit"
    if name in DYNAMIC_CALLS:
        return "dynamic code"
    return None


def _skip_kind(name: str | None) -> str | None:
    if not name:
        return None
    for prefix in SKIP_CALLS:
        if name == prefix or name.startswith(prefix + "."):
            return prefix
    return None


def _mark_kind(name: str | None) -> str | None:
    """'skip', 'skipif', 'xfail', or a unittest mark, for a marker spelling."""
    if name in UNITTEST_MARKS:
        return name
    for mark in ("skipif", "skip", "xfail"):
        full = f"pytest.mark.{mark}"
        if name == full or name == full + ".with_args":
            return mark
    return None


# ----------------------------------------------------------------- per-file view


class _File:  # noqa: PLR0904
    def __init__(self, tree: ast.Module, label: str, shadowed: bool = False) -> None:
        self.tree = tree
        self.label = label
        self.shadowed = shadowed
        self.fold = Folder(tree)
        self.names = Names(tree, self.fold)
        self.parents = self.fold.parents
        self.funcs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        for n in ast.walk(tree):
            if isinstance(n, _FUNCS):
                self.funcs.setdefault(n.name, n)
        self.fixtures = {
            name: fn for name, fn in self.funcs.items() if self._is_fixture(fn)
        }
        self.autouse = [fn for fn in self.fixtures.values() if self._autouse(fn)]
        self.makers = self._gate_makers()
        self._reach_memo: dict[tuple[str, frozenset[str]], bool] = {}
        self._result_memo: dict[str, bool] = {}

    # --- helpers

    def _is_fixture(self, fn: ast.AST) -> bool:
        for d in getattr(fn, "decorator_list", []):
            target = d.func if isinstance(d, ast.Call) else d
            if self.names.resolve(target) & {
                "pytest.fixture",
                "_pytest.fixtures.fixture",
            }:
                return True
        return False

    def _autouse(self, fn: ast.AST) -> bool:
        for d in fn.decorator_list:
            if isinstance(d, ast.Call):
                for kw in d.keywords:
                    if kw.arg == "autouse" and self.fold.truth(kw.value) != "false":
                        return True
        return False

    def owner(self, node: ast.AST) -> ast.AST | None:
        """Nearest enclosing function or class, or None at module level."""
        while node in self.parents:
            node = self.parents[node]
            if isinstance(node, (*_FUNCS, ast.ClassDef)):
                return node
        return None

    def in_test(self, node: ast.AST) -> bool:
        o = self.owner(node)
        return isinstance(o, _FUNCS) and o.name.startswith("test")

    def expected_exception(self, item: ast.withitem) -> bool:
        e = item.context_expr
        if not isinstance(e, ast.Call):
            return False
        if self.names.resolve(e.func) & EXPECTED_EXCEPTION:
            return True
        return isinstance(e.func, ast.Attribute) and e.func.attr.startswith(
            "assertRaises"
        )

    def under_expected_exception(self, node: ast.AST) -> bool:
        child = node
        while child in self.parents:
            p = self.parents[child]
            if isinstance(p, _SCOPES):
                return False
            if isinstance(p, (ast.With, ast.AsyncWith)) and child in p.body:
                if any(self.expected_exception(i) for i in p.items):
                    return True
            child = p
        return False

    # --- gates

    def real_gate_class(self, node: ast.AST) -> bool:
        return not self.shadowed and self.names.strictly(node) == {REAL_GATE}

    def real_gate_func(self, node: ast.AST) -> bool:
        if self.shadowed:
            return False
        names = self.names.strictly(node)
        return bool(names) and all(
            n
            and n.split(".", 1)[0] in REAL_ROOTS
            and n.rsplit(".", 1)[-1] in GATE_FUNCS
            for n in names
        )

    def makes_gate(self, expr: ast.AST | None, typed: set[str]) -> bool:
        if isinstance(expr, ast.Name):
            return expr.id in typed
        if isinstance(expr, ast.Call):
            if self.real_gate_class(expr.func):
                return True
            return isinstance(expr.func, ast.Name) and expr.func.id in self.makers
        return False

    def _gate_makers(self) -> set[str]:
        self.makers: set[str] = set()
        changed = True
        while changed:
            changed = False
            for name, fn in self.funcs.items():
                if name in self.makers:
                    continue
                typed = self.typed_names(fn, self.auto_params(fn))
                for n in _scope_nodes(fn):
                    if isinstance(n, (ast.Return, ast.Yield)) and self.makes_gate(
                        n.value, typed
                    ):
                        self.makers.add(name)
                        changed = True
                        break
        return self.makers

    def auto_params(self, fn: ast.AST) -> frozenset[str]:
        """Parameters pytest fills with a same-file gate fixture."""
        if not (self._is_fixture(fn) or fn.name.startswith("test")):
            return frozenset()
        return frozenset(
            a.arg
            for a in fn.args.args
            if a.arg in self.fixtures and a.arg in getattr(self, "makers", set())
        )

    def typed_names(self, fn: ast.AST, params: frozenset[str]) -> set[str]:
        """Names in fn that hold the real gate: every binding is a gate."""
        typed = set(params)
        binds = _bindings(fn)
        changed = True
        while changed:
            changed = False
            for name, vals in binds.items():
                if name in typed or name in params:
                    continue
                if vals and all(
                    v is not None and self.makes_gate(v, typed) for v in vals
                ):
                    typed.add(name)
                    changed = True
        return typed

    def is_gate(self, expr: ast.AST, typed: set[str]) -> bool:
        return self.makes_gate(expr, typed)

    def gate_call(self, call: ast.Call, typed: set[str]) -> bool:
        f = call.func
        if isinstance(f, ast.Attribute) and f.attr in GATE_METHODS:
            if self.is_gate(f.value, typed):
                return True
        if self.real_gate_func(f):
            return True
        return self.runs_hook_script(call)

    def runs_hook_script(self, call: ast.Call) -> bool:
        if not (self.names.resolve(call.func) & SUBPROCESS):
            return False
        consts = [
            c.value
            for c in ast.walk(call)
            if isinstance(c, ast.Constant) and isinstance(c.value, str)
        ]
        if any(_HOOK_SCRIPT.search(c) for c in consts):
            return True
        return "adapters" in consts and "claude_code_hook.py" in consts

    # --- liveness

    def empty_iter(self, node: ast.AST) -> bool:
        _kind, v = self.fold.fold(node, self.fold.at(node))
        try:
            return len(v) == 0  # type: ignore[arg-type]
        except TypeError:
            return False

    def live_calls(self, node: ast.AST) -> list[ast.Call]:
        """Calls under node that can run: no nested scopes, no dead branches."""
        out = []
        stack = [node]
        while stack:
            n = stack.pop()
            if isinstance(n, _SCOPES):
                continue
            if isinstance(n, ast.Call):
                out.append(n)
                stack.append(n.func)
                for a in (*n.args, *(k.value for k in n.keywords)):
                    # A generator handed straight to a call is consumed by it.
                    if isinstance(a, ast.GeneratorExp):
                        stack.extend(self._comp_parts(a))
                    else:
                        stack.append(a)
                continue
            if isinstance(n, ast.GeneratorExp):
                stack.append(n.generators[0].iter)
                continue
            if isinstance(n, (ast.ListComp, ast.SetComp, ast.DictComp)):
                stack.extend(self._comp_parts(n))
                continue
            if isinstance(n, ast.IfExp):
                t = self.fold.truth(n.test)
                stack.append(n.test)
                if t == "true":
                    stack.append(n.body)
                elif t == "false":
                    stack.append(n.orelse)
                elif t == "unknown":
                    stack.extend((n.body, n.orelse))
                continue
            if isinstance(n, ast.BoolOp):
                for v in n.values:
                    stack.append(v)
                    t = self.fold.truth(v)
                    if t == "raises" or t == (
                        "true" if isinstance(n.op, ast.Or) else "false"
                    ):
                        break
                continue
            stack.extend(ast.iter_child_nodes(n))
        return out

    def _comp_parts(self, comp: ast.AST) -> list[ast.AST]:
        first = comp.generators[0]
        if self.empty_iter(first.iter):
            return [first.iter]
        parts: list[ast.AST] = [first.iter]
        for g in comp.generators[1:]:
            parts.append(g.iter)
        for g in comp.generators:
            parts.extend(g.ifs)
        if isinstance(comp, ast.DictComp):
            parts += [comp.key, comp.value]
        else:
            parts.append(comp.elt)
        return parts

    def live_stmts(self, stmts: list[ast.stmt]):
        """Statements that can run, in order, stopping after return or raise."""
        for s in stmts:
            yield s
            if isinstance(s, ast.If):
                t = self.fold.truth(s.test)
                if t == "true":
                    yield from self.live_stmts(s.body)
                elif t == "false":
                    yield from self.live_stmts(s.orelse)
                elif t == "unknown":
                    yield from self.live_stmts(s.body)
                    yield from self.live_stmts(s.orelse)
            elif isinstance(s, (ast.For, ast.AsyncFor)):
                if not self.empty_iter(s.iter):
                    yield from self.live_stmts(s.body)
                yield from self.live_stmts(s.orelse)
            elif isinstance(s, ast.While):
                if self.fold.truth(s.test) != "false":
                    yield from self.live_stmts(s.body)
                yield from self.live_stmts(s.orelse)
            elif isinstance(s, (ast.With, ast.AsyncWith)):
                if not any(self.expected_exception(i) for i in s.items):
                    yield from self.live_stmts(s.body)
            elif isinstance(s, ast.Try) or type(s).__name__ == "TryStar":
                yield from self.live_stmts(s.body)
                for h in s.handlers:
                    yield from self.live_stmts(h.body)
                yield from self.live_stmts(s.orelse)
                yield from self.live_stmts(s.finalbody)
            elif isinstance(s, ast.Match):
                for c in s.cases:
                    yield from self.live_stmts(c.body)
            if isinstance(s, (ast.Return, ast.Raise)):
                return

    @staticmethod
    def stmt_exprs(s: ast.stmt) -> list[ast.AST]:
        """The expressions a statement evaluates itself, not its nested body."""
        if isinstance(s, (ast.If, ast.While)):
            return [s.test]
        if isinstance(s, (ast.For, ast.AsyncFor)):
            return [s.iter]
        if isinstance(s, (ast.With, ast.AsyncWith)):
            return [i.context_expr for i in s.items]
        if isinstance(s, ast.Try) or type(s).__name__ == "TryStar":
            return []
        if isinstance(s, ast.Match):
            return [s.subject]
        return [s]

    # --- reaching the gate

    def call_reaches(
        self, call: ast.Call, typed: set[str], seen: frozenset[str]
    ) -> bool:
        if self.gate_call(call, typed):
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
        if name not in self.funcs or name in seen:
            return False
        if self.names.strictly(callee) != {f"<local>.{name}"} and not (
            isinstance(callee, ast.Attribute)
        ):
            return False
        fn = self.funcs[name]
        params = self.gate_params(fn, call, typed)
        return self.reaches(name, params, seen | {name})

    def gate_params(self, fn, call: ast.Call, typed: set[str]) -> frozenset[str]:
        """Parameters of fn that receive a gate at this call."""
        names = [a.arg for a in (*fn.args.posonlyargs, *fn.args.args)]
        if (
            names
            and names[0] in ("self", "cls")
            and isinstance(call.func, ast.Attribute)
        ):
            names = names[1:]
        out = set()
        for i, a in enumerate(call.args):
            if i < len(names) and self.is_gate(a, typed):
                out.add(names[i])
        for kw in call.keywords:
            if kw.arg and self.is_gate(kw.value, typed):
                out.add(kw.arg)
        return frozenset(out)

    def reaches(self, name: str, params: frozenset[str], seen: frozenset[str]) -> bool:
        key = (name, params)
        if key not in self._reach_memo:
            self._reach_memo[key] = False
            fn = self.funcs[name]
            hit = self.fixture_reach(fn, seen)
            if not hit:
                hit, _ = self.first_reach_in(fn, params | self.auto_params(fn), seen)
            self._reach_memo[key] = hit
        return self._reach_memo[key]

    def fixture_reach(self, fn, seen: frozenset[str]) -> bool:
        if not (self._is_fixture(fn) or fn.name.startswith("test")):
            return False
        return any(
            a.arg in self.fixtures
            and a.arg not in seen
            and self.reaches(
                a.arg, self.auto_params(self.fixtures[a.arg]), seen | {a.arg}
            )
            for a in fn.args.args
        )

    def first_reach_in(self, fn, params: frozenset[str], seen: frozenset[str]):
        typed = self.typed_names(fn, params)
        return self.first_reach(fn.body, typed, seen)

    def first_reach(self, stmts, typed, seen) -> tuple[bool, ast.stmt | None]:
        """(gate reached, the return/raise that ended the path first, if any)."""
        for s in stmts:
            if isinstance(s, ast.If):
                t = self.fold.truth(s.test)
                if t in ("true", "false"):
                    hit, end = self.first_reach(
                        s.body if t == "true" else s.orelse, typed, seen
                    )
                    if hit or end:
                        return hit, end
                    continue
                if any(
                    self.call_reaches(c, typed, seen) for c in self.live_calls(s.test)
                ):
                    return True, None
                continue
            if isinstance(s, ast.Try) or type(s).__name__ == "TryStar":
                hit, end = self.first_reach(s.body, typed, seen)
                if hit or end:
                    return hit, end
                continue
            if isinstance(s, (ast.With, ast.AsyncWith)):
                if any(self.expected_exception(i) for i in s.items):
                    continue
                heads = [i.context_expr for i in s.items]
                if any(
                    self.call_reaches(c, typed, seen)
                    for h in heads
                    for c in self.live_calls(h)
                ):
                    return True, None
                hit, end = self.first_reach(s.body, typed, seen)
                if hit or end:
                    return hit, end
                continue
            if isinstance(s, (ast.For, ast.AsyncFor)):
                if any(
                    self.call_reaches(c, typed, seen) for c in self.live_calls(s.iter)
                ):
                    return True, None
                if self.empty_iter(s.iter):
                    continue
                hit, end = self.first_reach(s.body, typed, seen)
                if hit or end:
                    return hit, end
                continue
            if isinstance(s, (ast.While, ast.Match)):
                # The test or subject runs once; the body may not.
                head = s.test if isinstance(s, ast.While) else s.subject
                if any(
                    self.call_reaches(c, typed, seen) for c in self.live_calls(head)
                ):
                    return True, None
                continue
            if any(self.call_reaches(c, typed, seen) for c in self.live_calls(s)):
                return True, None
            if isinstance(s, (ast.Return, ast.Raise)):
                return False, s
        return False, None

    def test_reaches(self, fn) -> tuple[bool, ast.stmt | None]:
        seen = frozenset({fn.name})
        if self.fixture_reach(fn, seen):
            return True, None
        return self.first_reach_in(fn, self.auto_params(fn), seen)

    # --- patching the gate

    def closure(self, fn) -> list[ast.AST]:
        """The test, its fixtures (taken and autouse), and same-file helpers it calls."""
        out: list[ast.AST] = []
        todo = [fn, *self.autouse]
        seen: set[str] = set()
        while todo:
            f = todo.pop()
            if f.name in seen:
                continue
            seen.add(f.name)
            out.append(f)
            for a in f.args.args:
                if a.arg in self.fixtures:
                    todo.append(self.fixtures[a.arg])
            for n in ast.walk(f):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
                    if n.func.id in self.funcs:
                        todo.append(self.funcs[n.func.id])
        return out

    def gate_target(self, expr: ast.AST, typed: set[str]) -> bool:
        return self.is_gate(expr, typed) or self.real_gate_class(expr)

    def real_module(self, expr: ast.AST) -> bool:
        return any(
            n and n.split(".", 1)[0] in REAL_ROOTS for n in self.names.resolve(expr)
        )

    def patch_at(self, node: ast.AST, typed: set[str]) -> bool:  # noqa: PLR0911
        if isinstance(node, ast.Call):
            f = node.func
            spelled = ast.unparse(f)
            resolved = {n or "" for n in self.names.resolve(f)}
            setter = (
                isinstance(f, ast.Attribute) and f.attr in ("setattr", "delattr")
            ) or resolved & {"builtins.setattr", "builtins.delattr"}
            patcher = any(
                r.endswith(("mock.patch", "mock.patch.object", "mock.patch.multiple"))
                for r in resolved
            ) or spelled.endswith(("patch", "patch.object", "patch.multiple"))
            if not (setter or patcher) or not node.args:
                return False
            target = node.args[0]
            if isinstance(target, ast.Constant) and isinstance(target.value, str):
                parts = target.value.split(".")
                return parts[0] in REAL_ROOTS and bool(set(parts[1:]) & GATE_ATTRS)
            if self.gate_target(target, typed):
                return True
            if self.real_module(target) and len(node.args) > 1:
                attr = node.args[1]
                if isinstance(attr, ast.Constant):
                    return attr.value in GATE_ATTRS
                return True
            return False
        if isinstance(node, (ast.Assign, ast.Delete)):
            for t in node.targets:
                for a in ast.walk(t):
                    if isinstance(a, ast.Attribute) and isinstance(
                        a.ctx, (ast.Store, ast.Del)
                    ):
                        if self.gate_target(a.value, typed):
                            return True
                        if self.real_module(a.value) and a.attr in GATE_ATTRS:
                            return True
        return False

    def patched(self, fn) -> int | None:
        """Line where the test's world patches the gate, if it does."""
        module_level = [
            n
            for s in self.tree.body
            if not isinstance(s, (*_FUNCS, ast.ClassDef))
            for n in ast.walk(s)
        ]
        for n in module_level:
            if self.patch_at(n, set()):
                return n.lineno
        for f in self.closure(fn):
            typed = self.typed_names(
                f,
                self.auto_params(f)
                | frozenset(a.arg for a in f.args.args if a.arg in self.makers),
            )
            for n in ast.walk(f):
                if self.patch_at(n, typed):
                    return n.lineno
        return None

    # --- asserting on the result

    def returns_result(self, fixture) -> bool:
        if fixture.name in self._result_memo:
            return self._result_memo[fixture.name]
        self._result_memo[fixture.name] = False
        typed = self.typed_names(fixture, self.auto_params(fixture))
        results = self.result_names(fixture, typed, self.result_params(fixture))
        hit = any(
            isinstance(n, (ast.Return, ast.Yield))
            and n.value is not None
            and self.uses_result(n.value, typed, results)
            for n in _scope_nodes(fixture)
        )
        self._result_memo[fixture.name] = hit
        return hit

    def result_params(self, fn) -> set[str]:
        return {
            a.arg
            for a in fn.args.args
            if a.arg in self.fixtures and self.returns_result(self.fixtures[a.arg])
        }

    def uses_result(self, expr: ast.AST, typed: set[str], results: set[str]) -> bool:
        if isinstance(expr, _SCOPES):
            return False
        for n in [expr, *_scope_nodes(expr)]:
            if (
                isinstance(n, ast.Name)
                and n.id in results
                and isinstance(n.ctx, ast.Load)
            ):
                return True
        return any(
            self.call_reaches(c, typed, frozenset()) for c in self.live_calls(expr)
        )

    def result_names(self, fn, typed: set[str], seed: set[str]) -> set[str]:
        results = set(seed)
        changed = True
        while changed:
            changed = False
            for s in self.live_stmts(fn.body):
                for name in self._result_binds(s, typed, results):
                    if name not in results:
                        results.add(name)
                        changed = True
        return results

    def _result_binds(self, s: ast.stmt, typed, results) -> set[str]:
        out: set[str] = set()
        uses = lambda e: self.uses_result(e, typed, results)  # noqa: E731
        for n in ast.walk(s) if not isinstance(s, (*_FUNCS, ast.ClassDef)) else []:
            if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
                value = n.value
                if value is not None and uses(value):
                    targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                    for t in targets:
                        out |= {name for name, _ in _target_pairs(t, None)}
            elif isinstance(n, (ast.For, ast.AsyncFor)) and uses(n.iter):
                out |= {name for name, _ in _target_pairs(n.target, None)}
                out |= self._bound_in(n.body)
            elif isinstance(n, ast.withitem) and n.optional_vars is not None:
                if uses(n.context_expr):
                    out |= {name for name, _ in _target_pairs(n.optional_vars, None)}
            elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                if isinstance(n.func.value, ast.Name) and any(
                    uses(a) for a in (*n.args, *(k.value for k in n.keywords))
                ):
                    out.add(n.func.value.id)
            if isinstance(n, ast.If) and uses(n.test):
                out |= self._bound_in(n.body) | self._bound_in(n.orelse)
            if isinstance(n, ast.Match) and uses(n.subject):
                for case in n.cases:
                    out |= self._bound_in(case.body)
            if isinstance(n, ast.Try) or type(n).__name__ == "TryStar":
                if any(
                    uses(x)
                    for b in n.body
                    for x in ast.walk(b)
                    if isinstance(x, ast.expr)
                ):
                    for h in n.handlers:
                        out |= self._bound_in(h.body)
                    out |= self._bound_in(n.orelse)
        return out

    @staticmethod
    def _bound_in(stmts: list[ast.stmt]) -> set[str]:
        out: set[str] = set()
        for s in stmts:
            for n in ast.walk(s):
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                    out.add(n.id)
        return out

    def asserts_result(
        self, fn, params: frozenset[str], seed: set[str], seen: frozenset[str]
    ) -> bool:
        typed = self.typed_names(fn, params)
        results = self.result_names(fn, typed, seed)
        for s in self.live_stmts(fn.body):
            if isinstance(s, ast.Assert):
                if self.uses_result(s.test, typed, results):
                    return True
            for e in self.stmt_exprs(s):
                for c in self.live_calls(e):
                    if not isinstance(c.func, ast.Name) or c.func.id not in self.funcs:
                        continue
                    g = self.funcs[c.func.id]
                    if g.name in seen or self.names.strictly(c.func) != {
                        f"<local>.{g.name}"
                    }:
                        continue
                    names = [a.arg for a in (*g.args.posonlyargs, *g.args.args)]
                    passed = {
                        names[i]
                        for i, a in enumerate(c.args)
                        if i < len(names)
                        and not isinstance(a, ast.Starred)
                        and self.uses_result(a, typed, results)
                    } | {
                        k.arg
                        for k in c.keywords
                        if k.arg and self.uses_result(k.value, typed, results)
                    }
                    gp = self.gate_params(g, c, typed)
                    if self.asserts_result(g, gp, passed, seen | {g.name}):
                        return True
        return False


# ------------------------------------------------------------------------- rules


def _report(problems: list[str], label: str, line: int, text: str) -> None:
    msg = f"{label}:{line}: {text}"
    if msg not in problems:
        problems.append(msg)


def _platform_atom(f: _File, node: ast.AST) -> str | None:
    names = f.names.resolve(node)
    for n in names:
        if n in _PLATFORM_ATTRS:
            return n
    if isinstance(node, ast.Call) and not node.args:
        for n in f.names.resolve(node.func):
            if n and n.startswith("platform."):
                return n
    return None


def _platform_kind(f: _File, node: ast.AST, depth: int = 0) -> str:
    """'pure' (platform only), 'const' (no platform, constant), or 'mixed'."""
    if depth > 20:
        return "mixed"
    d = depth + 1
    if _platform_atom(f, node):
        return "pure"
    if isinstance(node, ast.Constant):
        return "const"
    if isinstance(node, ast.Name):
        vals = f.names.binds.get(node.id, [])
        if len(vals) == 1 and vals[0][0] == "value":
            return _platform_kind(f, vals[0][1], d)
        return "mixed"
    if isinstance(node, ast.UnaryOp):
        return _platform_kind(f, node.operand, d)
    if isinstance(node, ast.BoolOp):
        kinds = {_platform_kind(f, v, d) for v in node.values}
    elif isinstance(node, ast.Compare):
        kinds = {_platform_kind(f, v, d) for v in (node.left, *node.comparators)}
    elif isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        kinds = {_platform_kind(f, v, d) for v in node.elts}
    elif isinstance(node, ast.Subscript):
        kinds = {_platform_kind(f, node.value, d), _platform_kind(f, node.slice, d)}
    elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        kinds = {_platform_kind(f, node.func.value, d)} | {
            _platform_kind(f, a, d) for a in node.args
        }
    else:
        return "mixed"
    if "mixed" in kinds:
        return "mixed"
    return "pure" if "pure" in kinds else "const"


def _impossible_platform(f: _File, node: ast.AST) -> bool:
    """A platform compared to a value no platform has."""
    for n in ast.walk(node):
        if not isinstance(n, ast.Compare):
            continue
        sides = [n.left, *n.comparators]
        for i, op in enumerate(n.ops):
            for a, b in ((sides[i], sides[i + 1]), (sides[i + 1], sides[i])):
                atom = _platform_atom(f, a)
                known = _PLATFORM_VALUES.get(atom)
                if known is None:
                    continue
                kind, v = f.fold.fold(b, f.fold.at(b))
                vals = v if isinstance(op, (ast.In, ast.NotIn)) else [v]
                if isinstance(vals, (list, tuple, set, frozenset)):
                    if any(isinstance(x, str) and x not in known for x in vals):
                        return True
    for c in ast.walk(node):
        if (
            isinstance(c, ast.Call)
            and isinstance(c.func, ast.Attribute)
            and c.func.attr == "startswith"
            and _platform_atom(f, c.func.value) == "sys.platform"
            and c.args
        ):
            kind, v = f.fold.fold(c.args[0], f.fold.at(c))
            prefixes = v if isinstance(v, tuple) else (v,)
            if kind == "value" and all(isinstance(p, str) for p in prefixes):
                if not any(
                    k.startswith(p)
                    for p in prefixes
                    for k in _PLATFORM_VALUES["sys.platform"]
                ):
                    return True
    return False


def _condition(f: _File, node: ast.AST) -> ast.AST | None:
    """A skipif or xfail condition, parsing a string condition as pytest does."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        try:
            return ast.parse(node.value, mode="eval").body
        except SyntaxError:
            return None
    return node


def _check_condition(
    f: _File, problems, label, call: ast.Call, cond: ast.AST, mark: str, kat: bool
) -> None:
    line = call.lineno
    parsed = _condition(f, cond)
    if parsed is None:
        _report(problems, label, line, f"{mark} condition does not parse")
        return
    t = f.fold.truth(parsed, f.fold.at(call))
    if mark == "skipif" and t == "true":
        _report(problems, label, line, "skipif on a constant never runs the check")
        return
    if t == "raises":
        _report(problems, label, line, f"{mark} condition always raises")
        return
    if isinstance(parsed, ast.Name):
        owner = f.fold.scope_of(call)
        if isinstance(owner, _FUNCS) and parsed.id in {
            a.arg
            for a in (*owner.args.posonlyargs, *owner.args.args, *owner.args.kwonlyargs)
        }:
            _report(
                problems,
                label,
                line,
                f"{mark} condition comes from a parameter (marker wrapper)",
            )
            return
    kind = _platform_kind(f, parsed)
    if kind == "mixed" and any(_platform_atom(f, n) for n in ast.walk(parsed)):
        _report(
            problems,
            label,
            line,
            f"{mark} condition is not purely a platform condition",
        )
        return
    if _impossible_platform(f, parsed):
        _report(
            problems,
            label,
            line,
            f"{mark} compares a platform to a value no platform has",
        )
        return
    if kat and mark == "skipif" and t != "false" and kind != "pure":
        _report(
            problems,
            label,
            line,
            "skipif in a KAT file on a condition that is not a platform check",
        )


def _marker_calls(f: _File):
    """(call, mark kind) for every skipif or xfail mark call."""
    for n in ast.walk(f.tree):
        if not isinstance(n, ast.Call):
            continue
        for name in f.names.resolve(n.func):
            kind = _mark_kind(name)
            if kind in ("skipif", "xfail"):
                yield n, kind
                break


def _check_marks(f: _File, problems: list[str], label: str, kat: bool) -> None:
    for call, kind in _marker_calls(f):
        line = call.lineno
        if any(k.arg is None for k in call.keywords):
            _report(
                problems,
                label,
                line,
                f"{kind} with ** arguments: the lint cannot see its arguments",
            )
            continue
        kws = {k.arg: k.value for k in call.keywords}
        conds = list(call.args)
        if "condition" in kws:
            conds.append(kws["condition"])
        if kind == "skipif":
            if not conds:
                _report(problems, label, line, "skipif with no condition always skips")
            for c in conds:
                _check_condition(f, problems, label, call, c, "skipif", kat)
            continue
        for c in conds:
            _check_condition(f, problems, label, call, c, "xfail", kat)
        if "strict" in kws:
            t = f.fold.truth(kws["strict"], f.fold.at(call))
            if t == "false":
                _report(
                    problems,
                    label,
                    line,
                    "xfail(strict=False) lets a fixed bug pass silently",
                )
            elif t != "true":
                _report(
                    problems, label, line, "xfail(strict=...) is not provably strict"
                )
        if "run" in kws and f.fold.truth(kws["run"], f.fold.at(call)) != "true":
            _report(problems, label, line, "xfail(run=False) never runs the check")
        has_raises = "raises" in kws
        strict = (
            "strict" in kws and f.fold.truth(kws["strict"], f.fold.at(call)) == "true"
        )
        if has_raises and not strict and _xfail_hides_the_check(f, call):
            _report(problems, label, line, "xfail(raises=) decides the outcome by fiat")


def _xfail_hides_the_check(f: _File, node: ast.AST) -> bool:
    """An xfail that never reaches the gate is the outcome. One that does is a known hole."""
    owner = f.owner(node)
    if not isinstance(owner, _FUNCS) or not owner.name.startswith("test"):
        return False
    hit, _end = f.test_reaches(owner)
    return not hit


def _under_platform_if(f: _File, node: ast.AST) -> bool:
    child = node
    while child in f.parents:
        p = f.parents[child]
        if isinstance(p, ast.If) and _platform_kind(f, p.test) == "pure":
            return True
        child = p
    return False


def lint_hatches(src: str, label: str, f: _File | None = None) -> list[str]:
    """Escape hatches that defeat xfail_strict or hollow a test, in every test file."""
    if f is None:
        f = _File(ast.parse(src, filename=label), label)
    problems: list[str] = []
    _check_marks(f, problems, label, kat=False)
    for n in ast.walk(f.tree):
        resolved = f.names.resolve(n)
        if any(_skip_kind(r) == "pytest.xfail" for r in resolved) and _is_called(f, n):
            _report(
                problems, label, n.lineno, "imperative pytest.xfail is never strict"
            )
        if f.in_test(n):
            for r in resolved:
                what = _classify(r)
                if what in ("forced exit", "dynamic code", "pytest.exit"):
                    _report(problems, label, n.lineno, f"{what} decides the test")
    return problems


def _is_called(f: _File, node: ast.AST) -> bool:
    p = f.parents.get(node)
    return isinstance(p, ast.Call) and p.func is node


def _uncaught_raise(f: _File, node: ast.Raise, fn) -> bool:
    """A raise in a test that runs on every path and nothing catches."""
    child: ast.AST = node
    while child in f.parents:
        p = f.parents[child]
        if p is fn:
            return True
        if isinstance(p, ast.If):
            t = f.fold.truth(p.test)
            if not (
                (t == "true" and child in p.body)
                or (t == "false" and child in p.orelse)
            ):
                return False
        elif isinstance(
            p,
            (
                ast.For,
                ast.AsyncFor,
                ast.While,
                ast.ExceptHandler,
                ast.Match,
            ),
        ):
            return False
        elif (
            (isinstance(p, ast.Try) or type(p).__name__ == "TryStar")
            and child in p.body
            and p.handlers
        ):
            return False
        elif isinstance(p, (ast.With, ast.AsyncWith)) and any(
            f.expected_exception(i) for i in p.items
        ):
            return False
        child = p
    return False


def _fiat_raise(f: _File, node: ast.Raise) -> str | None:
    exc = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
    for r in f.names.resolve(exc):
        if r == "builtins.AssertionError":
            return "raise AssertionError"
        if r in ("builtins.SystemExit", "builtins.KeyboardInterrupt"):
            return "forced exit"
        skip = _skip_kind(r)
        if skip:
            return skip
    return None


def lint_source(src: str, label: str, shadowed: bool = False) -> list[str]:  # noqa: C901, PLR0912
    tree = ast.parse(src, filename=label)
    f = _File(tree, label, shadowed)
    problems: list[str] = []

    # Fiat references, raises, skips and marks anywhere in the file.
    for n in ast.walk(tree):
        if isinstance(n, (ast.Name, ast.Attribute, ast.Call, ast.Subscript)):
            for r in f.names.resolve(n):
                what = _classify(r)
                if what:
                    _report(
                        problems, label, n.lineno, f"{what} in a KAT file fails by fiat"
                    )
                mark = _mark_kind(r)
                if mark == "skip" or (mark and mark.startswith("unittest.")):
                    shown = "skip mark" if mark == "skip" else f"{mark} skip mark"
                    _report(
                        problems,
                        label,
                        n.lineno,
                        f"unconditional {shown} in a KAT file never runs the check",
                    )
                skip = _skip_kind(r)
                if skip and _is_called(f, n) and not _under_platform_if(f, n):
                    _report(
                        problems,
                        label,
                        n.lineno,
                        f"{skip} in a KAT file outside a platform check never runs the check",
                    )
            if (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == "skipTest"
                and not _under_platform_if(f, n)
            ):
                _report(
                    problems,
                    label,
                    n.lineno,
                    "self.skipTest in a KAT file never runs the check",
                )
        if isinstance(n, ast.Raise):
            what = _fiat_raise(f, n)
            if what and not f.under_expected_exception(n):
                _report(
                    problems, label, n.lineno, f"{what} in a KAT file fails by fiat"
                )
            elif not what and n.exc is not None:
                owner = f.owner(n)
                if (
                    isinstance(owner, _FUNCS)
                    and owner.name.startswith("test")
                    and _uncaught_raise(f, n, owner)
                ):
                    _report(
                        problems,
                        label,
                        n.lineno,
                        "forced failure in a KAT file fails by fiat",
                    )
        if isinstance(n, ast.Assert) and not f.under_expected_exception(n):
            env = f.fold.at(n)
            kind, v = f.fold.fold(n.test, env)
            what = None
            if kind == "raises":
                what = "always raises"
            elif kind == "value":
                if isinstance(n.test, ast.Compare):
                    what = "constant comparison"
                else:
                    what = "constant assert" if v else "assert False"
            if what:
                _report(
                    problems, label, n.lineno, f"{what} in a KAT file fails by fiat"
                )
        if isinstance(n, (ast.Expr, ast.Return, ast.Assign, ast.If, ast.While)):
            value = n.test if isinstance(n, (ast.If, ast.While)) else n.value
            if (
                value is not None
                and f.owner(n) is not None
                and not f.under_expected_exception(n)
            ):
                if f.fold.fold(value, f.fold.at(n))[0] == "raises":
                    _report(
                        problems,
                        label,
                        n.lineno,
                        "always raises in a KAT file fails by fiat",
                    )
    _check_marks(f, problems, label, kat=True)

    for name, fn in f.funcs.items():
        if not name.startswith("test"):
            continue
        where = f"{label}:{fn.lineno} {name}"
        line = f.patched(fn)
        if line is not None:
            problems.append(
                f"{where}: patches the gate at line {line}; a patched gate is not the real gate"
            )
            continue
        hit, end = f.test_reaches(fn)
        if not hit:
            if end is not None:
                problems.append(
                    f"{where}: returns or raises at line {end.lineno} before reaching the gate"
                )
            else:
                problems.append(
                    f"{where}: never reaches the gate on its straight-line path"
                )
            continue
        seed = f.result_params(fn)
        if not f.asserts_result(fn, f.auto_params(fn), seed, frozenset({name})):
            problems.append(f"{where}: never asserts on the gate's result")
    problems += [p for p in lint_hatches(src, label, f) if p not in problems]
    return problems


def _shadowed(path: Path, root: Path) -> bool:
    """A gate module beside the test file would be imported instead of the real one."""
    here = path.resolve().parent
    if here == root.resolve():
        return False
    return (here / "capability_gate.py").exists() or (here / "adapters").is_dir()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("files", nargs="*", type=Path)
    ap.add_argument("--root", type=Path, default=ROOT)
    a = ap.parse_args(argv)
    files = a.files or discover(a.root)
    every = a.files or test_files(a.root)

    problems = []
    try:
        kats = {p.resolve() for p in files}
        for path in files:
            problems += lint_source(
                path.read_text(encoding="utf-8"),
                path.as_posix(),
                _shadowed(path, a.root),
            )
        for path in every:
            if path.resolve() in kats:
                continue
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
