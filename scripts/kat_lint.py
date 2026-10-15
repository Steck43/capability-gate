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
  outcome exception or ``unittest.SkipTest``, or a class defined in the file
  that inherits from one of them (through any depth of same-file classes),
  and throwing one into a generator with ``.throw``;
* an ``assert`` whose test folds to a constant, or always raises;
* a tautological ``assert``: a comparison of an expression with itself
  (``==``, ``!=``, ``is``, ``is not``, ordering), its negation,
  ``isinstance(x, object)``, a constant element of a literal tuple or list
  picked by a constant index, or membership in a literal container that names
  every ``Verdict`` member, and an ``or`` with an always-true side or an
  ``and`` with an always-false side (``assert r == r or r``), including a
  side beside its own negation (``x == y or x != y``, ``p or not p``,
  ``not (p and not p)``); sides are compared after ``not`` is folded in,
  ``bool(x)`` is read as ``x``, ``!=``, ``is not`` and ``not in`` are read as
  negated ``==``, ``is`` and ``in``, and ``==`` and ``is`` operands are put in
  a fixed order;
* an ``assert`` whose test is truthy by construction: a display (tuple,
  list, set or dict) with a plain element or a starred non-empty display
  (``(*[d],)``), a generator expression, an f-string or a lambda; ``repr``, ``str``, ``format`` or ``hasattr`` of
  anything; ``any`` over a display with an element that folds true; and a
  length compared so that no length can fail it (``len(x) >= 0``,
  ``0 <= len(x)``, ``len(x) > -1``);
* an expression compared with itself in disguise: a walrus is both its
  target and its value (``(y := d) is y``), a one-off display picked by a
  constant index is the element it picks (``[d][0] is d``), membership in a
  display that holds the expression itself always holds (``x in (x,)``), and
  ``len`` of a display whose shape fixes its size (a tuple or list with no
  starred part, a one-element set or dict) compared with a constant;
* a statement, return value, or assigned value that always raises;
* in a test function, a ``raise`` that runs on every path and nothing catches.
  A loop over a non-empty constant, ``while True`` and the first case of a
  ``match`` whose pattern matches everything run their body; a handler that
  cannot catch the raised class does not stop it.

Constant folding sees literals, empty literals, names provably assigned once
(module, function, and tuple-unpacking bindings, annotated bindings, walrus),
ternaries, ``and`` and ``or`` with a constant side, ``not``, arithmetic,
comparisons and chains, membership in an empty container, subscripts, and the
pure builtins (``bool``, ``int``, ``len`` and the rest of ``_PURE``), and a
constant routed through something the file binds once: a no-argument helper
whose body is one ``return``, a lambda, a ``functools.partial``, a class
attribute or staticmethod of a class used only by attribute reads and calls,
``getattr`` with a constant name, and a dict or list read by subscript; a lambda
or ``functools.partial`` called where it is written; a same-file helper or
lambda with parameters whose one ``return`` reads none of them, or returns one
of them unchanged (the argument that parameter received folds); and a method of
a sealed same-file class called on a fresh instance, judged the same way. A name
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
names assigned once from those, and constants. A platform check is evaluated
on Linux, Windows and macOS, each under Python 3.11 and 3.12 (the tests job's
matrix): an imperative skip whose guard runs it in every one of those
(``sys.platform != "none"``, ``os.name == os.name``, every system listed,
two inequalities joined by ``or``, ``sys.version_info >= (3, 11)``), and a
``skipif`` true in every one, never run the check and are rejected. A guard
false in all of them never fires its skip, so the test runs and that stays
clean.

Reaching the real gate. A test reaches the gate when its straight-line path
(try, with, and for bodies count; if branches, except handlers, while loops,
and dead code do not), before any return or raise, calls:

* ``.evaluate`` or ``.throw`` on a gate: a ``capability_gate.Gate`` built in
  the test, a same-file pytest fixture that returns one (taken by name), a
  same-file helper that returns one, or a local name every binding of which is
  one of those. A helper's parameter is a gate only when the caller passes one;
* ``open_authorized_read``, ``_pre``, ``main`` or ``pre_tool_call`` imported
  from ``capability_gate`` or ``adapters``;
* a subprocess that runs ``adapters/claude_code_hook.py`` under Python: the
  program is ``sys.executable`` or a python command and the script is its
  first argument after plain options (an ``echo``, ``cat`` or ``-c`` does not
  run it);
* a same-file helper, or same-file fixture the test takes, that does one of
  those.

It does not count when the gate class or function comes from anywhere else (a
test helper module, conftest, a class defined or subclassed in the file,
``getattr``, ``type()``, ``importlib``), when a ``capability_gate.py`` or
``adapters`` folder sits beside the test file, when the test, its fixtures,
autouse fixtures, its helpers or the module patch the gate (``setattr`` or
``monkeypatch.setattr`` or ``mock.patch`` on a gate, the Gate class, a gate
function, or the gate module reached through ``sys.modules``; assignment
to one of their attributes or to an attribute of ``type(gate)`` or
``gate.__class__``, with ``getattr(x, "name")`` read as ``x.name``, and
the class read through ``__mro__[i]`` or through a name every binding of
which is that class (``k = type(gate); setattr(k, ...)``);
``monkeypatch.setitem`` or ``delitem`` on their ``__dict__`` or ``vars()``;
``__setattr__`` or ``__delattr__`` called on any of them, or through
``object`` or ``type``; a store into, or ``update``, ``setdefault``,
``pop`` or ``clear`` on, their ``__dict__`` or ``vars()``), when the test
rebinds a gate fixture it takes to anything other than a real gate (plain,
tuple-unpacking or walrus assignment), or when the call is dead:
under a constant-false branch, in a loop over an empty constant, in a
comprehension over one, in a generator expression nothing consumes, or inside
``pytest.raises``, ``contextlib.suppress`` or ``assertRaises``.

Every KAT that reaches the gate must also assert on the gate's answer, and
only one form counts (an allowlist, not a list of refused shapes): a single
``==`` or ``is`` (never ``!=`` or ``is not``, which pass on every other answer)
between either

- a verdict: ``.verdict`` read from a gate call or from a name that only ever
  holds a gate result, or a name that only ever holds such a verdict; and a
  ``Verdict`` member or a verdict string (``"allow"``, ``"deny"``, ``"ask"``);
- or a gate call's own answer: the call, a name that only ever holds it, or
  its ``returncode`` (the hook script run as a process); and a literal
  (``None``, a bool, a number or a string).

A name only ever holds a result when every store to it in the test is that
binding; any other store anywhere in the test (a plain assignment, an
unpacking, an augmented assignment, a loop target, a ``with`` or ``except``
name, an import, a store through ``globals()`` (under a key the lint cannot
fold it takes every name out), a ``global`` or ``nonlocal`` declaration, a
delete) takes it out. A ``raise`` caught inside a ``try`` body does not end
the path. The assert must sit on the test's straight path: the body, the
chosen branch of a constant ``if``, a ``try`` or ``with`` body, a ``finally``,
and the body of a ``for`` over a non-empty constant, before any statement that
always leaves. An assert in an ``if`` on an unknown test, a handler, a loop's
``else``, a ``while`` body, a nested function or a helper does not satisfy the
KAT, nor does one inside a ``try`` whose handler catches its failure
(``AssertionError``, ``Exception``, ``BaseException``, a bare ``except`` or a
tuple holding one) without raising again, nor one inside a ``try`` whose
``finally`` returns, breaks or continues.

Every other assert in a KAT test that reads the gate's answer (a name derived
from a gate result, or a gate call) is refused, unless it is one of the named
richer forms in ``ANSWER_FORMS``. Each is accepted in exactly this shape and
none satisfies a KAT on its own:

- reason substring, ``"<text>" in <result>.reason``: a real deny names its
  reason, and a fixed string in it is not true of every answer;
- enforced flag, ``<result>.enforced is True`` or ``is False`` (``==`` too):
  whether the verdict was enforced or only observed;
- paths literal, ``<result>.paths == (<string literals>)``: the paths the gate
  judged, written out.

So boolean combinations, ``not``, displays, comprehensions, calls, formatting,
helpers, partials, properties, subscripts, membership, chained comparisons,
ternaries and walrus expressions that read the answer are all refused, however
they are spelled. An assert that reads no gate answer (a file on disk, a log
row read back, a count from a helper) is still judged by the rules above.

A name defined more than once at module level in a KAT file is rejected:
pytest uses the last definition, so a second fixture of the same name can
replace the real gate.

KAT files are found among test files: those under tests/ and at the top level
whose names start with test, and every file pytest itself collects (its
testpaths, python_files and norecursedirs from pytest.ini, or pytest's
defaults), so a KAT pytest runs is never skipped. Among them, case-
insensitively: names like test_k*.py or containing "kat", any file with a
"# KAT" comment, and any test file that names a receipts/ path. Files named on
the command line are linted as KATs whatever their name. With
``--require-kats`` a run that finds no KAT file fails, so a check cannot pass
by having nothing to judge.

Known gaps: the lint reads one file. A gate patched from conftest.py or another
module, a fixture supplied by conftest.py, a module loaded by file path, and a
condition read from the environment outside a skip mark are not judged.
Patching any attribute of a gate object or the Gate class counts as patching
the gate; fault injection anywhere else (for example
``monkeypatch.setattr(os, "lstat", ...)``, or a private helper in the
``capability_gate`` module) is allowed on purpose. A ``while`` body never
counts as reaching the gate. It proves the test asks the real gate and asserts
on the answer; it does not prove the assertion is the right one (a verdict
compared with one the gate cannot return makes a red test, not a passing
one). For asserts that read no gate answer, tautologies are recognised only
in the listed shapes. Patching through
an alias the lint cannot resolve (a gate stored in a container and patched
from there) is not caught. Review findings N7 to N14 belong to other pull
requests (the leak scan, the wiring check, the hook, the kill switch and the
path matcher), not to this lint; H5d to H5n could not be identified from the
review record. The floor's KAT lint job does not pass ``--require-kats`` yet;
wiring it into floor.yml is #84's change. For asserts that read no gate
answer, a test that is truthy by construction is caught only in the listed
shapes, and a display with a starred part of unknown contents is not one of
them (it may be empty); a helper folds only when its one ``return`` reads
none of its parameters or returns one unchanged.

Every file is read as Python reads it: a coding cookie other than UTF-8 (any
alias of UTF-8, such as ``utf8`` or ``U8``, is UTF-8), or bytes that are not
UTF-8, is a lint problem, never a traceback.

Exit 0 = clean. Exit 1 = violation, or no KAT file with ``--require-kats``.
Exit 2 = a file did not parse.
"""

from __future__ import annotations

import argparse
import ast
import builtins
import codecs
import io
import operator
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
# One world per mainstream platform and supported Python. A platform
# condition true in every world (or false in every world) decides nothing about
# where the test runs.
_SYSTEMS = (
    {"sys.platform": "linux", "os.name": "posix", "platform.system": "Linux"},
    {"sys.platform": "win32", "os.name": "nt", "platform.system": "Windows"},
    {"sys.platform": "darwin", "os.name": "posix", "platform.system": "Darwin"},
)
# The Pythons the floor's tests job runs (floor.yml matrix).
_PYTHONS = ((3, 11, 0, "final", 0), (3, 12, 0, "final", 0))
_WORLDS = tuple(
    {**system, "sys.version_info": version}
    for system in _SYSTEMS
    for version in _PYTHONS
)
_NO_VALUE = object()
# Exceptions an assert raises when it fails; a handler for one of these that
# does not re-raise swallows the assert.
_ASSERT_CATCHERS = {
    "builtins.AssertionError",
    "builtins.Exception",
    "builtins.BaseException",
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
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [
                d for d in dirnames if not any(fnmatch.fnmatch(d, s) for s in skip)
            ]
            for name in filenames:
                if any(fnmatch.fnmatch(name, pat) for pat in files):
                    out.add(Path(dirpath) / name)
    return out


def test_files(root: Path) -> list[Path]:
    """Test files under tests/ and at the top level, and every file pytest
    itself collects, so a KAT pytest runs is never skipped by the lint."""
    found = {
        p
        for p in (*root.joinpath("tests").rglob("*.py"), *root.glob("*.py"))
        if p.name.lower().startswith("test") and p.is_file()
    } | {p for p in _pytest_collects(root) if p.suffix == ".py" and p.is_file()}
    return sorted(found)


def discover(root: Path) -> list[Path]:
    found = []
    for p in test_files(root):
        src = p.read_bytes().decode("utf-8", errors="replace")
        # EXEMPT covers the name and receipts heuristics only: a KAT marker
        # still makes an exempt file a KAT.
        if _has_marker(src):
            found.append(p)
        elif p.relative_to(root).as_posix() in EXEMPT:
            continue
        elif _NAME.search(p.name) or _names_receipts(src):
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
        # How often each name is bound anywhere in the file, and the module-level
        # definition of each name bound exactly once: a constant routed through
        # one of these (a helper, lambda, partial, class attribute) still folds.
        counts: dict[str, int] = {}
        for n in ast.walk(tree):
            names: list[str] = []
            if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                names = [n.id]
            elif isinstance(n, (*_FUNCS, ast.ClassDef)):
                names = [n.name]
            elif isinstance(n, (ast.Import, ast.ImportFrom)):
                names = [(a.asname or a.name).split(".", 1)[0] for a in n.names]
            elif isinstance(n, ast.arg):
                names = [n.arg]
            for name in names:
                counts[name] = counts.get(name, 0) + 1
        self.top: dict[str, ast.AST] = {}
        for s in tree.body:
            if isinstance(s, (*_FUNCS, ast.ClassDef)):
                name, value = s.name, s
            elif (
                isinstance(s, ast.Assign)
                and len(s.targets) == 1
                and isinstance(s.targets[0], ast.Name)
            ):
                name, value = s.targets[0].id, s.value
            else:
                continue
            if counts.get(name) == 1 and name not in self.shared:
                self.top[name] = value

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
            # A subscript read whose value is only read (an assert, a test, a
            # comparison) cannot change the container.
            if (
                isinstance(p, ast.Subscript)
                and p.value is n
                and isinstance(p.ctx, ast.Load)
                and isinstance(self.parents.get(p), _READ_PARENTS)
            ):
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

    def _fold(self, node, env, depth):
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
        if isinstance(node, ast.Attribute):
            value = self._class_member(node.value, node.attr)
            if isinstance(value, ast.expr):
                return self._fold(value, self.at(value), d)
            return UNKNOWN
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

    def _sealed_class(self, node: ast.AST) -> ast.ClassDef | None:
        """A module class bound once whose every use reads an attribute or
        calls it, so nothing outside its body can change its members."""
        if not isinstance(node, ast.Name):
            return None
        cls = self.top.get(node.id)
        if not isinstance(cls, ast.ClassDef):
            return None
        for n in ast.walk(self.tree):
            if isinstance(n, ast.Name) and n.id == node.id and n is not node:
                p = self.parents.get(n)
                if isinstance(p, ast.Attribute) and isinstance(p.ctx, ast.Load):
                    continue
                if isinstance(p, ast.Call) and p.func is n:
                    continue
                return None
        return cls

    def _class_member(self, owner: ast.AST, attr: str) -> ast.AST | None:
        """The one definition of attr in a sealed class: an assigned value or a
        staticmethod."""
        cls = self._sealed_class(owner)
        if cls is None:
            return None
        found = []
        for s in cls.body:
            if (
                isinstance(s, ast.Assign)
                and len(s.targets) == 1
                and isinstance(s.targets[0], ast.Name)
                and s.targets[0].id == attr
            ):
                found.append(s.value)
            elif isinstance(s, (*_FUNCS, ast.ClassDef)) and s.name == attr:
                static = any(
                    isinstance(dd, ast.Name) and dd.id == "staticmethod"
                    for dd in getattr(s, "decorator_list", [])
                )
                found.append(s if static else None)
            elif isinstance(s, (ast.AugAssign, ast.AnnAssign)) and (
                getattr(s.target, "id", None) == attr
            ):
                found.append(None)
        return found[0] if len(found) == 1 else None

    def _fold_returned(self, fn: ast.AST, node: ast.Call, env, d, method: bool):
        """A call of a function or lambda whose body is one return: the returned
        value when it reads none of the parameters, or the argument a parameter
        received when it returns that parameter unchanged (an identity)."""
        args = fn.args
        if args.vararg or args.kwarg or args.kwonlyargs or node.keywords:
            return None
        params = [a.arg for a in (*args.posonlyargs, *args.args)]
        if method:
            if not params:
                return None
            params = params[1:]
        if len(node.args) != len(params) or any(
            isinstance(a, ast.Starred) for a in node.args
        ):
            return None
        if isinstance(fn, ast.Lambda):
            value = fn.body
        else:
            body = [
                s
                for s in fn.body
                if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
            ]
            if not (
                len(body) == 1 and isinstance(body[0], ast.Return) and body[0].value
            ):
                return None
            value = body[0].value
        if isinstance(value, ast.Name) and value.id in params:
            return self._fold(node.args[params.index(value.id)], env, d)
        reads = {n.id for n in ast.walk(value) if isinstance(n, ast.Name)}
        own = {*params, *([args.args[0].arg] if method and args.args else [])}
        if reads & own:
            return None
        return self._fold(value, self.at(value), d)

    def _fold_routed(self, node: ast.Call, env, d):
        """A call of a same-file helper, lambda, staticmethod or
        functools.partial that the file binds once, a lambda or partial called
        where it is written, and a method of a sealed same-file class called on
        a fresh instance."""
        f = node.func
        if isinstance(f, ast.Lambda):
            return self._fold_returned(f, node, env, d, method=False)
        if (
            isinstance(f, ast.Call)
            and ast.unparse(f.func) in ("functools.partial", "partial")
            and f.args
            and not f.keywords
            and not node.keywords
        ):
            call = ast.Call(f.args[0], [*f.args[1:], *node.args], [])
            ast.copy_location(call, node)
            self.parents[call] = self.parents.get(node, self.tree)
            return self._fold_call(call, env, d)
        if (
            isinstance(f, ast.Attribute)
            and isinstance(f.value, ast.Call)
            and not f.value.args
            and not f.value.keywords
        ):
            cls = self._sealed_class(f.value.func)
            if cls is not None:
                methods = [
                    s for s in cls.body if isinstance(s, _FUNCS) and s.name == f.attr
                ]
                if len(methods) == 1 and not methods[0].decorator_list:
                    return self._fold_returned(methods[0], node, env, d, method=True)
            return None
        target: ast.AST | None = None
        if isinstance(f, ast.Name) and (
            f.id not in env or isinstance(self.top.get(f.id), ast.Lambda)
        ):
            target = self.top.get(f.id)
        elif isinstance(f, ast.Attribute):
            target = self._class_member(f.value, f.attr)
        if target is None:
            return None
        if (
            isinstance(target, ast.Call)
            and ast.unparse(target.func) in ("functools.partial", "partial")
            and target.args
            and not target.keywords
        ):
            call = ast.Call(target.args[0], [*target.args[1:], *node.args], [])
            ast.copy_location(call, node)
            self.parents[call] = self.parents.get(node, self.tree)
            return self._fold_call(call, env, d)
        if node.args and isinstance(target, (*_FUNCS, ast.Lambda)):
            return self._fold_returned(target, node, env, d, method=False)
        if node.args or node.keywords:
            return None
        if isinstance(target, ast.Lambda) and not target.args.args:
            return self._fold(target.body, self.at(target.body), d)
        if isinstance(target, _FUNCS) and not (
            target.args.args or target.args.posonlyargs or target.args.kwonlyargs
        ):
            body = [
                s
                for s in target.body
                if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
            ]
            if len(body) == 1 and isinstance(body[0], ast.Return) and body[0].value:
                return self._fold(body[0].value, self.at(body[0].value), d)
        return None

    def _fold_call(self, node: ast.Call, env, d):
        f = node.func
        if (
            isinstance(f, ast.Name)
            and f.id == "getattr"
            and f.id not in self.file_bound
            and len(node.args) == 2
            and not node.keywords
        ):
            kind, name = self._fold(node.args[1], env, d)
            if kind == "value" and isinstance(name, str):
                attr = ast.Attribute(node.args[0], name, ast.Load())
                ast.copy_location(attr, node)
                self.parents[attr] = self.parents.get(node, self.tree)
                return self._fold(attr, env, d)
            return UNKNOWN
        routed = self._fold_routed(node, env, d)
        if routed is not None:
            return routed
        if (
            isinstance(f, ast.Name)
            and f.id == "len"
            and f.id not in self.file_bound
            and len(node.args) == 1
            and not node.keywords
            and isinstance(node.args[0], (ast.List, ast.Tuple))
            and not any(isinstance(e, ast.Starred) for e in node.args[0].elts)
        ):
            return _known(len(node.args[0].elts))
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

    def _resolve(self, node, dynamic, depth):
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


class _File:
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
        self.classes = {
            n.name: n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)
        }
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
        """A subprocess that runs the hook script under Python: the program is
        sys.executable or a python command, and the script is its first
        argument after plain options (an echo, cat or ``-c`` does not run it)."""
        if not (self.names.resolve(call.func) & SUBPROCESS):
            return False
        argv = call.args[0] if call.args else None
        for kw in call.keywords:
            if kw.arg == "args":
                argv = kw.value
        if isinstance(argv, ast.Constant) and isinstance(argv.value, str):
            words: list[ast.AST] = [ast.Constant(w) for w in argv.value.split()]
        elif isinstance(argv, (ast.List, ast.Tuple)):
            words = list(argv.elts)
        else:
            return False
        if not words or not self._python_program(words[0]):
            return False
        for w in words[1:]:
            if self._hook_path(w):
                return True
            if not (
                isinstance(w, ast.Constant)
                and isinstance(w.value, str)
                and w.value.startswith("-")
                and w.value not in ("-c", "-m")
                and not w.value.startswith(("-c", "-m"))
            ):
                return False
        return False

    def _python_program(self, node: ast.AST) -> bool:
        if self.names.resolve(node) & {"sys.executable"}:
            return True
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            base = re.split(r"[\\/]", node.value)[-1].lower().removesuffix(".exe")
            return bool(re.fullmatch(r"python(3(\.\d+)?)?|py", base))
        return False

    @staticmethod
    def _hook_path(node: ast.AST) -> bool:
        consts = [
            c.value
            for c in ast.walk(node)
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
                t = self.fold.truth(s.test)
                if t != "false":
                    yield from self.live_stmts(s.body)
                # The else runs only when the test turns false; a test that is
                # always true never does, so its else is dead.
                if t != "true":
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
            if self.leaves(s):
                return

    def leaves(self, s: ast.stmt, jumps_only: bool = False) -> str | None:
        """'func' when a statement always leaves the function (return, or
        raise unless jumps_only), 'loop' when it always leaves the enclosing
        loop body (break, continue), else None."""
        if isinstance(s, ast.Return) or (isinstance(s, ast.Raise) and not jumps_only):
            return "func"
        if isinstance(s, (ast.Break, ast.Continue)):
            return "loop"
        if isinstance(s, ast.If):
            t = self.fold.truth(s.test)
            if t == "true":
                return self.block_leaves(s.body, jumps_only)
            if t == "false":
                return self.block_leaves(s.orelse, jumps_only)
            a = self.block_leaves(s.body, jumps_only)
            b = self.block_leaves(s.orelse, jumps_only)
            if a and b:
                return "func" if a == b == "func" else "loop"
            return None
        if isinstance(s, (ast.With, ast.AsyncWith)):
            if any(self.expected_exception(i) for i in s.items):
                return None
            return self.block_leaves(s.body, jumps_only)
        if isinstance(s, ast.Try) or type(s).__name__ == "TryStar":
            final = self.block_leaves(s.finalbody, jumps_only)
            if final:
                return final
            body = self.block_leaves(s.body, True if s.handlers else jumps_only)
            return body
        if isinstance(s, (ast.For, ast.AsyncFor)):
            kind, v = self.fold.fold(s.iter, self.fold.at(s))
            try:
                runs = kind == "value" and len(v) > 0  # type: ignore[arg-type]
            except TypeError:
                runs = False
            if runs and self.block_leaves(s.body, jumps_only) == "func":
                return "func"
            return None
        if isinstance(s, ast.While):
            if (
                self.fold.truth(s.test) == "true"
                and self.block_leaves(s.body, jumps_only) == "func"
            ):
                return "func"
            return None
        if isinstance(s, ast.Match) and s.cases:
            first = s.cases[0]
            if first.guard is None and _irrefutable(first.pattern):
                return self.block_leaves(first.body, jumps_only)
        return None

    def block_leaves(self, stmts: list[ast.stmt], jumps_only: bool = False):
        for s in stmts:
            how = self.leaves(s, jumps_only)
            if how:
                return how
        return None

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
        if self._sys_modules_entry(expr):
            return True
        if isinstance(expr, ast.Name):
            vals = self.names.binds.get(expr.id, [])
            if vals and all(
                kind == "value" and self._sys_modules_entry(v) for kind, v in vals
            ):
                return True
        return any(
            n and n.split(".", 1)[0] in REAL_ROOTS for n in self.names.resolve(expr)
        )

    def _sys_modules_entry(self, expr: ast.AST) -> bool:
        """sys.modules["capability_gate"] (or an adapters module), by any
        spelling the lint can fold."""
        if not (
            isinstance(expr, ast.Subscript)
            and self.names.resolve(expr.value) & {"sys.modules"}
        ):
            return False
        kind, v = self.fold.fold(expr.slice, self.fold.at(expr))
        return (
            kind == "value" and isinstance(v, str) and v.split(".", 1)[0] in REAL_ROOTS
        )

    def attr_view(self, expr: ast.AST) -> ast.AST:
        """getattr(x, "name") with a name the lint can fold, read as x.name."""
        if (
            isinstance(expr, ast.Call)
            and self.names.resolve(expr.func) == {"builtins.getattr"}
            and len(expr.args) == 2
            and not expr.keywords
        ):
            kind, name = self.fold.fold(expr.args[1], self.fold.at(expr))
            if kind == "value" and isinstance(name, str):
                return ast.Attribute(expr.args[0], name, ast.Load())
        return expr

    def gate_namespace(self, expr: ast.AST, typed: set[str]) -> bool:
        """The attribute dict of a gate, the Gate class or a gate module."""
        expr = self.attr_view(expr)
        if isinstance(expr, ast.Attribute) and expr.attr == "__dict__":
            inner = expr.value
        elif (
            isinstance(expr, ast.Call)
            and self.names.resolve(expr.func) == {"builtins.vars"}
            and expr.args
        ):
            inner = expr.args[0]
        else:
            return False
        return self.gate_target(inner, typed) or self.real_module(inner)

    def gate_type(self, expr: ast.AST, typed: set[str], depth: int = 0) -> bool:
        """type(gate) or gate.__class__ (getattr included): the class a gate
        instance was built from, read through ``__mro__[i]`` and through a
        name every binding of which is such a class."""
        expr = self.attr_view(expr)
        if depth > 10:
            return False
        if isinstance(expr, ast.Subscript):
            owner = self.attr_view(expr.value)
            if isinstance(owner, ast.Attribute) and owner.attr == "__mro__":
                return self.gate_type(owner.value, typed, depth + 1)
        if isinstance(expr, ast.Name):
            vals = self.names.binds.get(expr.id, [])
            if vals and all(
                kind == "value"
                and v is not expr
                and self.gate_type(v, typed, depth + 1)
                for kind, v in vals
            ):
                return True
        if isinstance(expr, ast.Attribute) and expr.attr == "__class__":
            return self.gate_target(self.attr_view(expr.value), typed)
        return (
            isinstance(expr, ast.Call)
            and self.names.resolve(expr.func) == {"builtins.type"}
            and len(expr.args) == 1
            and self.gate_target(expr.args[0], typed)
        )

    def patch_at(self, node: ast.AST, typed: set[str]) -> bool:
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute):
                if f.attr in ("__setattr__", "__delattr__") and (
                    self.gate_target(f.value, typed) or self.gate_type(f.value, typed)
                ):
                    return True
                if f.attr in (
                    "update",
                    "__setitem__",
                    "__delitem__",
                    "setdefault",
                    "pop",
                    "popitem",
                    "clear",
                ) and self.gate_namespace(f.value, typed):
                    return True
                # monkeypatch.setitem / delitem on a gate's namespace.
                if (
                    f.attr in ("setitem", "delitem")
                    and node.args
                    and self.gate_namespace(node.args[0], typed)
                ):
                    return True
            spelled = ast.unparse(f)
            resolved = {n or "" for n in self.names.resolve(f)}
            setter = (
                isinstance(f, ast.Attribute)
                and f.attr in ("setattr", "delattr", "__setattr__", "__delattr__")
            ) or resolved & {"builtins.setattr", "builtins.delattr"}
            patcher = any(
                r.endswith(("mock.patch", "mock.patch.object", "mock.patch.multiple"))
                for r in resolved
            ) or spelled.endswith(("patch", "patch.object", "patch.multiple"))
            if not (setter or patcher) or not node.args:
                return False
            target = node.args[0]
            if self.gate_type(target, typed):
                return True
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
                    if isinstance(a, ast.Subscript) and isinstance(
                        a.ctx, (ast.Store, ast.Del)
                    ):
                        if self.gate_namespace(a.value, typed):
                            return True
                    if isinstance(a, ast.Attribute) and isinstance(
                        a.ctx, (ast.Store, ast.Del)
                    ):
                        owner = self.attr_view(a.value)
                        if self.gate_target(owner, typed) or self.gate_type(
                            owner, typed
                        ):
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

        def uses(e) -> bool:
            return self.uses_result(e, typed, results)

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

    def catches_assert(self, handler: ast.ExceptHandler) -> bool:
        if handler.type is None:
            return True
        kinds = (
            handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
        )
        return any(self.names.resolve(k) & _ASSERT_CATCHERS for k in kinds)

    def swallowed(self, node: ast.AST, fn: ast.AST) -> bool:
        """An assert inside a try whose handler catches its failure and does
        not raise again: the assert can never fail the test."""
        child = node
        while child in self.parents and child is not fn:
            p = self.parents[child]
            if (isinstance(p, ast.Try) or type(p).__name__ == "TryStar") and (
                child in p.body
            ):
                for h in p.handlers:
                    if self.catches_assert(h) and not any(
                        isinstance(x, ast.Raise) for x in ast.walk(h)
                    ):
                        return True
            # A finally that returns, breaks or continues discards the
            # assert's failure on the way out.
            if (
                (isinstance(p, ast.Try) or type(p).__name__ == "TryStar")
                and child is not None
                and child not in p.finalbody
                and self.block_leaves(p.finalbody, jumps_only=True)
            ):
                return True
            child = p
        return False

    # --- the answer allowlist

    def runs_once(self, it: ast.AST) -> bool:
        kind, v = self.fold.fold(it, self.fold.at(it))
        try:
            return kind == "value" and len(v) > 0  # type: ignore[arg-type]
        except TypeError:
            return False

    def straight_path(self, stmts: list[ast.stmt]) -> tuple[list[ast.stmt], str | None]:
        """Statements that run on every pass through, in order: the chosen
        branch of a constant if, try and with bodies, a finally, and the body of
        a for over a non-empty constant. A branch on an unknown test, a handler,
        a loop's else and a while body are not on the path. Stops at the first
        statement that always leaves."""
        out: list[ast.stmt] = []
        for s in stmts:
            out.append(s)
            inner: list[ast.stmt] | None = None
            if isinstance(s, ast.If):
                truth = self.fold.truth(s.test)
                if truth == "true":
                    inner = s.body
                elif truth == "false":
                    inner = s.orelse
            elif isinstance(s, ast.Try) or type(s).__name__ == "TryStar":
                inner = s.body
            elif isinstance(s, (ast.With, ast.AsyncWith)):
                if not any(self.expected_exception(i) for i in s.items):
                    inner = s.body
            elif isinstance(s, (ast.For, ast.AsyncFor)) and self.runs_once(s.iter):
                inner = s.body
            if inner is not None:
                sub, left = self.straight_path(inner)
                out += sub
                # A raise in a try body may be caught; whether the try as a
                # whole leaves is decided by leaves() below.
                is_try = isinstance(s, ast.Try) or type(s).__name__ == "TryStar"
                if left == "func" and not is_try:
                    return out, "func"
            if (
                isinstance(s, ast.Try) or type(s).__name__ == "TryStar"
            ) and s.finalbody:
                sub, left = self.straight_path(s.finalbody)
                out += sub
                if left:
                    return out, left
            how = self.leaves(s)
            if how:
                return out, how
        return out, None

    def stores(self, fn) -> dict[str, list[ast.AST | None]]:
        """Every value each name in the test is set to; None where the store
        binds something the lint does not read as a value (an unpacking, an
        augmented assignment, a loop target, a with or except name, an import,
        a store through globals(), a global or nonlocal declaration, a delete).
        A globals() store under a key the lint cannot fold may be any name, so
        it is recorded under "*" and takes every name out."""
        out: dict[str, list[ast.AST | None]] = {}

        def add(name: str, value: ast.AST | None) -> None:
            out.setdefault(name, []).append(value)

        def names_in(tgt: ast.AST) -> list[str]:
            return [
                x.id
                for x in ast.walk(tgt)
                if isinstance(x, ast.Name) and isinstance(x.ctx, (ast.Store, ast.Del))
            ]

        for n in _scope_nodes(fn):
            if isinstance(n, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                if n.value is None:
                    continue
                targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                for tgt in targets:
                    if isinstance(tgt, ast.Name):
                        add(tgt.id, n.value)
                    else:
                        for name in names_in(tgt):
                            add(name, None)
            elif isinstance(n, (ast.AugAssign, ast.For, ast.AsyncFor)):
                for name in names_in(n.target):
                    add(name, None)
            elif isinstance(n, ast.withitem) and n.optional_vars is not None:
                for name in names_in(n.optional_vars):
                    add(name, None)
            elif isinstance(n, ast.Delete):
                for tgt in n.targets:
                    for name in names_in(tgt):
                        add(name, None)
            elif isinstance(n, ast.ExceptHandler) and n.name:
                add(n.name, None)
            elif isinstance(n, (ast.Import, ast.ImportFrom)):
                for alias in n.names:
                    add((alias.asname or alias.name).split(".")[0], None)
            elif isinstance(n, (ast.Global, ast.Nonlocal)):
                for name in n.names:
                    add(name, None)
            if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                for tgt in targets:
                    if (
                        isinstance(tgt, ast.Subscript)
                        and isinstance(tgt.value, ast.Call)
                        and isinstance(tgt.value.func, ast.Name)
                        and tgt.value.func.id in ("globals", "vars", "locals")
                    ):
                        kind, key = self.fold.fold(tgt.slice, self.fold.at(tgt))
                        add(
                            key if kind == "value" and isinstance(key, str) else "*",
                            None,
                        )
        return out

    def result_value(self, node: ast.AST, direct: set[str], typed: set[str]) -> bool:
        if isinstance(node, ast.Name):
            return node.id in direct and isinstance(node.ctx, ast.Load)
        return isinstance(node, ast.Call) and self.call_reaches(
            node, typed, frozenset()
        )

    def verdict_value(
        self, node: ast.AST, direct: set[str], verdicts: set[str], typed: set[str]
    ) -> bool:
        if isinstance(node, ast.Name):
            return node.id in verdicts and isinstance(node.ctx, ast.Load)
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "verdict"
            and self.result_value(node.value, direct, typed)
        )

    def verdict_token(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Constant):
            return node.value in _VERDICT_STRINGS
        return bool(self.names.resolve(node) & _VERDICTS)

    def answer_names(
        self, fn, typed: set[str], seed: set[str]
    ) -> tuple[set[str], set[str]]:
        """Names that only ever hold a gate result, and names that only ever
        hold a result's verdict. Any other store to a name, anywhere in the
        test, takes it out."""
        stores = self.stores(fn)
        if "*" in stores:
            return set(), set()
        direct = {n for n in seed if n not in stores} | {
            n
            for n, values in stores.items()
            if values
            and all(
                v is not None
                and isinstance(v, ast.Call)
                and self.call_reaches(v, typed, frozenset())
                for v in values
            )
        }
        verdicts = {
            n
            for n, values in stores.items()
            if values
            and all(
                v is not None and self.verdict_value(v, direct, set(), typed)
                for v in values
            )
        }
        return direct, verdicts

    def core_answer(
        self, test: ast.AST, direct: set[str], verdicts: set[str], typed: set[str]
    ) -> bool:
        """One == or is between a verdict and a Verdict member or string."""
        if not (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], (ast.Eq, ast.Is))
        ):
            return False
        a, b = test.left, test.comparators[0]
        if (
            self.verdict_value(a, direct, verdicts, typed) and self.verdict_token(b)
        ) or (self.verdict_value(b, direct, verdicts, typed) and self.verdict_token(a)):
            return True
        return (self.call_answer(a, direct, typed) and _plain_literal(b)) or (
            self.call_answer(b, direct, typed) and _plain_literal(a)
        )

    def call_answer(self, node: ast.AST, direct: set[str], typed: set[str]) -> bool:
        """A gate call's own answer: the call, a name that only ever holds it,
        or its returncode (the hook script run as a process)."""
        if isinstance(node, ast.Attribute) and node.attr == "returncode":
            node = node.value
        return self.result_value(node, direct, typed)

    def named_answer(
        self, test: ast.AST, direct: set[str], typed: set[str]
    ) -> str | None:
        """The richer forms a real KAT needs, each named in ANSWER_FORMS."""
        if not (isinstance(test, ast.Compare) and len(test.ops) == 1):
            return None
        op, a, b = test.ops[0], test.left, test.comparators[0]

        def field(n: ast.AST, name: str) -> bool:
            return (
                isinstance(n, ast.Attribute)
                and n.attr == name
                and self.result_value(n.value, direct, typed)
            )

        def const(n: ast.AST, kind: type) -> bool:
            return (
                isinstance(n, ast.Constant)
                and isinstance(n.value, kind)
                and (kind is not int or not isinstance(n.value, bool))
            )

        if isinstance(op, ast.In) and const(a, str) and field(b, "reason"):
            return "reason substring"
        if isinstance(op, (ast.Is, ast.Eq)) and field(a, "enforced") and const(b, bool):
            return "enforced flag"
        if (
            isinstance(op, ast.Eq)
            and field(a, "paths")
            and isinstance(b, (ast.Tuple, ast.List))
            and all(const(e, str) for e in b.elts)
        ):
            return "paths literal"
        return None

    def answer_check(self, fn, params: frozenset[str], seed: set[str]):
        """(an accepted answer assert on the straight path, the asserts that
        read the answer in a refused form)."""
        typed = self.typed_names(fn, params)
        results = self.result_names(fn, typed, seed)
        direct, verdicts = self.answer_names(fn, typed, seed)
        refused: list[ast.Assert] = []
        for n in _scope_nodes(fn):
            if (
                isinstance(n, ast.Assert)
                and not self.under_expected_exception(n)
                and self.uses_result(n.test, typed, results)
                and not self.core_answer(n.test, direct, verdicts, typed)
                and self.named_answer(n.test, direct, typed) is None
            ):
                refused.append(n)
        path, _left = self.straight_path(fn.body)
        accepted = any(
            isinstance(s, ast.Assert)
            and self.core_answer(s.test, direct, verdicts, typed)
            and not self.swallowed(s, fn)
            for s in path
        )
        return accepted, refused


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


def _platform_eval(f: _File, node: ast.AST, world: dict, depth: int = 0):
    """The value of a platform-only expression on one platform, or _NO_VALUE."""
    if depth > 20:
        return _NO_VALUE
    d = depth + 1
    atom = _platform_atom(f, node)
    if atom:
        return world.get(atom, _NO_VALUE)
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        vals = f.names.binds.get(node.id, [])
        if len(vals) == 1 and vals[0][0] == "value":
            return _platform_eval(f, vals[0][1], world, d)
        return _NO_VALUE
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        out = [_platform_eval(f, e, world, d) for e in node.elts]
        return _NO_VALUE if any(v is _NO_VALUE for v in out) else tuple(out)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        v = _platform_eval(f, node.operand, world, d)
        return _NO_VALUE if v is _NO_VALUE else not v
    if isinstance(node, ast.BoolOp):
        result = None
        for v_node in node.values:
            v = _platform_eval(f, v_node, world, d)
            if v is _NO_VALUE:
                return _NO_VALUE
            result = v
            if bool(v) == isinstance(node.op, ast.Or):
                return v
        return result
    if isinstance(node, ast.Compare):
        left = _platform_eval(f, node.left, world, d)
        for op, right_node in zip(node.ops, node.comparators):
            right = _platform_eval(f, right_node, world, d)
            if left is _NO_VALUE or right is _NO_VALUE:
                return _NO_VALUE
            try:
                if isinstance(op, (ast.Eq, ast.Is)):
                    ok = left == right
                elif isinstance(op, (ast.NotEq, ast.IsNot)):
                    ok = left != right
                elif isinstance(op, ast.In):
                    ok = left in right
                elif isinstance(op, ast.NotIn):
                    ok = left not in right
                elif isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)):
                    ok = _CMPOPS[type(op)](left, right)
                else:
                    return _NO_VALUE
            except TypeError:
                return _NO_VALUE
            if not ok:
                return False
            left = right
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in ("startswith", "endswith")
        and len(node.args) == 1
        and not node.keywords
    ):
        obj = _platform_eval(f, node.func.value, world, d)
        arg = _platform_eval(f, node.args[0], world, d)
        if isinstance(obj, str) and (
            isinstance(arg, str)
            or (isinstance(arg, tuple) and all(isinstance(a, str) for a in arg))
        ):
            return getattr(obj, node.func.attr)(arg)
    return _NO_VALUE


def _platform_constant(f: _File, node: ast.AST) -> bool | None:
    """True or False when a platform condition has that value on every
    mainstream platform; None when it depends on the platform or is unknown."""
    values = [_platform_eval(f, node, w) for w in _WORLDS]
    if any(v is _NO_VALUE for v in values):
        return None
    truths = {bool(v) for v in values}
    return truths.pop() if len(truths) == 1 else None


def _platform_guard(f: _File, node: ast.AST):
    """(the nearest enclosing if whose test is purely a platform check, and
    whether node sits in its body) or (None, False)."""
    child = node
    while child in f.parents:
        p = f.parents[child]
        if isinstance(p, _SCOPES):
            break
        if isinstance(p, ast.If) and _platform_kind(f, p.test) == "pure":
            return p, child in p.body
        child = p
    return None, False


def _guard_problem(f: _File, node: ast.AST) -> str | None:
    """Why a skip's platform guard decides nothing, or None if it is real. A
    guard false on every platform never fires the skip, so it stays clean."""
    guard, in_body = _platform_guard(f, node)
    if guard is None:
        return None
    const = _platform_constant(f, guard.test)
    if const is not None and const == in_body:
        return "sits under a platform check that is true on every platform, so it always runs"
    return None


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
    if mark == "skipif" and kind == "pure" and _platform_constant(f, parsed) is True:
        _report(
            problems,
            label,
            line,
            "skipif on a platform check that is true on every platform never runs the check",
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


def _irrefutable(pattern: ast.pattern) -> bool:
    """A match pattern that matches every subject: a wildcard or a capture."""
    if isinstance(pattern, ast.MatchAs):
        return pattern.pattern is None or _irrefutable(pattern.pattern)
    if isinstance(pattern, ast.MatchOr):
        return any(_irrefutable(p) for p in pattern.patterns)
    return False


def _builtin_exception(f: _File, node: ast.AST | None) -> type | None:
    """The builtin exception class a name resolves to, or None."""
    if node is None:
        return None
    for r in f.names.resolve(node):
        if r and r.startswith("builtins."):
            cls = getattr(builtins, r.split(".", 1)[1], None)
            if isinstance(cls, type) and issubclass(cls, BaseException):
                return cls
    return None


def _may_catch(f: _File, handler: ast.ExceptHandler, raised: type | None) -> bool:
    """Whether a handler can catch the raised class (yes when unsure)."""
    if handler.type is None or raised is None:
        return True
    kinds = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    for k in kinds:
        cls = _builtin_exception(f, k)
        if cls is None or issubclass(raised, cls):
            return True
    return False


def _uncaught_raise(f: _File, node: ast.Raise, fn) -> bool:
    """A raise in a test that runs on every path and nothing catches. A loop
    over a non-empty constant, ``while True`` and the first case of a match
    whose pattern matches everything run their body; a handler that cannot
    catch the raised class does not stop it."""
    raised = _builtin_exception(
        f, node.exc.func if isinstance(node.exc, ast.Call) else node.exc
    )
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
        elif isinstance(p, (ast.For, ast.AsyncFor)):
            kind, v = f.fold.fold(p.iter, f.fold.at(p))
            try:
                runs = kind == "value" and len(v) > 0  # type: ignore[arg-type]
            except TypeError:
                runs = False
            if not (runs and child in p.body):
                return False
        elif isinstance(p, ast.While):
            if not (f.fold.truth(p.test) == "true" and child in p.body):
                return False
        elif isinstance(p, ast.match_case):
            pass
        elif isinstance(p, ast.Match):
            if not (
                p.cases
                and child is p.cases[0]
                and p.cases[0].guard is None
                and _irrefutable(p.cases[0].pattern)
            ):
                return False
        elif isinstance(p, ast.ExceptHandler):
            return False
        elif (
            (isinstance(p, ast.Try) or type(p).__name__ == "TryStar")
            and child in p.body
            and any(_may_catch(f, h, raised) for h in p.handlers)
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
    return _fiat_exception(f, exc)


def _fiat_exception(f: _File, exc: ast.AST | None, depth: int = 0) -> str | None:
    """What an exception class decides when raised in a KAT: an assert
    failure, a forced exit or a skip, through aliases and same-file
    subclasses."""
    if exc is None or depth > 10:
        return None
    if isinstance(exc, ast.Name) and exc.id in f.classes:
        cls = f.classes[exc.id]
        for base in cls.bases:
            what = _fiat_exception(f, base, depth + 1)
            if what:
                return what
    for r in f.names.resolve(exc):
        if r == "builtins.AssertionError":
            return "raise AssertionError"
        if r in ("builtins.SystemExit", "builtins.KeyboardInterrupt"):
            return "forced exit"
        skip = _skip_kind(r)
        if skip:
            return skip
    return None


def _verdict_members() -> set[str]:
    """Every member of capability_gate.Verdict, read from the real source."""
    path = ROOT / "capability_gate.py"
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return set()
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "Verdict":
            return {
                f"capability_gate.Verdict.{t.id}"
                for s in node.body
                if isinstance(s, ast.Assign)
                for t in s.targets
                if isinstance(t, ast.Name)
            }
    return set()


_VERDICTS = _verdict_members()


# The verdict strings the gate writes, compared as a verdict member's value.
def _plain_literal(node: ast.AST) -> bool:
    """None, a bool, a number or a string written out: the one thing a gate
    call's answer may be compared with."""
    return isinstance(node, ast.Constant) and (
        node.value is None or isinstance(node.value, (bool, int, float, str))
    )


_VERDICT_STRINGS = frozenset({"allow", "deny", "ask"})
# The richer answer forms a real KAT needs beside the verdict comparison.
# Each is accepted only in exactly this shape and never satisfies a KAT on
# its own; the docstring says why each one is safe.
ANSWER_FORMS = (
    "reason substring",
    "enforced flag",
    "paths literal",
)


def _forms(node: ast.AST, depth: int = 0) -> set[str]:
    """Every spelling of one value: the node itself, a walrus as both its
    target and its value, and a one-off display picked by a constant index as
    the element it picks."""
    out = {ast.dump(node, annotate_fields=False)}
    if depth > 20:
        return out
    if isinstance(node, ast.NamedExpr):
        # The target is a store; the reads that follow it are loads of the
        # same name.
        target = ast.Name(id=node.target.id, ctx=ast.Load())
        out |= _forms(target, depth + 1) | _forms(node.value, depth + 1)
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, (ast.Tuple, ast.List))
        and not any(isinstance(e, ast.Starred) for e in node.value.elts)
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, int)
        and not isinstance(node.slice.value, bool)
        and -len(node.value.elts) <= node.slice.value < len(node.value.elts)
    ):
        out |= _forms(node.value.elts[node.slice.value], depth + 1)
    return out


def _same(a: ast.AST, b: ast.AST) -> bool:
    return bool(_forms(a) & _forms(b))


def _display_len(f: _File, node: ast.AST) -> int | None:
    """The length of len(<display>) when the display's shape fixes it: a tuple
    or list with no starred part, or a set or dict with exactly one element."""
    if not (
        isinstance(node, ast.Call)
        and len(node.args) == 1
        and f.names.resolve(node.func) == {"builtins.len"}
    ):
        return None
    arg = node.args[0]
    if isinstance(arg, (ast.Tuple, ast.List)) and not any(
        isinstance(e, ast.Starred) for e in arg.elts
    ):
        return len(arg.elts)
    if (
        isinstance(arg, ast.Set)
        and len(arg.elts) == 1
        and not isinstance(arg.elts[0], ast.Starred)
    ):
        return 1
    if isinstance(arg, ast.Dict) and len(arg.keys) == 1 and arg.keys[0] is not None:
        return 1
    return None


# Calls whose result says nothing about the answer as an assert test.
_NOT_A_CHECK = {"builtins.repr", "builtins.str", "builtins.format", "builtins.hasattr"}


def _len_bound(f: _File, test: ast.Compare) -> bool:
    """``len(x) >= 0`` and the forms that mean it: a length is never negative."""
    op = test.ops[0]
    left, right = test.left, test.comparators[0]

    def is_len(n: ast.AST) -> bool:
        return isinstance(n, ast.Call) and f.names.resolve(n.func) == {"builtins.len"}

    def number(n: ast.AST) -> float | None:
        kind, v = f.fold.fold(n, f.fold.at(n))
        if kind == "value" and isinstance(v, (int, float)) and not isinstance(v, bool):
            return v
        return None

    if is_len(left) and (k := number(right)) is not None:
        return (isinstance(op, ast.GtE) and k <= 0) or (
            isinstance(op, ast.Gt) and k < 0
        )
    if is_len(right) and (k := number(left)) is not None:
        return (isinstance(op, ast.LtE) and k <= 0) or (
            isinstance(op, ast.Lt) and k < 0
        )
    return False


def _nonempty_display(node: ast.AST) -> bool:
    """A display that has an element whatever its parts hold: a plain element,
    or a starred or ``**`` part that is itself a non-empty display. A starred
    part with unknown contents may be empty, so it proves nothing."""
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return any(
            not isinstance(e, ast.Starred) or _nonempty_display(e.value)
            for e in node.elts
        )
    if isinstance(node, ast.Dict):
        return any(
            k is not None or _nonempty_display(v)
            for k, v in zip(node.keys, node.values, strict=True)
        )
    return False


def _truthy_by_construction(f: _File, test: ast.AST) -> bool:
    """A test that holds whatever the gate answered: a provably non-empty
    display, a generator, an f-string or a lambda, repr, str, format or hasattr
    of anything, any() over a display with an element that folds true, and a
    length compared so that no length can fail it."""
    if isinstance(test, (ast.GeneratorExp, ast.JoinedStr, ast.Lambda)):
        return True
    if _nonempty_display(test):
        return True
    if isinstance(test, ast.Call):
        name = f.names.resolve(test.func)
        if name & _NOT_A_CHECK:
            return True
        if (
            name == {"builtins.any"}
            and len(test.args) == 1
            and isinstance(test.args[0], (ast.Tuple, ast.List, ast.Set))
        ):
            for e in test.args[0].elts:
                kind, v = f.fold.fold(e, f.fold.at(e))
                if kind == "value" and v:
                    return True
    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        return _len_bound(f, test)
    return False


def _tautology(f: _File, test: ast.AST) -> bool:
    """An assert whose outcome does not depend on the value it names."""
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return _tautology(f, test.operand)
    if _truthy_by_construction(f, test):
        return True
    if isinstance(test, ast.BoolOp):
        return _side_truth(f, test) is not None
    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        left, right = test.left, test.comparators[0]
        if _same(left, right) and isinstance(
            test.ops[0],
            (ast.Eq, ast.NotEq, ast.Is, ast.IsNot, ast.Lt, ast.LtE, ast.Gt, ast.GtE),
        ):
            return True
        if isinstance(test.ops[0], (ast.In, ast.NotIn)) and isinstance(
            right, (ast.Tuple, ast.List, ast.Set)
        ):
            if any(
                not isinstance(e, ast.Starred) and _same(left, e) for e in right.elts
            ):
                return True
        for sized, other in ((left, right), (right, left)):
            if _display_len(f, sized) is not None:
                kind, _v = f.fold.fold(other, f.fold.at(other))
                if kind == "value":
                    return True
        if (
            isinstance(test.ops[0], (ast.In, ast.NotIn))
            and isinstance(right, (ast.Tuple, ast.List, ast.Set))
            and _VERDICTS
        ):
            named = set()
            for e in right.elts:
                named |= {r for r in f.names.resolve(e) if r}
            if _VERDICTS <= named:
                return True
    if (
        isinstance(test, ast.Call)
        and f.names.resolve(test.func) == {"builtins.isinstance"}
        and len(test.args) == 2
    ):
        kinds = (
            test.args[1].elts if isinstance(test.args[1], ast.Tuple) else [test.args[1]]
        )
        if any(f.names.resolve(k) == {"builtins.object"} for k in kinds):
            return True
    if (
        isinstance(test, ast.Subscript)
        and isinstance(test.value, (ast.Tuple, ast.List))
        and isinstance(test.slice, ast.Constant)
        and isinstance(test.slice.value, int)
        and not isinstance(test.slice.value, bool)
    ):
        elts = test.value.elts
        i = test.slice.value
        if -len(elts) <= i < len(elts):
            kind, _v = f.fold.fold(elts[i], f.fold.at(test))
            return kind == "value" or _tautology(f, elts[i])
    return False


_NEGATED_CMP = {
    ast.Eq: (ast.Eq, True),
    ast.NotEq: (ast.Eq, False),
    ast.Is: (ast.Is, True),
    ast.IsNot: (ast.Is, False),
    ast.In: (ast.In, True),
    ast.NotIn: (ast.In, False),
}


def _literal(f: _File, node: ast.AST, depth: int = 0) -> tuple[str, bool]:
    """A side reduced to a key and a polarity, so a test and its negation share
    the key with opposite polarity: ``not`` flips it, ``bool(x)`` is ``x``,
    ``!=``, ``is not`` and ``not in`` are negated ``==``, ``is`` and ``in``,
    and the operands of ``==`` and ``is`` are put in a fixed order."""
    if depth < 20:
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            key, positive = _literal(f, node.operand, depth + 1)
            return key, not positive
        if (
            isinstance(node, ast.Call)
            and len(node.args) == 1
            and not node.keywords
            and f.names.resolve(node.func) == {"builtins.bool"}
        ):
            return _literal(f, node.args[0], depth + 1)
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            base = _NEGATED_CMP.get(type(node.ops[0]))
            if base is not None:
                op, positive = base
                sides = [
                    ast.dump(node.left, annotate_fields=False),
                    ast.dump(node.comparators[0], annotate_fields=False),
                ]
                if op is not ast.In:
                    sides.sort()
                return f"{op.__name__}:{sides[0]}:{sides[1]}", positive
    return ast.dump(node, annotate_fields=False), True


def _has_pair(f: _File, values: list[ast.AST]) -> bool:
    """Whether some side appears beside its own negation."""
    seen: dict[str, set[bool]] = {}
    for v in values:
        key, positive = _literal(f, v)
        seen.setdefault(key, set()).add(positive)
    return any(len(p) == 2 for p in seen.values())


def _side_truth(f: _File, node: ast.AST, depth: int = 0) -> bool | None:
    """The truth a side of an or/and has whatever the gate answered, or None
    when it depends on the answer. An `or` with an always-true side, or an
    `and` with an always-false side, is decided by that side alone."""
    if depth > 20:
        return None
    d = depth + 1
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        inner = _side_truth(f, node.operand, d)
        return None if inner is None else not inner
    if isinstance(node, ast.BoolOp):
        if _has_pair(f, node.values):
            # A side and its own negation: an or is true, an and is false.
            return isinstance(node.op, ast.Or)
        sides = [_side_truth(f, v, d) for v in node.values]
        if isinstance(node.op, ast.Or):
            if True in sides:
                return True
            return False if all(s is False for s in sides) else None
        if False in sides:
            return False
        return True if all(s is True for s in sides) else None
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        op = node.ops[0]
        if _same(node.left, node.comparators[0]):
            if isinstance(op, (ast.Eq, ast.Is, ast.LtE, ast.GtE)):
                return True
            if isinstance(op, (ast.NotEq, ast.IsNot, ast.Lt, ast.Gt)):
                return False
    if not isinstance(node, ast.BoolOp) and _tautology(f, node):
        kind, v = f.fold.fold(node, f.fold.at(node))
        if kind == "value":
            return bool(v)
        if isinstance(node, ast.Compare) and isinstance(node.ops[0], ast.NotIn):
            return False
        return True
    kind, v = f.fold.fold(node, f.fold.at(node))
    return bool(v) if kind == "value" else None


def _rebound_gate(f: _File, fn) -> ast.AST | None:
    """The first statement in a test that rebinds a gate fixture parameter to
    anything that is not the real gate."""
    params = f.auto_params(fn)
    if not params:
        return None
    typed = f.typed_names(fn, params)
    for n in _scope_nodes(fn):
        if not (
            isinstance(n, ast.Name)
            and n.id in params
            and isinstance(n.ctx, (ast.Store, ast.Del))
        ):
            continue
        p = f.parents.get(n)
        value = None
        if isinstance(p, (ast.Assign, ast.AnnAssign)) and any(
            t is n for t in (p.targets if isinstance(p, ast.Assign) else [p.target])
        ):
            value = p.value
        elif isinstance(p, ast.NamedExpr) and p.target is n:
            value = p.value
        if value is None or not f.makes_gate(value, typed):
            return n
    return None


def lint_source(src: str, label: str, shadowed: bool = False) -> list[str]:
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
                if skip and _is_called(f, n):
                    if not _under_platform_if(f, n):
                        _report(
                            problems,
                            label,
                            n.lineno,
                            f"{skip} in a KAT file outside a platform check never runs the check",
                        )
                    else:
                        why = _guard_problem(f, n)
                        if why:
                            _report(problems, label, n.lineno, f"{skip} {why}")
            if (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == "throw"
                and n.args
                and not f.under_expected_exception(n)
            ):
                thrown = n.args[0]
                what = _fiat_exception(
                    f, thrown.func if isinstance(thrown, ast.Call) else thrown
                )
                if what:
                    _report(
                        problems,
                        label,
                        n.lineno,
                        f"throw {what.removeprefix('raise ')} in a KAT file fails by fiat",
                    )
            if (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == "skipTest"
                and _under_platform_if(f, n)
                and _guard_problem(f, n)
            ):
                _report(
                    problems,
                    label,
                    n.lineno,
                    f"self.skipTest {_guard_problem(f, n)}",
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
            elif _tautology(f, n.test):
                _report(
                    problems,
                    label,
                    n.lineno,
                    "tautological assert in a KAT file never tests the gate's answer",
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

    # pytest keeps the last module-level definition of a name; the lint would
    # judge the first. A second definition is refused outright.
    seen_defs: dict[str, int] = {}
    for s in tree.body:
        if isinstance(s, (*_FUNCS, ast.ClassDef)):
            if s.name in seen_defs:
                _report(
                    problems,
                    label,
                    s.lineno,
                    f"{s.name} is defined more than once in a KAT file; pytest uses the last definition",
                )
            seen_defs.setdefault(s.name, s.lineno)

    for name, fn in f.funcs.items():
        if not name.startswith("test"):
            continue
        where = f"{label}:{fn.lineno} {name}"
        rebound = _rebound_gate(f, fn)
        if rebound is not None:
            problems.append(
                f"{where}: rebinds the gate fixture {rebound.id} at line {rebound.lineno};"
                " the test no longer holds the real gate"
            )
            continue
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
        accepted, refused = f.answer_check(fn, f.auto_params(fn), seed)
        for a in refused:
            _report(
                problems,
                label,
                a.lineno,
                "not an accepted assert on the gate's answer: use one == or is between"
                " the result's verdict and a Verdict member or verdict string",
            )
        if not accepted:
            problems.append(
                f"{where}: never asserts on the gate's result in the accepted form"
                " (one == or is between its verdict and a Verdict member or verdict"
                " string, on the test's straight path)"
            )
    problems += [p for p in lint_hatches(src, label, f) if p not in problems]
    return problems


def _shadowed(path: Path, root: Path) -> bool:
    """A gate module beside the test file would be imported instead of the real one."""
    here = path.resolve().parent
    if here == root.resolve():
        return False
    return (here / "capability_gate.py").exists() or (here / "adapters").is_dir()


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
    # codecs.lookup names every alias of a codec the same way (utf8, U8 and
    # UTF8 are all utf-8).
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
    ap.add_argument(
        "--require-kats",
        action="store_true",
        help="fail when no KAT file is found, so a run cannot pass with nothing to judge",
    )
    a = ap.parse_args(argv)
    files = a.files or discover(a.root)
    every = a.files or test_files(a.root)
    if a.require_kats and not files:
        print("kat lint: no KAT file found; --require-kats needs at least one")
        return 1

    problems = []
    try:
        kats = {p.resolve() for p in files}
        for path in files:
            src, why = _source(path)
            if src is None:
                problems.append(f"{path.as_posix()}:1: {why}")
                continue
            problems += lint_source(src, path.as_posix(), _shadowed(path, a.root))
        for path in every:
            if path.resolve() in kats:
                continue
            src, why = _source(path)
            if src is None:
                problems.append(f"{path.as_posix()}:1: {why}")
                continue
            problems += lint_hatches(src, path.as_posix())
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
