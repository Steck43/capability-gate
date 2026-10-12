"""Live wiring, fast source check. tests/test_hook_behavior.py is the control.

This reads the host entry points with ast and checks tests/wiring_manifest.json,
which maps "<file>::<function>" to the calls that function must make. It is a
fast hint that fails at review time; the behavior tests run the hooks for real
and catch shapes a source read cannot (a rebound gate, a swallowed error).

What counts as a call:

* Only live code. A walk stops at the first unconditional return, raise, or
  process exit in a block, and follows only the taken side of a constant guard
  (``if False:``, ``x if False else y``, ``False and x``).
* A plain spec must be on the straight-line path: inside try and with bodies
  is fine, inside an if, loop, or except handler is not, so a recheck on a rare
  branch cannot stand in for the main call.
* "any:<name>" may sit in a live branch.
* "verdict:<name>" is a straight-line call whose result is assigned to a name
  that a later straight-line ``if`` reads as ``<name>.verdict``, so a decision
  that is computed and then ignored does not count.
* A spec with arguments, such as ``register_hook("pre_tool_call", pre_tool_call)``,
  must match those arguments exactly.

Entries under "_pending" are known gaps, held as strict expected failures until
the wiring lands. A pending entry may only leave "_pending" by moving into the
wired entries; dropping it fails test_read_binding_not_silently_dropped.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads(
    (ROOT / "tests" / "wiring_manifest.json").read_text(encoding="utf-8")
)
WIRED = {k: v for k, v in MANIFEST.items() if k != "_pending"}
PENDING = MANIFEST.get("_pending", {})

HOOKS = ("__init__.py::pre_tool_call", "adapters/claude_code_hook.py::_pre")
REACH = {
    "adapters/claude_code_hook.py::main": "any:_pre",
    "__init__.py::register": 'register_hook("pre_tool_call", pre_tool_call)',
}
READ_BINDING = "any:open_authorized_read"

_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
_EXITS = {"os._exit", "sys.exit", "_exit", "exit", "_deny"}


def _dotted(node: ast.expr) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _const(node: ast.expr) -> tuple[bool, bool]:
    """(is a constant, its truth value)."""
    if isinstance(node, ast.Constant):
        return True, bool(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        known, value = _const(node.operand)
        return known, not value
    return False, False


def _live_children(node: ast.AST) -> list[ast.AST]:
    """Children that can run, pruning constant-guarded branches."""
    if isinstance(node, ast.IfExp):
        known, value = _const(node.test)
        if known:
            return [node.body if value else node.orelse]
    if isinstance(node, ast.BoolOp):
        kept = []
        for v in node.values:
            kept.append(v)
            known, value = _const(v)
            if known and value == isinstance(node.op, ast.Or):
                break
            if known and not value and isinstance(node.op, ast.And):
                break
        return kept
    return [c for c in ast.iter_child_nodes(node) if not isinstance(c, _SCOPES)]


def _calls(node: ast.AST) -> list[ast.Call]:
    """Live calls under node, not descending into nested defs or lambdas."""
    out = []
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, ast.Call):
            out.append(n)
        stack.extend(_live_children(n))
    return out


def _terminates(s: ast.stmt) -> bool:
    if isinstance(s, (ast.Return, ast.Raise)):
        return True
    return (
        isinstance(s, ast.Expr)
        and isinstance(s.value, ast.Call)
        and _dotted(s.value.func) in _EXITS
    )


def _straight(stmts: list[ast.stmt]) -> tuple[list[ast.stmt], bool]:
    """Statements on the straight-line path, and whether the path ended."""
    out: list[ast.stmt] = []
    for s in stmts:
        if isinstance(s, ast.Try):
            inner, ended = _straight(s.body)
            out += inner
            if ended:
                return out, True
            fin, ended = _straight(s.finalbody)
            out += fin
            if ended:
                return out, True
            continue
        if isinstance(s, (ast.With, ast.AsyncWith)):
            out.append(s)
            inner, ended = _straight(s.body)
            out += inner
            if ended:
                return out, True
            continue
        if isinstance(s, ast.If):
            known, value = _const(s.test)
            if known:
                inner, ended = _straight(s.body if value else s.orelse)
                out += inner
                if ended:
                    return out, True
                continue
        if isinstance(s, ast.Match) and _only_wildcard(s):
            out.append(s)
            inner, ended = _straight(s.cases[0].body)
            out += inner
            if ended:
                return out, True
            continue
        out.append(s)
        if _terminates(s):
            return out, True
    return out, False


def _only_wildcard(s: ast.Match) -> bool:
    """A match with one unguarded `case _:` always runs that case."""
    if len(s.cases) != 1 or s.cases[0].guard is not None:
        return False
    pattern = s.cases[0].pattern
    return isinstance(pattern, ast.MatchAs) and pattern.pattern is None


def _shallow_calls(s: ast.stmt) -> list[ast.Call]:
    """Calls a straight-line statement makes itself, not in its nested blocks."""
    if isinstance(s, (ast.With, ast.AsyncWith)):
        return [c for item in s.items for c in _calls(item.context_expr)]
    if isinstance(s, ast.If):
        return _calls(s.test)
    if isinstance(s, (ast.For, ast.AsyncFor, ast.While, ast.Match, *_SCOPES)):
        return []
    return _calls(s)


def _all_live_calls(stmts: list[ast.stmt]) -> list[ast.Call]:
    """Live calls in any branch of a block, stopping where the block ends."""
    out: list[ast.Call] = []
    for s in stmts:
        if isinstance(s, _SCOPES):
            continue
        if isinstance(s, (ast.If, ast.While)):
            known, value = _const(s.test)
            if known:
                block = s.body if value else s.orelse
                out += _all_live_calls(block)
                if isinstance(s, ast.If) and _ends(block):
                    return out
                continue
        out += _shallow_calls(s)
        blocks = [getattr(s, f, None) or [] for f in ("body", "orelse", "finalbody")]
        blocks += [h.body for h in getattr(s, "handlers", None) or []]
        blocks += [c.body for c in getattr(s, "cases", None) or []]
        for block in blocks:
            out += _all_live_calls(block)
        if _terminates(s):
            return out
    return out


def _ends(stmts: list[ast.stmt]) -> bool:
    return _straight(stmts)[1]


def _entry_in(
    tree: ast.Module, func: str, label: str
) -> ast.FunctionDef | ast.AsyncFunctionDef:
    defs = [
        n
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == func
    ]
    assert defs, f"entry point {label} not found"
    assert len(defs) == 1, f"entry point {label} is defined {len(defs)} times"
    return defs[0]


def _entry(entry: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    rel, func = entry.split("::")
    tree = ast.parse((ROOT / rel).read_text(encoding="utf-8"), filename=rel)
    return _entry_in(tree, func, entry)


class _Names:
    """What a call in one function stands for, through the refactors a reader sees.

    A local name bound to another name or attribute (``ev = gate.evaluate``,
    ``g = gate``), ``getattr(x, "attr")`` with a constant name, the gate class
    under an import alias (``_G.evaluate(gate, ...)``), and a same-module helper
    whose straight-line path returns the call (one level of arguments mapped to
    its parameters, up to three helpers deep).
    """

    def __init__(
        self,
        tree: ast.Module,
        fn: ast.FunctionDef | ast.AsyncFunctionDef,
        bound: dict[str, str] | None = None,
        depth: int = 0,
    ) -> None:
        self.tree = tree
        self.depth = depth
        self.helpers = {
            n.name: n
            for n in tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self.gate_class = {"Gate"} | {
            a.asname or a.name
            for n in ast.walk(tree)
            if isinstance(n, ast.ImportFrom)
            for a in n.names
            if a.name == "Gate"
        }
        self.alias = dict(bound or {})
        for n in ast.walk(fn):
            if (
                isinstance(n, ast.Assign)
                and len(n.targets) == 1
                and isinstance(n.targets[0], ast.Name)
                and isinstance(n.value, (ast.Name, ast.Attribute))
                and (d := _dotted(n.value))
            ):
                self.alias[n.targets[0].id] = d

    def resolve(self, dotted: str) -> str:
        for _ in range(5):
            head, dot, rest = dotted.partition(".")
            if head not in self.alias:
                break
            dotted = self.alias[head] + dot + rest
        return dotted

    def of(self, call: ast.Call) -> set[str]:
        f = call.func
        if (
            isinstance(f, ast.Call)
            and isinstance(f.func, ast.Name)
            and f.func.id == "getattr"
            and len(f.args) == 2
            and isinstance(f.args[1], ast.Constant)
            and isinstance(f.args[1].value, str)
            and (target := _dotted(f.args[0]))
        ):
            d: str | None = f"{target}.{f.args[1].value}"
        else:
            d = _dotted(f)
        out: set[str] = set()
        if d:
            d = self.resolve(d)
            out.add(d)
            head, _, rest = d.partition(".")
            if head in self.gate_class and rest and call.args:
                receiver = _dotted(call.args[0])
                if receiver:
                    out.add(f"{self.resolve(receiver)}.{rest}")
        if isinstance(f, ast.Name) and f.id in self.helpers and self.depth < 3:
            out |= self._through_helper(self.helpers[f.id], call)
        return out

    def _through_helper(self, helper: ast.FunctionDef, call: ast.Call) -> set[str]:
        bound = {}
        for param, arg in zip(helper.args.args, call.args):
            if (d := _dotted(arg)) is not None:
                bound[param.arg] = self.resolve(d)
        inner = _Names(self.tree, helper, bound, self.depth + 1)
        straight, _ = _straight(helper.body)
        out: set[str] = set()
        for s in straight:
            if isinstance(s, ast.Return) and isinstance(s.value, ast.Call):
                out |= inner.of(s.value)
        return out

    def matches_name(self, call: ast.Call, name: str) -> bool:
        return any(d == name or d.endswith("." + name) for d in self.of(call))

    def matches(self, call: ast.Call, spec: str) -> bool:
        if "(" not in spec:
            return self.matches_name(call, spec)
        want = ast.parse(spec, mode="eval").body
        assert isinstance(want, ast.Call), spec
        return self.matches_name(call, _dotted(want.func) or "") and [
            ast.dump(a) for a in call.args
        ] == [ast.dump(a) for a in want.args]


def _verdict_checked(stmts: list[ast.stmt], name: str) -> bool:
    for s in stmts:
        if isinstance(s, ast.If):
            for n in ast.walk(s.test):
                if (
                    isinstance(n, ast.Attribute)
                    and n.attr == "verdict"
                    and isinstance(n.value, ast.Name)
                    and n.value.id == name
                ):
                    return True
    return False


def _has(
    tree: ast.Module, fn: ast.FunctionDef | ast.AsyncFunctionDef, spec: str
) -> bool:
    names = _Names(tree, fn)
    if spec.startswith("any:"):
        return any(names.matches(c, spec[4:]) for c in _all_live_calls(fn.body))
    straight, _ = _straight(fn.body)
    if spec.startswith("verdict:"):
        name = spec[len("verdict:") :]
        for i, s in enumerate(straight):
            if (
                isinstance(s, ast.Assign)
                and len(s.targets) == 1
                and isinstance(s.targets[0], ast.Name)
                and isinstance(s.value, ast.Call)
                and names.matches_name(s.value, name)
                and _verdict_checked(straight[i + 1 :], s.targets[0].id)
            ):
                return True
        return False
    return any(names.matches(c, spec) for s in straight for c in _shallow_calls(s))


def _missing(entry: str, specs: list[str]) -> list[str]:
    rel, func = entry.split("::")
    tree = ast.parse((ROOT / rel).read_text(encoding="utf-8"), filename=rel)
    fn = _entry_in(tree, func, entry)
    return [spec for spec in specs if not _has(tree, fn, spec)]


def _missing_src(src: str, func: str, specs: list[str]) -> list[str]:
    tree = ast.parse(src)
    fn = _entry_in(tree, func, func)
    return [spec for spec in specs if not _has(tree, fn, spec)]


def test_manifest_is_not_empty() -> None:
    assert WIRED, "wiring manifest has no wired entries"
    for entry, specs in WIRED.items():
        assert specs, f"{entry} lists no required calls"


def test_manifest_pins_the_gate_call_and_reachability() -> None:
    for hook in HOOKS:
        assert "verdict:gate.evaluate" in WIRED.get(hook, []), hook
    for entry, spec in REACH.items():
        assert spec in WIRED.get(entry, []), entry


@pytest.mark.parametrize("entry", sorted(WIRED))
def test_entry_point_calls_required_protection(entry: str) -> None:
    assert _missing(entry, WIRED[entry]) == []


def test_pending_entries_resolve() -> None:
    # A typo in a pending entry must fail here, not hide as an expected failure.
    for entry in PENDING:
        _entry(entry)


def test_read_binding_not_silently_dropped() -> None:
    for hook in HOOKS:
        assert READ_BINDING in PENDING.get(hook, []) + WIRED.get(hook, []), hook


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="read path not yet bound to opened object; see follow-up PR",
)
@pytest.mark.parametrize("entry", sorted(PENDING))
def test_entry_point_binds_read_to_checked_object(entry: str) -> None:
    assert _missing(entry, PENDING[entry]) == []


# Shapes of a hook body, checked against the same "verdict:gate.evaluate" spec
# the real hooks carry. Correct refactors must pass; unwired look-alikes must not.
_PRELUDE = """
import contextlib
import os

from capability_gate import Gate as _G
from capability_gate import Verdict


def _deny(reason):
    os._exit(2)


def _check(g, *a):
    return g.evaluate(*a)


def _other(g, *a):
    return None


def _early(g, *a):
    return None
    return g.evaluate(*a)


def _discard(g, *a):
    g.evaluate(*a)
    return None

"""
_TAIL = """
    if decision.verdict is not Verdict.ALLOW:
        _deny("blocked")
    os._exit(0)
"""
_HEAD = "def _pre(event):\n    gate = _G({})\n"

CORRECT_SHAPES = {
    "method alias": "    ev = gate.evaluate\n    decision = ev('s', 't', [])\n",
    "class alias": "    decision = _G.evaluate(gate, 's', 't', [])\n",
    "getattr": "    decision = getattr(gate, 'evaluate')('s', 't', [])\n",
    "helper": "    decision = _check(gate, 's', 't', [])\n",
    "local rebinding": "    _gate = gate\n    decision = _gate.evaluate('s', 't', [])\n",
    "match wildcard": (
        "    match event:\n        case _:\n"
        "            decision = gate.evaluate('s', 't', [])\n"
    ),
}

UNWIRED_SHAPES = {
    "alias never called": "    ev = gate.evaluate\n    decision = _other(gate)\n",
    "getattr of another method": "    decision = getattr(gate, 'throw')('s')\n",
    "helper that never calls the gate": "    decision = _other(gate, 's', 't', [])\n",
    "helper that returns first": "    decision = _early(gate, 's', 't', [])\n",
    "helper that discards the decision": "    decision = _discard(gate, 's', 't', [])\n",
    "match on a specific case": (
        "    match event:\n        case 'Read':\n"
        "            decision = gate.evaluate('s', 't', [])\n"
    ),
}


@pytest.mark.parametrize("shape", sorted(CORRECT_SHAPES))
def test_correct_refactor_shapes_pass(shape: str) -> None:
    src = _PRELUDE + _HEAD + CORRECT_SHAPES[shape] + _TAIL
    assert _missing_src(src, "_pre", ["verdict:gate.evaluate"]) == []


@pytest.mark.parametrize("shape", sorted(UNWIRED_SHAPES))
def test_unwired_look_alikes_fail(shape: str) -> None:
    src = _PRELUDE + _HEAD + UNWIRED_SHAPES[shape] + _TAIL
    assert _missing_src(src, "_pre", ["verdict:gate.evaluate"]) == [
        "verdict:gate.evaluate"
    ]
