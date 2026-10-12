"""Live wiring: each host entry point must call the protection it relies on.

A fix that exists in capability_gate.py but is never called from the hook the
host actually runs protects nothing. This reads the entry points with ast and
checks tests/wiring_manifest.json, which maps "<file>::<function>" to the
callees that function must reach directly.

A plain callee must sit on the function's straight-line path: inside try and
with blocks is fine, inside an if, loop, or except handler is not. That keeps a
second call on a rare branch (for example the observe-to-enforce recheck) from
standing in for the main one. A callee written "any:<name>" may sit in a branch,
for protections that apply to some tools only. Entries under "_pending" are
known gaps, held as strict expected failures until the wiring lands.
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

_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


def _dotted(node: ast.expr) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _calls(node: ast.AST) -> set[str]:
    """Call names under node, not descending into nested defs or lambdas."""
    out = set()
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, ast.Call) and (name := _dotted(n.func)):
            out.add(name)
        stack.extend(c for c in ast.iter_child_nodes(n) if not isinstance(c, _SCOPES))
    return out


def _straight_line_calls(stmts: list[ast.stmt]) -> set[str]:
    out: set[str] = set()
    for s in stmts:
        if isinstance(s, ast.Try):
            out |= _straight_line_calls(s.body) | _straight_line_calls(s.finalbody)
        elif isinstance(s, (ast.With, ast.AsyncWith)):
            for item in s.items:
                out |= _calls(item.context_expr)
            out |= _straight_line_calls(s.body)
        elif isinstance(s, ast.If):
            out |= _calls(s.test)
        elif isinstance(s, (ast.For, ast.AsyncFor, ast.While, ast.Match, *_SCOPES)):
            continue
        else:
            out |= _calls(s)
    return out


def _entry(entry: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    rel, func = entry.split("::")
    tree = ast.parse((ROOT / rel).read_text(encoding="utf-8"), filename=rel)
    defs = [
        n
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == func
    ]
    assert defs, f"entry point {entry} not found"
    assert len(defs) == 1, f"entry point {entry} is defined {len(defs)} times"
    return defs[0]


def _missing(entry: str, callees: list[str]) -> list[str]:
    fn = _entry(entry)
    anywhere = set().union(*(_calls(s) for s in fn.body))
    straight = _straight_line_calls(fn.body)
    missing = []
    for spec in callees:
        name = spec.removeprefix("any:")
        pool = anywhere if spec.startswith("any:") else straight
        if not any(x == name or x.endswith("." + name) for x in pool):
            missing.append(spec)
    return missing


def test_manifest_names_both_host_entry_points() -> None:
    assert "__init__.py::pre_tool_call" in WIRED
    assert "adapters/claude_code_hook.py::_pre" in WIRED


@pytest.mark.parametrize("entry", sorted(WIRED))
def test_entry_point_calls_required_protection(entry: str) -> None:
    assert _missing(entry, WIRED[entry]) == []


@pytest.mark.xfail(
    strict=True, reason="read path not yet bound to opened object; see follow-up PR"
)
@pytest.mark.parametrize("entry", sorted(PENDING))
def test_entry_point_binds_read_to_checked_object(entry: str) -> None:
    assert _missing(entry, PENDING[entry]) == []
