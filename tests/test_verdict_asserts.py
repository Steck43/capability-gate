"""Every test in the kill switch's known-answer file asserts the gate's verdict.

A test there that only reads the log or the marker passes whatever the gate
decides, so it is not a known-answer test of the gate. Each test must hold at
least one ``assert <answer>.verdict is Verdict.<MEMBER>``, where the answer is
a gate call or a name bound to one. Tests about the marker and the log alone
live in tests/test_halt_marker.py.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOF = Path(__file__).resolve().parents[1]
KAT_FILE = ROOF / "tests" / "test_kill_switch.py"
TREE = ast.parse(KAT_FILE.read_text(encoding="utf-8"))
TESTS = [
    n
    for n in TREE.body
    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    and n.name.startswith("test")
]


def _verdict_identity(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Assert)
        and isinstance(node.test, ast.Compare)
        and len(node.test.ops) == 1
        and isinstance(node.test.ops[0], ast.Is)
        and isinstance(node.test.left, ast.Attribute)
        and node.test.left.attr == "verdict"
        and isinstance(node.test.left.value, (ast.Name, ast.Call))
        and isinstance(node.test.comparators[0], ast.Attribute)
        and isinstance(node.test.comparators[0].value, ast.Name)
        and node.test.comparators[0].value.id == "Verdict"
    )


def test_the_kat_file_has_tests() -> None:
    assert TESTS, f"no test functions found in {KAT_FILE.name}"


@pytest.mark.parametrize("fn", TESTS, ids=[t.name for t in TESTS])
def test_each_kat_asserts_the_gate_verdict(fn: ast.FunctionDef) -> None:
    assert any(_verdict_identity(n) for n in ast.walk(fn)), (
        f"{fn.name} never asserts a gate verdict by identity; it belongs in "
        "tests/test_halt_marker.py, or it must assert the answer it pins"
    )
