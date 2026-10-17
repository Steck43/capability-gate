"""Keep local TEST-SOURCE-MAP test locators attached to real Python nodes."""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_MAP = ROOT / "TEST-SOURCE-MAP.md"
PAPER_TEST_ROW = re.compile(
    r"^\| (T-[A-Z]+-\d+) \| `([^`:]+):(\d+)::([A-Za-z_]\w*)` \|",
    re.MULTILINE,
)


def _function_lines(path: Path) -> dict[str, int]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.name: node.lineno
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def test_source_map_nodes_exist() -> None:
    text = SOURCE_MAP.read_text(encoding="utf-8")
    local_rows = PAPER_TEST_ROW.findall(text)
    assert {row[0] for row in local_rows} == {
        "T-COMP-02",
        "T-COMP-05",
        "T-FAIL-01",
        "T-FAIL-03",
        "T-FAIL-04",
        "T-ADV-02",
        "T-ADV-03",
    }

    for test_id, relative, recorded_line, node_name in local_rows:
        path = ROOT / relative
        assert path.is_file(), f"{test_id}: missing {relative}"
        functions = _function_lines(path)
        assert node_name in functions, f"{test_id}: missing {relative}::{node_name}"
        assert functions[node_name] == int(recorded_line), (
            f"{test_id}: {relative}::{node_name} moved to line "
            f"{functions[node_name]}; refresh TEST-SOURCE-MAP.md"
        )
