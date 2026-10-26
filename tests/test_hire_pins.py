"""Fail-when-removed pins: the registry is well formed, every claim the demo
asserts at REAL is pinned, and each mutant really turns its tests red.

test_mutant_is_killed runs every mutant in a scratch copy of the tree, so CI
goes red the day a control stops being load-bearing for its claim.
"""

from __future__ import annotations

import ast
import importlib
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "demos" / "hire"))

pins = importlib.import_module("pins")

MUTANTS = pins.load()
IDS = [m["id"] for m in MUTANTS]
CLAIMS = yaml.safe_load((ROOT / "claimgate" / "claims.yaml").read_text("utf-8"))[
    "claims"
]


@pytest.mark.parametrize("mutant", MUTANTS, ids=IDS)
def test_mutant_find_text_occurs_once(mutant):
    text = (ROOT / mutant["file"]).read_text(encoding="utf-8")
    assert text.count(mutant["find"]) == 1
    assert mutant["find"] != mutant["replace"]


@pytest.mark.parametrize("mutant", MUTANTS, ids=IDS)
def test_mutant_tests_exist(mutant):
    assert mutant["tests"]
    for node in mutant["tests"]:
        path, name = node.split("::")
        tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
        names = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
        assert name in names, node


@pytest.mark.parametrize("mutant", MUTANTS, ids=IDS)
def test_mutant_claim_exists_and_lists_it(mutant):
    rows = [c for c in CLAIMS if c["claim_id"] == mutant["claim_id"]]
    assert len(rows) == 1
    assert mutant["id"] in rows[0].get("pins", [])


@pytest.mark.parametrize("mutant", MUTANTS, ids=IDS)
def test_mutant_is_killed(mutant):
    res = pins.run_one(mutant)
    assert res.verdict == "KILLED", res.detail


def test_every_demo_claim_at_real_is_pinned():
    real = [c for c in CLAIMS if c["status"] == "REAL"]
    assert real
    for c in real:
        assert c.get("pins"), c["claim_id"]


def test_registry_ids_unique():
    assert len(IDS) == len(set(IDS))


def test_identity_mutant_survives(tmp_path):
    m = dict(MUTANTS[0])
    m["id"] = "M-IDENTITY"
    m["replace"] = m["find"]
    assert pins.run_one(m).verdict == "SURVIVED"


def test_missing_find_is_broken():
    m = dict(MUTANTS[0])
    m["id"] = "M-MISSING"
    m["find"] = "this text is not in the gate\n"
    res = pins.run_one(m)
    assert res.verdict == "BROKEN"
    assert "0 times" in res.detail


def test_apply_refuses_repeated_find(tmp_path):
    (tmp_path / "f.py").write_text("x = 1\nx = 1\n", encoding="utf-8")
    why = pins.apply(tmp_path, {"file": "f.py", "find": "x = 1\n", "replace": "y\n"})
    assert "2 times" in why
    assert (tmp_path / "f.py").read_text(encoding="utf-8") == "x = 1\nx = 1\n"


def test_apply_missing_file(tmp_path):
    assert "missing" in pins.apply(
        tmp_path, {"file": "nope.py", "find": "a", "replace": "b"}
    )


def test_render_counts():
    r = pins.PinResult("M-A", "C-A", "f.py", ["t::test_a"], "KILLED", "")
    s = pins.PinResult("M-B", "C-B", "f.py", ["t::test_b"], "SURVIVED", "")
    text = pins.render([r, s])
    assert "KILLED 1 of 2." in text
    assert "| M-B | C-B |" in text


def test_working_tree_untouched_by_pin_run():
    before = (ROOT / "capability_gate.py").read_bytes()
    pins.run_one(MUTANTS[0])
    assert (ROOT / "capability_gate.py").read_bytes() == before
