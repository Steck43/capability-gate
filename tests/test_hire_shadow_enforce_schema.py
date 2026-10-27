"""Shadow to enforce metric template: the JSON Schema and its validation only.

No command at this commit emits these metrics. The tests check the schema
accepts the shipped template and a document filled from a real S12 run, and
refuses each missing, mistyped, out-of-range or unknown field. The validator
below covers the keyword subset the schema uses; a test pins that subset, and
the jsonschema package cross-checks it (pinned in requirements-ci.lock, so the
cross-check runs in CI and fails rather than skips when jsonschema is missing).
"""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HIRE = ROOT / "demos" / "hire"
SCHEMA = json.loads(
    (HIRE / "shadow_enforce_metrics.schema.json").read_text(encoding="utf-8")
)
EXAMPLE = json.loads(
    (HIRE / "shadow_enforce_metrics.example.json").read_text(encoding="utf-8")
)

KNOWN = {
    "$schema",
    "$id",
    "title",
    "description",
    "type",
    "additionalProperties",
    "required",
    "properties",
    "const",
    "enum",
    "minimum",
    "minLength",
    "maxLength",
    "pattern",
    "format",
}
_TYPES = {
    "object": lambda v: isinstance(v, dict),
    "string": lambda v: isinstance(v, str),
    "boolean": lambda v: isinstance(v, bool),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
}


def errors(schema: dict, doc, path: str = "$") -> list[str]:
    out: list[str] = []
    t = schema.get("type")
    if t is not None and not _TYPES[t](doc):
        return [f"{path}: not {t}"]
    if "const" in schema and doc != schema["const"]:
        out.append(f"{path}: not const")
    if "enum" in schema and doc not in schema["enum"]:
        out.append(f"{path}: not in enum")
    if isinstance(doc, str):
        if len(doc) < schema.get("minLength", 0):
            out.append(f"{path}: too short")
        if "maxLength" in schema and len(doc) > schema["maxLength"]:
            out.append(f"{path}: too long")
        if "pattern" in schema and not re.search(schema["pattern"], doc):
            out.append(f"{path}: pattern")
    if "minimum" in schema and isinstance(doc, int) and doc < schema["minimum"]:
        out.append(f"{path}: below minimum")
    if isinstance(doc, dict):
        props = schema.get("properties", {})
        for k in schema.get("required", []):
            if k not in doc:
                out.append(f"{path}.{k}: required")
        if schema.get("additionalProperties") is False:
            out += [f"{path}.{k}: unknown" for k in doc if k not in props]
        for k, sub in props.items():
            if k in doc:
                out += errors(sub, doc[k], f"{path}.{k}")
    return out


def _walk(schema: dict, path: tuple = ()):
    yield path, schema
    for k, sub in schema.get("properties", {}).items():
        yield from _walk(sub, (*path, k))


NODES = list(_walk(SCHEMA))
REQUIRED_PATHS = [(*p, r) for p, node in NODES for r in node.get("required", [])]
LEAVES = [(p, n) for p, n in NODES if p and "properties" not in n]
OBJECTS = [(p, n) for p, n in NODES if "properties" in n]


def _get(doc, path):
    for k in path:
        doc = doc[k]
    return doc


def _set(doc, path, value):
    _get(doc, path[:-1])[path[-1]] = value


def _del(doc, path):
    del _get(doc, path[:-1])[path[-1]]


def test_schema_uses_only_known_keywords():
    for _, node in NODES:
        assert set(node) <= KNOWN, set(node) - KNOWN


def test_schema_is_closed_at_every_object():
    for p, node in OBJECTS:
        assert node.get("additionalProperties") is False, p
        assert node.get("required"), p


def test_example_template_validates():
    assert errors(SCHEMA, EXAMPLE) == []


def test_example_template_has_no_dash_or_real_names():
    text = json.dumps(EXAMPLE) + json.dumps(SCHEMA)
    assert "\u2014" not in text and "\u2013" not in text
    assert "example.invalid" in text


@pytest.mark.parametrize(
    "path", REQUIRED_PATHS, ids=[".".join(p) for p in REQUIRED_PATHS]
)
def test_missing_required_field_is_refused(path):
    doc = copy.deepcopy(EXAMPLE)
    _del(doc, path)
    assert any("required" in e for e in errors(SCHEMA, doc))


@pytest.mark.parametrize(
    "path", [p for p, _ in OBJECTS], ids=[".".join(p) or "$" for p, _ in OBJECTS]
)
def test_unknown_key_is_refused(path):
    doc = copy.deepcopy(EXAMPLE)
    _get(doc, path)["unexpected"] = 1
    assert any("unknown" in e for e in errors(SCHEMA, doc))


WRONG_VALUES = [None, "", "x", -1, 1.5, True, [], {}]


def _bad_for(node: dict, value) -> bool:
    return bool(errors(node, value))


LEAF_CASES = [(p, v) for p, n in LEAVES for v in WRONG_VALUES if _bad_for(n, v)]


@pytest.mark.parametrize(
    ("path", "value"),
    LEAF_CASES,
    ids=[f"{'.'.join(p)}={v!r}" for p, v in LEAF_CASES],
)
def test_wrong_leaf_value_is_refused(path, value):
    doc = copy.deepcopy(EXAMPLE)
    _set(doc, path, value)
    assert errors(SCHEMA, doc)


def test_every_leaf_has_at_least_two_refused_values():
    for p, n in LEAVES:
        assert sum(1 for v in WRONG_VALUES if _bad_for(n, v)) >= 2, p


@pytest.mark.parametrize(
    "stamp",
    [
        "2026-10-26",
        "2026-10-26 00:00:00Z",
        "26-10-2026T00:00:00Z",
        "2026-10-26T00:00:00",
        "now",
    ],
)
def test_bad_timestamp_is_refused(stamp):
    doc = copy.deepcopy(EXAMPLE)
    doc["window"]["start"] = stamp
    assert errors(SCHEMA, doc)


@pytest.mark.parametrize(
    "stamp",
    ["2026-10-26T00:00:00Z", "2026-10-26T00:00:00.123Z", "2026-10-26T00:00:00-07:00"],
)
def test_good_timestamp_accepts(stamp):
    doc = copy.deepcopy(EXAMPLE)
    doc["promotion"]["decided_at"] = stamp
    assert errors(SCHEMA, doc) == []


@pytest.mark.parametrize(
    "decision", ["promote", "enforce", "STAY_SHADOW", "auto_promote"]
)
def test_unknown_promotion_decision_is_refused(decision):
    doc = copy.deepcopy(EXAMPLE)
    doc["promotion"]["decision"] = decision
    assert errors(SCHEMA, doc)


def test_optional_decision_record_digest_accepts():
    doc = copy.deepcopy(EXAMPLE)
    doc["promotion"]["decision_record_sha256"] = "a" * 64
    assert errors(SCHEMA, doc) == []


# --- filled from a real S12 run ----------------------------------------------


def _from_s12() -> dict:
    sys.path.insert(0, str(ROOT / "demos"))
    st = importlib.import_module("synthtraffic")
    res = st.run_scenario(
        st.load_scenario(ROOT / "demos" / "scenarios" / "S12-shadow-vs-enforce.yaml")
    )
    assert res["status"] == "PASS"
    a = res["actual"]
    doc = copy.deepcopy(EXAMPLE)
    doc["scope"]["policy_sha256"] = hashlib.sha256(b"S12 demo policy").hexdigest()
    doc["shadow"] = {
        "calls": res["events"],
        "would_block": a["shadow_would_block"],
        "executed": a["shadow_executed"],
    }
    doc["enforce"] = {
        "calls": res["events"],
        "blocked": a["enforce_blocked"],
        "risky_executed": a["enforce_risky_executed"],
    }
    doc["agreement"]["flagged_sets_identical"] = bool(a["flagged_sets_identical"])
    return doc


def test_document_filled_from_s12_validates():
    doc = _from_s12()
    assert errors(SCHEMA, doc) == []
    assert doc["enforce"]["risky_executed"] == 0
    assert doc["shadow"]["executed"] == doc["shadow"]["calls"]


def test_jsonschema_cross_check():
    jsonschema = importlib.import_module("jsonschema")
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    v = jsonschema.Draft202012Validator(SCHEMA)
    assert list(v.iter_errors(EXAMPLE)) == []
    for path in REQUIRED_PATHS:
        doc = copy.deepcopy(EXAMPLE)
        _del(doc, path)
        assert list(v.iter_errors(doc)), path
    for path, value in LEAF_CASES:
        doc = copy.deepcopy(EXAMPLE)
        _set(doc, path, value)
        assert list(v.iter_errors(doc)), (path, value)


# --- the contract, written out so a schema edit that drops it goes red -------

CONTRACT_REQUIRED = [
    ("schema_version",),
    ("window", "start"),
    ("window", "end"),
    ("scope", "skill"),
    ("scope", "policy_sha256"),
    ("scope", "log_head"),
    ("shadow", "calls"),
    ("shadow", "would_block"),
    ("shadow", "executed"),
    ("enforce", "calls"),
    ("enforce", "blocked"),
    ("enforce", "risky_executed"),
    ("agreement", "flagged_sets_identical"),
    ("promotion", "decision"),
    ("promotion", "approver"),
    ("promotion", "decided_at"),
]


@pytest.mark.parametrize(
    "path", CONTRACT_REQUIRED, ids=[".".join(p) for p in CONTRACT_REQUIRED]
)
def test_contract_field_is_required(path):
    doc = copy.deepcopy(EXAMPLE)
    _del(doc, path)
    assert errors(SCHEMA, doc), path


@pytest.mark.parametrize("path", [(), ("shadow",), ("enforce",), ("promotion",)])
def test_contract_object_is_closed(path):
    doc = copy.deepcopy(EXAMPLE)
    _get(doc, path)["auto_promote"] = True
    assert errors(SCHEMA, doc), path


@pytest.mark.parametrize("path", [("enforce", "risky_executed"), ("shadow", "calls")])
def test_contract_count_is_non_negative(path):
    doc = copy.deepcopy(EXAMPLE)
    _set(doc, path, -1)
    assert errors(SCHEMA, doc), path
