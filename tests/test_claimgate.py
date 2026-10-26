"""ClaimGate (B7): CI lint on public claims. Not Gate.evaluate.

The repo's own claims file must lint clean; the intentional red fixture must
lint red with OVERREACH. Every rule is checked on a scratch root with its own
enforcement file, test file and mutant registry, so these tests do not depend
on the demo staying as it is.
"""

from __future__ import annotations

import importlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "claimgate"))

cgate = importlib.import_module("claimgate")

GOOD = {
    "claim_id": "X-GOOD",
    "text": "The thing is denied.",
    "status": "REAL",
    "enforcement_path": "pkg/enf.py::Guard.check",
    "evidence": ["tests/test_x.py::test_denies"],
    "pins": ["M-X"],
}


@pytest.fixture()
def scratch(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "enf.py").write_text(
        "class Guard:\n    def check(self):\n        return False\n\n"
        "def helper():\n    return 1\n",
        encoding="utf-8",
    )
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text(
        "def test_denies():\n    pass\n\ndef test_other():\n    pass\n\n"
        "def not_a_test():\n    pass\n",
        encoding="utf-8",
    )
    reg = {
        "mutants": [
            {"id": "M-X", "claim_id": "X-GOOD"},
            {"id": "M-OTHER", "claim_id": "X-OTHER"},
        ]
    }
    (tmp_path / "mutants.yaml").write_text(yaml.safe_dump(reg), encoding="utf-8")
    return tmp_path


def _lint(root: Path, rows, name="claims.yaml"):
    path = root / name
    path.write_text(yaml.safe_dump({"claims": rows}, sort_keys=False), encoding="utf-8")
    return cgate.check_files([path], root, root / "mutants.yaml")


def _codes(findings):
    return sorted({f.code for f in findings})


def _row(**kw):
    row = dict(GOOD)
    row.update(kw)
    return {k: v for k, v in row.items() if v is not _DROP}


_DROP = object()


# --- the repo's own files ------------------------------------------------


def test_repo_claims_file_is_green():
    findings = cgate.check_files(
        [ROOT / "claimgate" / "claims.yaml"],
        ROOT,
        ROOT / cgate.DEFAULT_REGISTRY,
    )
    assert [f.line() for f in findings] == []


def test_repo_claims_every_real_row_has_pins():
    data = yaml.safe_load((ROOT / "claimgate" / "claims.yaml").read_text("utf-8"))
    reg = cgate.load_registry(ROOT / cgate.DEFAULT_REGISTRY)
    real = [r for r in data["claims"] if r["status"] == "REAL"]
    assert len(real) >= 10
    for r in real:
        assert r["pins"], r["claim_id"]
        for p in r["pins"]:
            assert reg[p]["claim_id"] == r["claim_id"]


def test_repo_every_mutant_is_claimed():
    data = yaml.safe_load((ROOT / "claimgate" / "claims.yaml").read_text("utf-8"))
    pinned = {p for r in data["claims"] for p in r.get("pins", [])}
    reg = cgate.load_registry(ROOT / cgate.DEFAULT_REGISTRY)
    assert set(reg) == pinned


def test_red_fixture_is_red_with_overreach():
    findings = cgate.check_files(
        [ROOT / "claimgate" / "fixtures" / "red-overreach.yaml"],
        ROOT,
        ROOT / cgate.DEFAULT_REGISTRY,
    )
    assert "OVERREACH" in _codes(findings)
    assert {f.claim_id for f in findings} == {"RED-KILL-OVERREACH"}


def test_cli_green_and_red_exit_codes():
    ok = subprocess.run(
        [sys.executable, "claimgate/claimgate.py", "check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert ok.returncode == 0, ok.stdout
    red = subprocess.run(
        [
            sys.executable,
            "claimgate/claimgate.py",
            "check",
            "claimgate/fixtures/red-overreach.yaml",
            "--json",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert red.returncode == 1
    assert json.loads(red.stdout)[0]["code"] == "OVERREACH"


def test_cli_unreadable_file_exits_two(tmp_path):
    proc = subprocess.run(
        [
            sys.executable,
            "claimgate/claimgate.py",
            "check",
            str(tmp_path / "nope.yaml"),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2


# --- status ladder -------------------------------------------------------


def test_good_row_is_clean(scratch):
    assert _lint(scratch, [_row()]) == []


def test_overreach_real_without_pins(scratch):
    assert "OVERREACH" in _codes(_lint(scratch, [_row(pins=_DROP)]))


def test_overreach_real_with_empty_evidence(scratch):
    assert "OVERREACH" in _codes(_lint(scratch, [_row(evidence=[])]))


@pytest.mark.parametrize(
    "status,evidence,pins,enforcement,ok",
    [
        (
            "REAL",
            ["tests/test_x.py::test_denies"],
            ["M-X"],
            "pkg/enf.py::Guard.check",
            True,
        ),
        (
            "REAL",
            ["tests/test_x.py::test_denies"],
            [],
            "pkg/enf.py::Guard.check",
            False,
        ),
        ("REAL", [], ["M-X"], "pkg/enf.py::Guard.check", False),
        (
            "PARTIAL",
            ["tests/test_x.py::test_denies"],
            [],
            "pkg/enf.py::Guard.check",
            True,
        ),
        ("PARTIAL", [], [], "pkg/enf.py::Guard.check", False),
        ("PARTIAL", ["tests/test_x.py::test_denies"], [], "pkg/enf.py::Nope", False),
        ("STUBBED", [], [], "pkg/enf.py::helper", True),
        ("STUBBED", [], [], "pkg/enf.py", True),
        ("STUBBED", [], [], "pkg/missing.py", False),
        ("PLANNED", [], [], "", True),
        ("RETIRED", [], [], "", True),
        ("PLANNED", [], [], "pkg/missing.py", True),
    ],
)
def test_status_ladder(scratch, status, evidence, pins, enforcement, ok):
    row = _row(
        status=status, evidence=evidence, pins=pins, enforcement_path=enforcement
    )
    findings = _lint(scratch, [row])
    assert (findings == []) is ok, [f.line() for f in findings]


@pytest.mark.parametrize("declared", ["REAL", "PARTIAL", "STUBBED"])
def test_overreach_from_planned_support(scratch, declared):
    row = _row(status=declared, evidence=[], pins=[], enforcement_path="pkg/none.py")
    assert "OVERREACH" in _codes(_lint(scratch, [row]))


# --- dangling references -------------------------------------------------


@pytest.mark.parametrize(
    "ref",
    [
        "tests/test_x.py::test_missing",
        "tests/test_nope.py::test_denies",
        "tests/test_x.py::not_a_test",
        "tests/test_x.py",
        "test_denies",
        "../outside.py::test_denies",
        "tests/test_x.py::test denies",
        42,
    ],
)
def test_evidence_missing_test_flagged(scratch, ref):
    row = _row(evidence=["tests/test_x.py::test_denies", ref])
    assert "EVIDENCE" in _codes(_lint(scratch, [row]))


@pytest.mark.parametrize(
    "ref",
    [
        "pkg/enf.py::Guard.nope",
        "pkg/enf.py::Nope",
        "pkg/missing.py::Guard",
        "pkg/enf.py::",
        "pkg/enf.txt",
        "/etc/passwd",
        "../x.py",
        "",
    ],
)
def test_enforcement_missing_symbol_flagged(scratch, ref):
    assert "ENFORCEMENT" in _codes(_lint(scratch, [_row(enforcement_path=ref)]))


@pytest.mark.parametrize("pin", ["M-OTHER", "M-NOPE", 7, ""])
def test_pin_wrong_claim_flagged(scratch, pin):
    assert "PIN" in _codes(_lint(scratch, [_row(pins=["M-X", pin])]))


def test_enforcement_syntax_error_file_flagged(scratch):
    (scratch / "pkg" / "bad.py").write_text("def (:\n", encoding="utf-8")
    assert "ENFORCEMENT" in _codes(
        _lint(scratch, [_row(enforcement_path="pkg/bad.py::x")])
    )


# --- wording -------------------------------------------------------------


@pytest.mark.parametrize("word", cgate.THEATER)
@pytest.mark.parametrize("status", ["REAL", "PARTIAL", "PLANNED"])
def test_theater_words(scratch, word, status):
    row = _row(text=f"The gate is {word} here.", status=status)
    if status != "REAL":
        row.pop("pins")
    if status == "PLANNED":
        row.update(evidence=[], enforcement_path="")
    assert "THEATER" in _codes(_lint(scratch, [row]))


@pytest.mark.parametrize("word", ["every", "All", "never", "ALWAYS", "any", "none"])
@pytest.mark.parametrize("status", ["PARTIAL", "STUBBED", "PLANNED"])
def test_absolute_needs_real(scratch, word, status):
    row = _row(text=f"It denies {word} call.", status=status, pins=[])
    if status in ("STUBBED", "PLANNED"):
        row["evidence"] = []
    assert "ABSOLUTE" in _codes(_lint(scratch, [row]))


@pytest.mark.parametrize("word", ["every", "all", "never", "always", "any"])
def test_absolute_allowed_at_real(scratch, word):
    assert _lint(scratch, [_row(text=f"It denies {word} call.")]) == []


@pytest.mark.parametrize("word", ["everything", "allowed", "anyone", "nevertheless"])
def test_absolute_is_whole_word(scratch, word):
    row = _row(text=f"Note {word} here.", status="PARTIAL", pins=[])
    assert "ABSOLUTE" not in _codes(_lint(scratch, [row]))


@pytest.mark.parametrize(
    "text",
    [
        "ClaimGate is Gate.evaluate.",
        "ClaimGate is evaluate under a new name.",
        "claimgate as gate.evaluate",
        "Gate.evaluate renamed to ClaimGate.",
        "evaluate is ClaimGate",
        "ClaimGate = Gate.evaluate",
        "ClaimGate replaces Gate.evaluate.",
    ],
)
def test_name_fence(scratch, text):
    assert "NAME_FENCE" in _codes(_lint(scratch, [_row(text=text)]))


def test_name_fence_runtime_claim_enforced_by_claimgate(scratch):
    (scratch / "claimgate").mkdir()
    (scratch / "claimgate" / "lint.py").write_text("def run():\n    pass\n", "utf-8")
    row = _row(
        text="Each tool call is checked.", enforcement_path="claimgate/lint.py::run"
    )
    assert "NAME_FENCE" in _codes(_lint(scratch, [row]))


@pytest.mark.parametrize(
    "text",
    [
        "ClaimGate lints claims in CI.",
        "Gate.evaluate decides tool calls.",
        "ClaimGate and Gate.evaluate stay apart.",
    ],
)
def test_name_fence_allows_honest_text(scratch, text):
    assert "NAME_FENCE" not in _codes(_lint(scratch, [_row(text=text)]))


@pytest.mark.parametrize("dash", ["\u2014", "\u2013"])
def test_em_dash_refused(scratch, dash):
    assert "STYLE" in _codes(_lint(scratch, [_row(text=f"Denied {dash} logged.")]))


# --- schema --------------------------------------------------------------


@pytest.mark.parametrize("field", cgate.REQUIRED)
def test_missing_required_field(scratch, field):
    assert "SCHEMA" in _codes(_lint(scratch, [_row(**{field: _DROP})]))


@pytest.mark.parametrize("field", ["owner", "Status", "evidences", "pin"])
def test_unknown_field(scratch, field):
    assert "SCHEMA" in _codes(_lint(scratch, [_row(**{field: "x"})]))


@pytest.mark.parametrize(
    "cid", ["x-good", "XGOOD", "X_GOOD", "-X", "X-", "1X-A", "", None, 5, "X GOOD"]
)
def test_bad_claim_id(scratch, cid):
    assert "SCHEMA" in _codes(_lint(scratch, [_row(claim_id=cid)]))


@pytest.mark.parametrize("cid", ["A-B", "CG-KILL-1", "X9-Y9-Z9"])
def test_good_claim_id(scratch, cid):
    reg = {"mutants": [{"id": "M-X", "claim_id": cid}]}
    (scratch / "mutants.yaml").write_text(yaml.safe_dump(reg), encoding="utf-8")
    assert _lint(scratch, [_row(claim_id=cid)]) == []


@pytest.mark.parametrize("status", ["real", "DONE", "SHIPPED", "", None, 4])
def test_bad_status(scratch, status):
    assert "SCHEMA" in _codes(_lint(scratch, [_row(status=status)]))


@pytest.mark.parametrize("text", ["", "   ", None, 3, ["a"], "line one\nline two"])
def test_bad_text(scratch, text):
    assert "SCHEMA" in _codes(_lint(scratch, [_row(text=text)]))


@pytest.mark.parametrize("value", ["tests/test_x.py::test_denies", None, {"a": 1}])
def test_evidence_must_be_list(scratch, value):
    assert "SCHEMA" in _codes(_lint(scratch, [_row(evidence=value)]))


@pytest.mark.parametrize("value", ["M-X", None, {"a": 1}])
def test_pins_must_be_list(scratch, value):
    assert "SCHEMA" in _codes(_lint(scratch, [_row(pins=value)]))


@pytest.mark.parametrize("value", [None, 1, ["a"]])
def test_enforcement_must_be_string(scratch, value):
    assert "SCHEMA" in _codes(_lint(scratch, [_row(enforcement_path=value)]))


def test_row_not_mapping(scratch):
    assert "SCHEMA" in _codes(_lint(scratch, ["just text"]))


def test_duplicate_claim_id_across_files(scratch):
    a = scratch / "a.yaml"
    b = scratch / "b.yaml"
    for p in (a, b):
        p.write_text(yaml.safe_dump({"claims": [_row()]}), encoding="utf-8")
    findings = cgate.check_files([a, b], scratch, scratch / "mutants.yaml")
    assert "DUPLICATE" in _codes(findings)


def test_duplicate_claim_id_in_one_file(scratch):
    assert "DUPLICATE" in _codes(_lint(scratch, [_row(), _row()]))


@pytest.mark.parametrize(
    "body",
    [
        "claims: []\n",
        "claims: {}\n",
        "[]\n",
        "claims: [ ]\nextra: 1\n",
        "other: []\n",
        "",
    ],
)
def test_bad_root(scratch, body):
    p = scratch / "c.yaml"
    p.write_text(body, encoding="utf-8")
    assert "SCHEMA" in _codes(cgate.check_files([p], scratch, scratch / "mutants.yaml"))


def test_duplicate_yaml_key_refused(scratch):
    p = scratch / "c.yaml"
    p.write_text(
        "claims:\n  - claim_id: X-GOOD\n    status: PLANNED\n    status: REAL\n",
        encoding="utf-8",
    )
    with pytest.raises(yaml.YAMLError):
        cgate.check_files([p], scratch, scratch / "mutants.yaml")


def test_missing_registry_means_no_pin_resolves(scratch):
    path = scratch / "c.yaml"
    path.write_text(yaml.safe_dump({"claims": [_row()]}), encoding="utf-8")
    findings = cgate.check_files([path], scratch, scratch / "gone.yaml")
    assert {"PIN", "OVERREACH"} <= set(_codes(findings))


def test_supported_status_direct(scratch):
    res = cgate.Resolver(scratch, cgate.load_registry(scratch / "mutants.yaml"))
    assert cgate.supported_status(_row(), res) == "REAL"
    assert cgate.supported_status(_row(pins=[]), res) == "PARTIAL"
    assert cgate.supported_status(_row(pins=[], evidence=[]), res) == "STUBBED"
    assert (
        cgate.supported_status(_row(pins=[], evidence=[], enforcement_path="x.py"), res)
        == "PLANNED"
    )


def test_finding_line_shape():
    f = cgate.Finding("X-A", "OVERREACH", "msg")
    assert f.line() == "ERROR X-A OVERREACH: msg"
