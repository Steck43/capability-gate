"""control_check: an old vs new policy diff that refuses a change dropping a
required control. DENY for a mandatory control, ASK for an adopted one."""

from __future__ import annotations

import copy
import json
import random
from pathlib import Path

import pytest

import control_check as cc
from capability_gate import PolicyError, load_policy, load_yaml_mapping

ROOT = Path(__file__).resolve().parent.parent
CATALOG = cc.load_catalog(
    load_yaml_mapping((ROOT / "controls/catalog.yaml").read_text())
)
PROFILE_TEXT = (ROOT / "controls/profile.example.yaml").read_text()
PROFILE = cc.load_profile(load_yaml_mapping(PROFILE_TEXT), CATALOG)

BASE = {
    "version": 1,
    "require_approval": ["terminal", "execute_code"],
    "skills": {
        "notes": {
            "tools": ["read_file", "write_file", "terminal"],
            "paths": ["/srv/notes/**"],
        },
        "research": {
            "tools": ["read_file", "web_search"],
            "paths": ["/srv/research/**"],
        },
    },
}


def _pol(m):
    return load_policy(m)


def _run(new, old=BASE, profile=PROFILE, old_profile=None):
    return cc.check(_pol(old), _pol(new), profile, CATALOG, old_profile)


def _edit(fn):
    m = copy.deepcopy(BASE)
    fn(m)
    return m


def _status(report, key):
    return next(c for c in report["controls"] if c["control"] == key)


def _profile(rows):
    return cc.load_profile({"version": 1, "requires": rows}, CATALOG)


# The verdict on each kind of change


def test_unchanged_policy_allows():
    r = _run(BASE)
    assert r["verdict"] == "ALLOW"
    assert {c["status"] for c in r["controls"]} == {"KEPT"}


def test_granted_tool_dropped_from_approval_denies():
    """Review finding F2: terminal granted and removed from require_approval went ASK to ALLOW silently."""
    r = _run(_edit(lambda m: m["require_approval"].remove("terminal")))
    assert r["verdict"] == "DENY"
    art14 = _status(r, "eu-ai-act-art-14-4")
    assert (art14["status"], art14["verdict"]) == ("DROPPED", "DENY")
    assert any("terminal" in w for w in art14["why"])


def test_same_drop_under_an_adopted_control_asks():
    prof = _profile(
        [
            {
                "control": "atlas-aml-m0029",
                "level": "adopted",
                "obligations": {"approval_for": ["terminal"]},
            }
        ]
    )
    r = _run(_edit(lambda m: m["require_approval"].remove("terminal")), profile=prof)
    assert r["verdict"] == "ASK"


def test_approval_dropped_for_a_tool_no_skill_grants_allows():
    """Review correction: an approval for an ungranted tool is inert, so dropping it widens nothing."""
    r = _run(_edit(lambda m: m["require_approval"].remove("execute_code")))
    assert r["verdict"] == "ALLOW"


def test_new_tool_grant_is_widening():
    r = _run(_edit(lambda m: m["skills"]["research"]["tools"].append("write_file")))
    assert r["verdict"] == "ASK"
    assert _status(r, "atlas-aml-m0028")["status"] == "DROPPED"
    assert any(
        "gains tool 'write_file'" in w for w in _status(r, "atlas-aml-m0028")["why"]
    )


def test_new_path_glob_is_widening():
    r = _run(_edit(lambda m: m["skills"]["notes"]["paths"].append("/srv/**")))
    assert any(
        "gains path '/srv/**'" in w for w in _status(r, "atlas-aml-m0028")["why"]
    )
    assert r["verdict"] == "ASK"


def test_new_skill_is_widening():
    r = _run(
        _edit(
            lambda m: m["skills"].update({"ops": {"tools": ["read_file"], "paths": []}})
        )
    )
    assert any(
        "new skill 'ops'" in w for w in _status(r, "owasp-llm-2026-llm03")["why"]
    )


def test_changed_glob_counts_as_new_even_when_narrower():
    r = _run(
        _edit(lambda m: m["skills"]["notes"].update({"paths": ["/srv/notes/a/**"]}))
    )
    assert r["verdict"] == "ASK"


def test_granting_a_never_granted_tool_asks_or_denies_by_level():
    r = _run(_edit(lambda m: m["skills"]["research"]["tools"].append("execute_code")))
    assert _status(r, "iso-27001-a-8-2")["verdict"] == "ASK"
    prof = _profile(
        [
            {
                "control": "eu-ai-act-art-14-4",
                "level": "mandatory",
                "obligations": {"never_granted": ["execute_code"]},
            }
        ]
    )
    assert (
        _run(
            _edit(lambda m: m["skills"]["research"]["tools"].append("execute_code")),
            profile=prof,
        )["verdict"]
        == "DENY"
    )


def test_control_unmet_before_and_after_is_unmet_not_allowed():
    old = _edit(lambda m: m["require_approval"].remove("terminal"))
    r = _run(old, old=old)
    art14 = _status(r, "eu-ai-act-art-14-4")
    assert (art14["status"], r["verdict"]) == ("UNMET", "DENY")


def test_narrowing_allows():
    def narrow(m):
        m["skills"]["notes"]["tools"].remove("write_file")
        m["skills"]["research"]["paths"] = []
        del m["skills"]["notes"]

    assert _run(_edit(narrow))["verdict"] == "ALLOW"


# Property: narrowing never flags, any single widening always does


def _random_narrowing(rng, m):
    for name in list(m["skills"]):
        rule = m["skills"][name]
        if rng.random() < 0.2:
            del m["skills"][name]
            continue
        rule["tools"] = [t for t in rule["tools"] if rng.random() < 0.7]
        rule["paths"] = [p for p in rule["paths"] if rng.random() < 0.7]
    m["require_approval"] += [
        t for t in ("patch", "search_files") if rng.random() < 0.5
    ]


def _random_widening(rng, m):
    kind = rng.choice(["tool", "path", "skill", "approval"])
    if kind == "tool":
        m["skills"][rng.choice(sorted(m["skills"]))]["tools"].append(
            f"tool_{rng.randrange(1000)}"
        )
    elif kind == "path":
        m["skills"][rng.choice(sorted(m["skills"]))]["paths"].append(
            f"/w/{rng.randrange(1000)}/**"
        )
    elif kind == "skill":
        m["skills"][f"s{rng.randrange(1000)}"] = {"tools": [], "paths": []}
    else:
        m["require_approval"].remove("terminal")


@pytest.mark.parametrize("seed", range(40))
def test_property_narrowing_is_never_widening(seed):
    rng = random.Random(seed)
    new = _edit(lambda m: _random_narrowing(rng, m))
    assert cc.widening(_pol(BASE), _pol(new)) == []
    assert _run(new)["verdict"] == "ALLOW"


@pytest.mark.parametrize("seed", range(40))
def test_property_any_widening_is_flagged(seed):
    rng = random.Random(seed)
    new = _edit(lambda m: _random_widening(rng, m))
    assert cc.widening(_pol(BASE), _pol(new)) != []
    assert _run(new)["verdict"] != "ALLOW"


# The profile itself


def test_profile_dropping_a_required_control_denies():
    smaller = {k: v for k, v in PROFILE.items() if k != "eu-ai-act-art-14-4"}
    r = _run(BASE, profile=smaller, old_profile=PROFILE)
    assert r["verdict"] == "DENY"
    assert _status(r, "eu-ai-act-art-14-4")["status"] == "PROFILE_DROPPED"


def test_profile_downgrading_a_control_denies():
    up = dict(PROFILE)
    up["atlas-aml-m0028"] = cc.Required(
        "atlas-aml-m0028", "mandatory", PROFILE["atlas-aml-m0028"].obligations
    )
    assert _run(BASE, profile=PROFILE, old_profile=up)["verdict"] == "DENY"


def test_profile_raising_a_control_allows():
    up = dict(PROFILE)
    up["atlas-aml-m0028"] = cc.Required(
        "atlas-aml-m0028", "mandatory", PROFILE["atlas-aml-m0028"].obligations
    )
    assert _run(BASE, profile=up, old_profile=PROFILE)["verdict"] == "ALLOW"


def test_profile_with_weakened_obligations_denies():
    gutted = _profile(
        [
            {
                "control": key,
                "level": req.level,
                "obligations": {"approval_for": ["no_such_tool"]},
            }
            for key, req in PROFILE.items()
        ]
    )
    new = _edit(lambda m: m["require_approval"].remove("terminal"))
    r = _run(new, profile=gutted, old_profile=PROFILE)
    assert r["verdict"] == "DENY"
    dropped = {
        c["control"]: c["why"]
        for c in r["controls"]
        if c["status"] == "PROFILE_DROPPED"
    }
    assert dropped == {key: ["obligations weakened"] for key in PROFILE}


def test_approval_for_a_tool_no_policy_grants_is_a_warning():
    typo = _profile(
        [
            {
                "control": "atlas-aml-m0029",
                "level": "adopted",
                "obligations": {"approval_for": ["termnal"]},
            }
        ]
    )
    r = _run(BASE, profile=typo)
    assert r["verdict"] == "ALLOW"
    assert r["warnings"] == [
        "atlas-aml-m0029: approval_for names 'termnal', which neither policy grants"
    ]
    assert _run(BASE)["warnings"] == [
        f"{key}: approval_for names 'execute_code', which neither policy grants"
        for key in ("eu-ai-act-art-14-4", "atlas-aml-m0029")
    ]


def test_same_profile_on_both_sides_allows():
    assert _run(BASE, profile=PROFILE, old_profile=PROFILE)["verdict"] == "ALLOW"


# Isolation counts as a control

NO_NEW_GRANTS = [
    {
        "control": "atlas-aml-m0028",
        "level": "mandatory",
        "obligations": {"no_new_grants": True},
    }
]
ISOLATED = _edit(
    lambda m: (m.update(isolate=["terminal"]), m["require_approval"].remove("terminal"))
)
HOST = _edit(lambda m: m["require_approval"].remove("terminal"))


def test_tool_taken_out_of_isolate_is_widening():
    r = _run(HOST, old=ISOLATED, profile=_profile(NO_NEW_GRANTS))
    assert r["verdict"] == "DENY"
    assert _status(r, "atlas-aml-m0028")["why"] == [
        "tool 'terminal' leaves isolate while still granted"
    ]


def test_tool_put_into_isolate_allows():
    r = _run(ISOLATED, old=HOST, profile=_profile(NO_NEW_GRANTS))
    assert r["verdict"] == "ALLOW"


# Load errors fail loudly

BAD_PROFILES = [
    {"version": 1, "requires": []},
    {
        "version": 2,
        "requires": [
            {
                "control": "atlas-aml-m0028",
                "level": "adopted",
                "obligations": {"no_new_grants": True},
            }
        ],
    },
    {
        "version": 1,
        "requires": [
            {
                "control": "no-such-control",
                "level": "adopted",
                "obligations": {"no_new_grants": True},
            }
        ],
    },
    {
        "version": 1,
        "requires": [
            {
                "control": "atlas-aml-m0028",
                "level": "advisory",
                "obligations": {"no_new_grants": True},
            }
        ],
    },
    {
        "version": 1,
        "requires": [
            {"control": "atlas-aml-m0028", "level": "adopted", "obligations": {}}
        ],
    },
    {
        "version": 1,
        "requires": [
            {
                "control": "atlas-aml-m0028",
                "level": "adopted",
                "obligations": {"approve": ["x"]},
            }
        ],
    },
    {
        "version": 1,
        "requires": [
            {
                "control": "atlas-aml-m0028",
                "level": "adopted",
                "obligations": {"approval_for": []},
            }
        ],
    },
    {
        "version": 1,
        "requires": [
            {
                "control": "atlas-aml-m0028",
                "level": "adopted",
                "obligations": {"approval_for": "terminal"},
            }
        ],
    },
    {
        "version": 1,
        "requires": [
            {
                "control": "atlas-aml-m0028",
                "level": "adopted",
                "obligations": {"no_new_grants": "yes"},
            }
        ],
    },
    {
        "version": 1,
        "requires": [
            {
                "control": "eu-ai-act-art-14-4",
                "level": "adopted",
                "obligations": {"no_new_grants": True},
            }
        ],
    },
    {
        "version": 1,
        "requires": [
            {
                "control": "atlas-aml-m0028",
                "level": "adopted",
                "obligations": {"no_new_grants": True},
            },
            {
                "control": "atlas-aml-m0028",
                "level": "adopted",
                "obligations": {"no_new_grants": True},
            },
        ],
    },
    {
        "version": 1,
        "requires": [
            {
                "control": "atlas-aml-m0028",
                "level": "adopted",
                "obligations": {"no_new_grants": True},
                "note": "x",
            }
        ],
    },
]


GOOD_ROW = {
    "control": "atlas-aml-m0028",
    "level": "adopted",
    "obligations": {"no_new_grants": True},
}
BAD_PROFILES += [
    {"version": True, "requires": [GOOD_ROW]},
    {"version": 1.0, "requires": [GOOD_ROW]},
    {"version": 1, "requires": [GOOD_ROW], "notes": "x"},
]


@pytest.mark.parametrize("bad", BAD_PROFILES)
def test_bad_profile_is_a_policy_error(bad):
    with pytest.raises(PolicyError):
        cc.load_profile(bad, CATALOG)


def _catalog_with(**change):
    row = dict(next(iter(CATALOG.values())), **change)
    return {"version": 1, "controls": [{k: v for k, v in row.items() if v is not None}]}


@pytest.mark.parametrize(
    "change",
    [
        {"binding": "voluntary"},
        {"source_url": "http://example.invalid"},
        {"title": ""},
        {"paraphrase": "x"},
        {"grade": None},
    ],
)
def test_bad_catalog_row_is_a_policy_error(change):
    with pytest.raises(PolicyError):
        cc.load_catalog(_catalog_with(**change))


@pytest.mark.parametrize(
    "top",
    [{"version": True}, {"version": 1.0}, {"version": 1, "source": "x"}],
    ids=["version-bool", "version-float", "unknown-key"],
)
def test_bad_catalog_top_level_is_a_policy_error(top):
    rows = list(CATALOG.values())
    with pytest.raises(PolicyError):
        cc.load_catalog({"version": 1, "controls": rows, **top})


def test_duplicate_catalog_key_is_a_policy_error():
    row = next(iter(CATALOG.values()))
    with pytest.raises(PolicyError):
        cc.load_catalog({"version": 1, "controls": [row, row]})


def _dup(tmp_path):
    p = tmp_path / "profile.yaml"
    p.write_text("version: 1\nversion: 1\n")
    return p


def test_profile_yaml_with_a_duplicate_key_is_refused(tmp_path):
    with pytest.raises(PolicyError):
        cc._read(str(_dup(tmp_path)))


# The shipped catalog and profile


def test_catalog_covers_each_framework():
    names = " ".join(r["framework"] for r in CATALOG.values())
    for fw in (
        "OWASP",
        "MITRE ATLAS",
        "NIST AI RMF",
        "EU AI Act",
        "ISO/IEC 42001",
        "ISO/IEC 27001",
        "NIST CSF",
        "Cyber Resilience Act",
    ):
        assert fw in names, fw


def test_mandatory_rows_are_the_eu_laws():
    assert {
        r["framework"].split(" (")[0]
        for r in CATALOG.values()
        if r["binding"] == "mandatory"
    } == {"EU AI Act", "EU Cyber Resilience Act"}


def test_example_profile_holds_on_the_example_allowlist(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    pol = load_policy(load_yaml_mapping((ROOT / "allowlist.example.yaml").read_text()))
    assert cc.check(pol, pol, PROFILE, CATALOG)["verdict"] == "ALLOW"


def test_gate_does_not_import_the_check():
    assert "control_check" not in (ROOT / "capability_gate.py").read_text()


# CLI


def _write(tmp_path, name, mapping):
    p = tmp_path / name
    p.write_text(json.dumps(mapping))  # JSON is YAML
    return str(p)


@pytest.mark.parametrize(
    "new,code",
    [
        (BASE, 0),
        (_edit(lambda m: m["skills"]["research"]["tools"].append("write_file")), 1),
        (_edit(lambda m: m["require_approval"].remove("terminal")), 3),
    ],
)
def test_cli_exit_codes(tmp_path, capsys, new, code):
    old = _write(tmp_path, "old.yaml", BASE)
    args = [
        old,
        _write(tmp_path, "new.yaml", new),
        "--catalog",
        str(ROOT / "controls/catalog.yaml"),
        "--profile",
        str(ROOT / "controls/profile.example.yaml"),
    ]
    assert cc.main(args) == code
    assert (
        json.loads(capsys.readouterr().out)["verdict"]
        == ["ALLOW", "ASK", "DENY", "DENY"][code if code < 3 else 2]
    )


@pytest.mark.parametrize(
    "text", ["skills: [1]\n", "a: 1\na: 2\n", "- x\n", "skills:\n  s:\n    tools: x\n"]
)
def test_cli_malformed_policy_exits_2(tmp_path, capsys, text):
    bad = tmp_path / "new.yaml"
    bad.write_text(text)
    args = [
        _write(tmp_path, "old.yaml", BASE),
        str(bad),
        "--catalog",
        str(ROOT / "controls/catalog.yaml"),
        "--profile",
        str(ROOT / "controls/profile.example.yaml"),
    ]
    assert cc.main(args) == 2
    assert json.loads(capsys.readouterr().out)["verdict"] == "DENY"


def test_cli_missing_file_exits_2(tmp_path, capsys):
    args = [
        str(tmp_path / "nope.yaml"),
        str(tmp_path / "nope2.yaml"),
        "--catalog",
        str(ROOT / "controls/catalog.yaml"),
        "--profile",
        str(ROOT / "controls/profile.example.yaml"),
    ]
    assert cc.main(args) == 2


DEEP = "requires: " + "[" * 5000 + "]" * 5000 + "\n"
ROW_TAIL = "  level: mandatory\n  obligations: {no_new_grants: true}\n"
CONTROL_LIST = "version: 1\nrequires:\n- control: [eu-ai-act-art-14-4]\n" + ROW_TAIL
CONTROL_MAP = "version: 1\nrequires:\n- control: {a: b}\n" + ROW_TAIL


@pytest.mark.parametrize(
    "text",
    [CONTROL_LIST, CONTROL_MAP, "version: 1\n" + DEEP],
    ids=["control-list", "control-mapping", "deep-nesting"],
)
def test_cli_any_load_error_exits_2_not_ask(tmp_path, capsys, text):
    bad = tmp_path / "profile.yaml"
    bad.write_text(text)
    old = _write(tmp_path, "old.yaml", BASE)
    args = [old, old, "--catalog", str(ROOT / "controls/catalog.yaml")]
    assert cc.main([*args, "--profile", str(bad)]) == 2
    assert json.loads(capsys.readouterr().out)["verdict"] == "DENY"
