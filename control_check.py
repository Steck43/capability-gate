"""Old vs new policy check for required controls.

A policy edit can drop a control a deployment depends on: a tool taken out
of require_approval while a skill still grants it, a new tool or path granted
to a skill, a new skill. This module diffs the old and new policy against a
profile of required controls and refuses any change that leaves one unmet. It
is a change check, run at load time or in CI, in the spirit of a "no new
access" policy check; it is not edit protection and it never runs inside
Gate.evaluate.

Verdicts: ALLOW when every required control holds in the new policy; ASK when
an adopted control does not; DENY when a mandatory one does not, or when the
profile itself drops or downgrades a required control. Anything malformed
raises PolicyError, and the CLI exits 2.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from dataclasses import dataclass

import yaml

from capability_gate import Policy, PolicyError, load_policy, load_yaml_mapping

BINDINGS = frozenset({"mandatory", "advisory", "advisory_as_selected"})
LEVELS = ("adopted", "mandatory")
OBLIGATIONS = frozenset({"approval_for", "never_granted", "no_new_grants"})
_CATALOG_FIELDS = (
    "key",
    "framework",
    "edition",
    "control_id",
    "title",
    "binding",
    "grade",
    "source_url",
)
_RANK = {"ALLOW": 0, "ASK": 1, "DENY": 2}
EXIT = {"ALLOW": 0, "ASK": 1, "DENY": 3}


@dataclass(frozen=True)
class Required:
    control: str
    level: str
    obligations: Mapping


def _need(cond: bool, msg: str) -> None:
    if not cond:
        raise PolicyError(msg)


def _tool_list(value, where: str) -> frozenset[str]:
    _need(
        isinstance(value, list)
        and value
        and all(isinstance(t, str) and t for t in value),
        f"{where} must be a non-empty list of tool names",
    )
    return frozenset(value)


def load_catalog(mapping: Mapping) -> dict[str, dict]:
    _need(
        isinstance(mapping, Mapping) and mapping.get("version") == 1,
        "catalog: version must be 1",
    )
    rows = mapping.get("controls")
    _need(
        isinstance(rows, list) and rows, "catalog: 'controls' must be a non-empty list"
    )
    out: dict[str, dict] = {}
    for row in rows:
        _need(isinstance(row, Mapping), "catalog: each control must be a mapping")
        missing = [
            f
            for f in _CATALOG_FIELDS
            if not isinstance(row.get(f), str) or not row.get(f)
        ]
        _need(not missing, f"catalog: control {row.get('key')!r} lacks {missing}")
        extra = set(row) - set(_CATALOG_FIELDS)
        _need(
            not extra,
            f"catalog: control {row['key']!r} has unknown fields {sorted(extra)}",
        )
        _need(
            row["binding"] in BINDINGS,
            f"catalog: control {row['key']!r} has binding {row['binding']!r}",
        )
        _need(
            row["source_url"].startswith("https://"),
            f"catalog: control {row['key']!r} needs an https source",
        )
        _need(row["key"] not in out, f"catalog: duplicate key {row['key']!r}")
        out[row["key"]] = dict(row)
    return out


def load_profile(mapping: Mapping, catalog: Mapping[str, dict]) -> dict[str, Required]:
    _need(
        isinstance(mapping, Mapping) and mapping.get("version") == 1,
        "profile: version must be 1",
    )
    rows = mapping.get("requires")
    _need(
        isinstance(rows, list) and rows, "profile: 'requires' must be a non-empty list"
    )
    out: dict[str, Required] = {}
    for row in rows:
        _need(
            isinstance(row, Mapping)
            and set(row) <= {"control", "level", "obligations"},
            "profile: each entry has control, level and obligations",
        )
        key, level, obs = row.get("control"), row.get("level"), row.get("obligations")
        _need(key in catalog, f"profile: unknown control {key!r}")
        _need(key not in out, f"profile: control {key!r} listed twice")
        _need(
            level in LEVELS, f"profile: control {key!r} level must be one of {LEVELS}"
        )
        _need(
            not (catalog[key]["binding"] == "mandatory" and level != "mandatory"),
            f"profile: control {key!r} is mandatory law and cannot be required as {level!r}",
        )
        _need(
            isinstance(obs, Mapping) and obs,
            f"profile: control {key!r} needs obligations",
        )
        _need(
            set(obs) <= OBLIGATIONS,
            f"profile: control {key!r} has unknown obligations {sorted(set(obs) - OBLIGATIONS)}",
        )
        clean: dict = {}
        for name in ("approval_for", "never_granted"):
            if name in obs:
                clean[name] = _tool_list(obs[name], f"profile: {key} {name}")
        if "no_new_grants" in obs:
            _need(
                obs["no_new_grants"] is True,
                f"profile: {key} no_new_grants must be true",
            )
            clean["no_new_grants"] = True
        out[key] = Required(key, level, clean)
    return out


def _granted(policy: Policy) -> frozenset[str]:
    return frozenset(t for rule in policy.skills.values() for t in rule.tools)


def widening(old: Policy, new: Policy) -> list[str]:
    """Every way new grants more than old: a new skill, a tool or path glob a
    skill did not have, or an approval dropped for a tool that is still
    granted. A changed glob counts as new even when it is narrower."""
    found = []
    for name, rule in new.skills.items():
        before = old.skills.get(name)
        if before is None:
            found.append(f"new skill {name!r}")
            continue
        found += [
            f"skill {name!r} gains tool {t!r}"
            for t in sorted(rule.tools - before.tools)
        ]
        found += [
            f"skill {name!r} gains path {g!r}"
            for g in rule.path_globs
            if g not in before.path_globs
        ]
    still = _granted(new)
    found += [
        f"tool {t!r} leaves require_approval while still granted"
        for t in sorted(old.require_approval - new.require_approval)
        if t in still
    ]
    return found


def unmet(req: Required, policy: Policy, old: Policy | None = None) -> list[str]:
    """Why policy fails the obligations of req, or [] when it meets them."""
    granted, why = _granted(policy), []
    for t in sorted(req.obligations.get("approval_for", ())):
        if t in granted and t not in policy.require_approval:
            why.append(f"tool {t!r} is granted without approval")
    for t in sorted(req.obligations.get("never_granted", ())):
        if t in granted:
            why.append(f"tool {t!r} is granted")
    if req.obligations.get("no_new_grants") and old is not None:
        why += widening(old, policy)
    return why


def check(
    old: Policy,
    new: Policy,
    profile: Mapping[str, Required],
    catalog: Mapping[str, dict],
    old_profile: Mapping[str, Required] | None = None,
) -> dict:
    """Compare old and new against the profile. Returns the report; its
    verdict is the strictest of the per-control verdicts."""
    controls, verdict = [], "ALLOW"
    for key, req in profile.items():
        now = unmet(req, new, old)
        before = unmet(req, old) if "no_new_grants" not in req.obligations else []
        status = "KEPT" if not now else ("UNMET" if before else "DROPPED")
        v = "ALLOW" if not now else ("DENY" if req.level == "mandatory" else "ASK")
        verdict = max(verdict, v, key=_RANK.get)
        row = catalog[key]
        controls.append(
            {
                "control": key,
                "framework": row["framework"],
                "control_id": row["control_id"],
                "level": req.level,
                "status": status,
                "verdict": v,
                "why": now,
            }
        )
    for key, req in (old_profile or {}).items():
        cur = profile.get(key)
        if cur is None or LEVELS.index(cur.level) < LEVELS.index(req.level):
            verdict = "DENY"
            controls.append(
                {
                    "control": key,
                    "level": req.level,
                    "status": "PROFILE_DROPPED",
                    "verdict": "DENY",
                    "why": [
                        "removed from the profile"
                        if cur is None
                        else f"downgraded to {cur.level!r}"
                    ],
                }
            )
    return {"verdict": verdict, "controls": controls}


def _read(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            return load_yaml_mapping(f.read())
    except (OSError, ValueError, yaml.YAMLError) as e:
        raise PolicyError(f"{path}: {e}") from e


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("old_policy")
    ap.add_argument("new_policy")
    ap.add_argument("--catalog", default="controls/catalog.yaml")
    ap.add_argument("--profile", default="controls/profile.example.yaml")
    ap.add_argument("--old-profile")
    a = ap.parse_args(argv)
    try:
        catalog = load_catalog(_read(a.catalog))
        profile = load_profile(_read(a.profile), catalog)
        old_profile = (
            load_profile(_read(a.old_profile), catalog) if a.old_profile else None
        )
        report = check(
            load_policy(_read(a.old_policy)),
            load_policy(_read(a.new_policy)),
            profile,
            catalog,
            old_profile,
        )
    except PolicyError as e:
        print(json.dumps({"verdict": "DENY", "error": str(e)}))
        return 2
    print(json.dumps(report, indent=2))
    return EXIT[report["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
