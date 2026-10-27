#!/usr/bin/env python3
"""Shadow to enforce meter: one review window, same traffic through observe and
enforce, emits cg.shadow-enforce-metrics/v1 and validates it against the schema
shipped on capability-gate main (demos/hire/shadow_enforce_metrics.schema.json).

The promotion block is never decided here. decision stays "stay_shadow" and the
approver reads "pending-human-review" unless a person passes --approver and
--decision. Synthetic traffic, our box; not customer data.
"""

import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path

from _cg import CG_ROOT, SKILL, cg, make_client, sdk

SCHEMA = Path(CG_ROOT) / "demos" / "hire" / "shadow_enforce_metrics.schema.json"


def traffic(work):
    w = str(work)
    return [
        ("read_file", [f"{w}/a.txt"]),
        ("write_file", [f"{w}/b.txt"]),
        ("web_search", []),
        ("write_file", ["/etc/passwd"]),
        ("shell", []),
        ("terminal", []),
        ("read_file", [f"{w}/../../etc/shadow"]),
        ("read_file", [f"{w}/c.txt"]),
    ]


def run_window(approver="pending-human-review", decision="stay_shadow"):
    start = dt.datetime.now(dt.UTC).replace(microsecond=0)
    obs, _oroot, owork = make_client(mode=cg.OBSERVE)
    enf, eroot, ework = make_client(mode=cg.ENFORCE)
    s_flag, e_flag, s_exec, e_risky = set(), set(), 0, 0
    for i, ((tool, paths), (_, epaths)) in enumerate(
        zip(traffic(owork), traffic(ework))
    ):
        do = obs.check(SKILL, tool, paths)
        if do.verdict is not cg.Verdict.ALLOW:
            s_flag.add(i)
        s_exec += sdk.may_run(do)
        de = enf.check(SKILL, tool, epaths)
        if not sdk.may_run(de):
            e_flag.add(i)
        elif de.verdict is not cg.Verdict.ALLOW:
            e_risky += 1
    pol_sha = hashlib.sha256((eroot / "policy.yaml").read_bytes()).hexdigest()
    end = dt.datetime.now(dt.UTC).replace(microsecond=0)

    def iso(t):
        return t.strftime("%Y-%m-%dT%H:%M:%SZ")

    n = len(traffic(owork))
    return {
        "schema_version": "cg.shadow-enforce-metrics/v1",
        "window": {"start": iso(start), "end": iso(end)},
        "scope": {
            "skill": SKILL,
            "policy_sha256": pol_sha,
            "log_head": enf.verify_log(),
        },
        "shadow": {"calls": n, "would_block": len(s_flag), "executed": s_exec},
        "enforce": {"calls": n, "blocked": len(e_flag), "risky_executed": e_risky},
        "agreement": {
            "flagged_sets_identical": s_flag == e_flag,
            "false_positives_reviewed": 0,
            "false_positives_confirmed": 0,
        },
        "promotion": {
            "decision": decision,
            "approver": approver,
            "decided_at": iso(end),
        },
    }


def validate(doc):
    import jsonschema

    jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text())).validate(doc)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--approver", default="pending-human-review")
    ap.add_argument(
        "--decision",
        default="stay_shadow",
        choices=["stay_shadow", "promote_enforce", "rollback_to_shadow"],
    )
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    doc = run_window(a.approver, a.decision)
    validate(doc)
    text = json.dumps(doc, indent=2, sort_keys=True)
    if a.out:
        Path(a.out).write_text(text + "\n")
    print(text)
    ok = (
        doc["agreement"]["flagged_sets_identical"]
        and doc["enforce"]["risky_executed"] == 0
        and doc["shadow"]["executed"] == doc["shadow"]["calls"]
        and doc["enforce"]["blocked"] > 0
    )
    print("METER " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
