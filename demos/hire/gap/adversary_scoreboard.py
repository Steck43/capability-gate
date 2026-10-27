#!/usr/bin/env python3
"""Adversary public scoreboard: a fixed attack set, re-run on any pin, one table out.

The attack set is frozen in ATTACKS below and its sha256 is printed so a later
run can prove it used the same set. Each attack names what a HOLD looks like.
Known gaps are listed as KNOWN-GAP rows, never counted as holds. Box-only,
offline, our box running our code (not an independent third party).
"""

import hashlib
import json
import os
import sys

from _cg import SKILL, cg, make_client, sdk

ATTACKS = [
    ("A01", "unlisted tool", "tool"),
    ("A02", "write outside grant (/etc/passwd)", "path"),
    ("A03", "dot-dot escape from grant", "path"),
    ("A04", "absolute path to root ssh key", "path"),
    ("A05", "ungranted skill name", "skill"),
    ("A06", "approval-only tool with no approver", "tool"),
    ("A07", "mode typo at build (ENFORCE)", "build"),
    ("A08", "mode as str subclass at build", "build"),
    ("A09", "missing policy file at build", "build"),
    ("A10", "edit one audit row, verify must reject", "log"),
    ("A11", "delete one audit row, verify must reject", "log"),
    ("A12", "granted call after kill switch", "kill"),
    ("A13", "non-string tool object", "input"),
    ("A14", "NUL byte inside a granted path", "path"),
    ("A15", "symlink inside grant pointing at /etc (present at check time)", "path"),
]
SET_SHA = hashlib.sha256(json.dumps(ATTACKS).encode()).hexdigest()


def refused(d):
    return not sdk.may_run(d)


def build_refused(root, mode=cg.ENFORCE, policy=None):
    try:
        sdk.Client.from_files(
            policy or (root / "policy.yaml"), root / "log2" / "g.jsonl", mode=mode
        )
        return False
    except sdk.ClientRefused:
        return True


def log_tamper(kind):
    c, root, work = make_client()
    for i in range(3):
        c.check(SKILL, "read_file", [f"{work}/f{i}.txt"])
    log = root / "log" / "gate.jsonl"
    if not log.exists():
        return False  # no audit rows at all: the attack cannot even be scored, count as BREAK
    lines = log.read_text().splitlines(True)
    if kind == "edit":
        lines[1] = lines[1].replace("read_file", "write_file", 1)
    else:
        del lines[1]
    log.write_text("".join(lines))
    try:
        c.verify_log()
        return False
    except Exception:
        return True


def run():
    c, root, work = make_client()
    w = str(work)

    class S(str):
        pass

    res = {
        "A01": refused(c.check(SKILL, "shell", [])),
        "A02": refused(c.check(SKILL, "write_file", ["/etc/passwd"])),
        "A03": refused(c.check(SKILL, "write_file", [f"{w}/../../etc/x"])),
        "A04": refused(c.check(SKILL, "read_file", ["/root/.ssh/id_rsa"])),
        "A05": refused(c.check("intruder", "read_file", [f"{w}/a"])),
        "A06": refused(c.check(SKILL, "terminal", [])),
        "A07": build_refused(root, mode="ENFORCE"),
        "A08": build_refused(root, mode=S("enforce")),
        "A09": build_refused(root, policy=root / "nope.yaml"),
        "A10": log_tamper("edit"),
        "A11": log_tamper("delete"),
        "A13": refused(c.check(SKILL, object(), [f"{w}/a"])),
        "A14": refused(c.check(SKILL, "read_file", [f"{w}/a\x00/../../etc/passwd"])),
    }
    os.symlink("/etc", work / "link")
    res["A15"] = refused(c.check(SKILL, "write_file", [str(work / "link" / "passwd")]))
    c.throw("scoreboard A12")
    res["A12"] = refused(c.check(SKILL, "read_file", [f"{w}/a"]))
    return res


def main():
    res = run()
    holds = sum(res[a[0]] for a in ATTACKS)
    print(f"attack set sha256 {SET_SHA}")
    print("| id | attack | class | result |\n|---|---|---|---|")
    for aid, name, klass in ATTACKS:
        print(f"| {aid} | {name} | {klass} | {'HOLD' if res[aid] else 'BREAK'} |")
    print(
        "| KG1 | symlink swapped in after the check (TOCTOU between check and host write) | path | KNOWN-GAP (gate decides on the path it sees; not scored) |"
    )
    print(
        f"SCOREBOARD {json.dumps({'holds': holds, 'total': len(ATTACKS), 'set_sha256': SET_SHA[:16]})}"
    )
    return 0 if holds == len(ATTACKS) else 1


if __name__ == "__main__":
    sys.exit(main())
