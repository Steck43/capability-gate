#!/usr/bin/env python3
"""One command, four outcomes: allow, deny, kill switch, fail closed.

    python demos/hire/hire_demo.py [--out DIR] [--json]

Every row comes from the real gate (capability_gate.Gate.evaluate) on a
throwaway folder. A stand-in tool runs only when the gate says ALLOW in
enforce mode, so "executed" counts are what the host would have run.

Steps, in order, all on one decision log:

  1 ALLOW        granted tool on a granted path; the tool runs
  2 DENY         tool not granted, path outside the grant, canary secret;
                 none run
  3 KILL         throw the switch mid run; every tool in the policy plus an
                 unknown one is denied and logged with no restart;
                 executed_after_kill == 0; a THROWN row is on the chain
  4 FAIL CLOSED  a malformed policy is refused at load; a gate error is a
                 DENY row; a removed log folder denies every call
  5 VERIFY       the hash chain verifies; its head and row count are printed
  6 OBSERVE      the same denied call in observe mode is logged with
                 enforced=false and the host would run it (the honest limit)

Exit 0 only when every expected outcome held. Nothing touches the network.
This is the gate alone: it says nothing about whether a live harness hook
calls it.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

cg = importlib.import_module("capability_gate")

SKILL = "writer"
GRANTED_TOOLS = ("read_file", "write_file", "list_dir")
UNGRANTED_TOOLS = ("shell", "http_post", "delete_file")
UNKNOWN_TOOL = "tool_nobody_named"


@dataclass
class Row:
    step: str
    label: str
    verdict: str
    enforced: bool
    executed: bool
    reason: str

    def line(self) -> str:
        ran = "RAN" if self.executed else "blocked"
        mode = "enforce" if self.enforced else "observe"
        return (
            f"[{self.step:<12}] {self.label:<38} {self.verdict.upper():<7} "
            f"{mode:<7} {ran:<7} {self.reason}"
        )


@dataclass
class Result:
    rows: list[Row] = field(default_factory=list)
    checks: list[tuple[str, bool]] = field(default_factory=list)
    chain_head: str = ""
    chain_rows: int = 0
    executed_after_kill: int = 0
    log_path: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(ok for _, ok in self.checks)

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "rows": [r.__dict__ for r in self.rows],
            "checks": [{"check": c, "ok": ok} for c, ok in self.checks],
            "chain_head": self.chain_head,
            "chain_rows": self.chain_rows,
            "executed_after_kill": self.executed_after_kill,
        }


def policy_mapping(work: Path) -> dict:
    return {
        "version": 1,
        "skills": {SKILL: {"tools": list(GRANTED_TOOLS), "paths": [f"{work}/**"]}},
    }


def host_runs(decision: cg.Decision) -> bool:
    """What a host does with a decision: run only an enforced ALLOW, or any
    call in observe mode (observe logs the verdict and acts on nothing)."""
    if not decision.enforced:
        return True
    return decision.verdict is cg.Verdict.ALLOW


def _call(
    res: Result, gate: cg.Gate, step: str, label: str, tool: str, paths
) -> cg.Decision:
    d = gate.evaluate(SKILL, tool, paths)
    ran = host_runs(d)
    res.rows.append(Row(step, label, d.verdict.value, d.enforced, ran, d.reason))
    return d


def _check(res: Result, name: str, ok: bool) -> None:
    res.checks.append((name, bool(ok)))


def _rows(log: Path) -> list[dict]:
    if not log.exists():
        return []
    return [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines() if x]


class _Unprintable:
    """A path whose str() raises: stands in for any error inside evaluate."""

    def __str__(self) -> str:
        raise RuntimeError("path object exploded")


def run(sandbox: Path) -> Result:
    res = Result()
    work = sandbox / "work"
    work.mkdir(parents=True, exist_ok=True)
    (work / "notes.txt").write_text("hello\n", encoding="utf-8")
    (work / "secret-canary.txt").write_text("canary\n", encoding="utf-8")
    (work / ".env").write_text("TOKEN=canary\n", encoding="utf-8")
    log = sandbox / "audit" / "decisions.jsonl"
    res.log_path = str(log)
    policy = cg.load_policy(policy_mapping(work))
    gate = cg.Gate(policy, str(log))

    # 1 ALLOW
    d = _call(
        res,
        gate,
        "1 ALLOW",
        "read_file work/notes.txt",
        "read_file",
        [str(work / "notes.txt")],
    )
    _check(
        res,
        "allow: granted call is ALLOW and runs",
        d.verdict is cg.Verdict.ALLOW and host_runs(d),
    )

    # 2 DENY
    d1 = _call(res, gate, "2 DENY", "shell (tool not granted)", "shell", [])
    d2 = _call(
        res,
        gate,
        "2 DENY",
        "read_file /etc/passwd (outside)",
        "read_file",
        ["/etc/passwd"],
    )
    d3 = _call(
        res,
        gate,
        "2 DENY",
        "read_file work/secret-canary.txt",
        "read_file",
        [str(work / "secret-canary.txt")],
    )
    d4 = _call(
        res,
        gate,
        "2 DENY",
        "read_file work/.env (protected)",
        "read_file",
        [str(work / ".env")],
    )
    _check(
        res,
        "deny: tool not granted is DENY and blocked",
        d1.verdict is cg.Verdict.DENY
        and not host_runs(d1)
        and "not granted" in d1.reason,
    )
    _check(
        res,
        "deny: path outside grant is DENY and blocked",
        d2.verdict is cg.Verdict.DENY
        and not host_runs(d2)
        and "outside allowlist" in d2.reason,
    )
    _check(
        res,
        "deny: canary secret inside grant is DENY and blocked",
        d3.verdict is cg.Verdict.DENY and not host_runs(d3) and "canary" in d3.reason,
    )
    _check(
        res,
        "deny: protected .env inside grant is DENY and blocked",
        d4.verdict is cg.Verdict.DENY
        and not host_runs(d4)
        and "protected" in d4.reason,
    )

    # 3 KILL
    rows_before = len(_rows(log))
    thrown = gate.throw("demo: operator pulled the switch")
    _check(res, "kill: throw() reports it threw the switch", thrown is True)
    tools = (*GRANTED_TOOLS, *UNGRANTED_TOOLS, UNKNOWN_TOOL)
    after = []
    for tool in tools:
        after.append(
            _call(
                res,
                gate,
                "3 KILL",
                f"{tool} after throw",
                tool,
                [str(work / "notes.txt")],
            )
        )
    res.executed_after_kill = sum(1 for x in after if host_runs(x))
    log_rows = _rows(log)
    thrown_rows = [r for r in log_rows if r.get("verdict") == "thrown"]
    kill_rows = log_rows[rows_before + 1 :]
    _check(
        res,
        "kill: every tool after throw is DENY",
        all(x.verdict is cg.Verdict.DENY for x in after),
    )
    _check(
        res,
        "kill: deny reason names the kill switch",
        all("kill switch" in x.reason for x in after),
    )
    _check(res, "kill: executed_after_kill == 0", res.executed_after_kill == 0)
    _check(res, "kill: one THROWN row on the chain", len(thrown_rows) == 1)
    _check(
        res,
        "kill: every post-throw call has its own DENY row",
        len(kill_rows) == len(tools)
        and all(r.get("verdict") == "deny" for r in kill_rows),
    )
    _check(
        res,
        "kill: second throw is a no-op (already thrown)",
        gate.throw("again") is False,
    )

    # 5 VERIFY (before the fail-closed step removes a folder)
    try:
        head = cg.verify_hash_chain(str(log))
        res.chain_head = head
        res.chain_rows = len(_rows(log))
        _check(res, "verify: chain verifies after the kill", True)
    except ValueError as exc:
        _check(res, f"verify: chain verifies after the kill ({exc})", False)

    # 4 FAIL CLOSED
    try:
        cg.load_policy({"skills": {SKILL: {"tools": "shell"}}})
        refused = False
    except cg.PolicyError:
        refused = True
    _check(res, "fail-closed: malformed policy refused at load", refused)
    res.rows.append(
        Row(
            "4 FAILCLOSED",
            "malformed policy (tools: str)",
            "refused",
            True,
            False,
            "PolicyError at load",
        )
    )

    log2 = sandbox / "audit2" / "decisions.jsonl"
    gate2 = cg.Gate(policy, str(log2))
    d = gate2.evaluate(SKILL, "read_file", [_Unprintable()])
    res.rows.append(
        Row(
            "4 FAILCLOSED",
            "gate error inside evaluate",
            d.verdict.value,
            d.enforced,
            host_runs(d),
            d.reason,
        )
    )
    err_rows = _rows(log2)
    _check(
        res,
        "fail-closed: gate error is DENY and blocked",
        d.verdict is cg.Verdict.DENY
        and not host_runs(d)
        and "failing closed" in d.reason,
    )
    _check(
        res,
        "fail-closed: gate error DENY is on the log",
        len(err_rows) == 1 and err_rows[0]["verdict"] == "deny",
    )

    log3 = sandbox / "audit3" / "decisions.jsonl"
    gate3 = cg.Gate(policy, str(log3))
    shutil.rmtree(log3.parent)
    d = gate3.evaluate(SKILL, "read_file", [str(work / "notes.txt")])
    res.rows.append(
        Row(
            "4 FAILCLOSED",
            "log folder removed, granted call",
            d.verdict.value,
            d.enforced,
            host_runs(d),
            d.reason,
        )
    )
    _check(
        res,
        "fail-closed: removed log folder denies a granted call",
        d.verdict is cg.Verdict.DENY and not host_runs(d),
    )
    _check(
        res,
        "fail-closed: removed log folder is not silently re-created",
        not log3.parent.exists(),
    )

    # 6 OBSERVE (honest limit)
    log4 = sandbox / "audit4" / "decisions.jsonl"
    gate4 = cg.Gate(policy, str(log4), mode=cg.OBSERVE)
    d = gate4.evaluate(SKILL, "shell", [])
    res.rows.append(
        Row(
            "6 OBSERVE",
            "shell in observe mode",
            d.verdict.value,
            d.enforced,
            host_runs(d),
            d.reason,
        )
    )
    obs = _rows(log4)
    _check(
        res,
        "observe: true verdict DENY is logged with enforced=false",
        d.verdict is cg.Verdict.DENY
        and d.enforced is False
        and len(obs) == 1
        and obs[0]["enforced"] is False,
    )
    return res


def render(res: Result) -> str:
    out = ["capability-gate one-command demo (gate alone, synthetic paths)", ""]
    out += [r.line() for r in res.rows]
    out += [
        "",
        f"executed_after_kill = {res.executed_after_kill}",
        f"chain rows = {res.chain_rows}",
        f"chain head = {res.chain_head}",
        "",
    ]
    out += [f"{'PASS' if ok else 'FAIL'}  {c}" for c, ok in res.checks]
    out += ["", "RESULT: " + ("PASS" if res.ok else "FAIL")]
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", help="folder for demo-output.txt and summary.json")
    ap.add_argument("--json", action="store_true", help="print JSON, not the table")
    args = ap.parse_args(argv)
    sandbox = Path(tempfile.mkdtemp(prefix="cg-hire-demo-"))
    try:
        res = run(sandbox)
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)
    text = render(res)
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "demo-output.txt").write_text(text, encoding="utf-8")
        (out / "summary.json").write_text(
            json.dumps(res.as_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    sys.stdout.write(
        json.dumps(res.as_dict(), sort_keys=True) + "\n" if args.json else text
    )
    return 0 if res.ok else 1


if __name__ == "__main__":
    os.umask(0o077)
    raise SystemExit(main())
