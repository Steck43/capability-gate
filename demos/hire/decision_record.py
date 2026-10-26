#!/usr/bin/env python3
"""CISO decision record bound to a real decision log row.

    python demos/hire/decision_record.py demo [--out DIR] [--json]
    python demos/hire/decision_record.py check RECORD LOG [--now EPOCH]

A decision record is the paper a security lead signs ("keep shell denied for
this skill", "promote this skill to enforce"). Here it carries a receipt that
binds it to one row of the gate's own hash chained decision log:

  receipt   log_head (hash of the last row when the record was made),
            row_count, row_index, row_sha256 and the row's verdict, tool
            and skill
  binding   action_hash = sha256 of the canonical decision plus receipt,
            approver, not_after (epoch seconds) and a hex nonce

check accepts a record only when the log still verifies
(capability_gate.verify_hash_chain), the first row_count rows hash to
log_head, the row at row_index hashes to row_sha256 and says what the
receipt says, action_hash recomputes and not_after is in the future. A
missing receipt, a forged field or a rewritten log is a reject with a reason.

Honest limit: this is a record checked after the fact. Gate.evaluate does not
read it, so it does not approve or run a call; an approve-then-run receipt on
the live path is not built at this commit.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import re
import secrets
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
cg = importlib.import_module("capability_gate")

SCHEMA = "cg.decision-record/v1"
RECEIPT_KEYS = (
    "log_head",
    "row_count",
    "row_index",
    "row_sha256",
    "verdict",
    "tool",
    "skill",
)
RECORD_KEYS = ("schema", "decision", "receipt", "approver", "not_after", "nonce")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_NONCE = re.compile(r"^[0-9a-f]{32,128}$")


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _log_lines(log_path: Path) -> list[str]:
    if not log_path.exists():
        return []
    return [
        ln.rstrip("\n")
        for ln in log_path.read_text(encoding="utf-8").splitlines()
        if ln.strip()
    ]


def make_receipt(log_path: Path, row_index: int) -> dict:
    """Receipt for one row of a log that verifies now."""
    cg.verify_hash_chain(str(log_path))
    lines = _log_lines(log_path)
    if not 0 <= row_index < len(lines):
        raise ValueError(f"row_index {row_index} outside log of {len(lines)} rows")
    row = json.loads(lines[row_index])
    return {
        "log_head": cg._hash_log_line(lines[-1]),
        "row_count": len(lines),
        "row_index": row_index,
        "row_sha256": cg._hash_log_line(lines[row_index]),
        "verdict": row.get("verdict"),
        "tool": row.get("tool"),
        "skill": row.get("skill"),
    }


def action_hash(decision: str, receipt: dict) -> str:
    return hashlib.sha256(
        _canon({"decision": decision, "receipt": receipt})
    ).hexdigest()


def build_record(
    decision: str,
    receipt: dict,
    approver: str,
    not_after: float,
    nonce: str | None = None,
) -> dict:
    return {
        "schema": SCHEMA,
        "decision": decision,
        "receipt": dict(receipt),
        "action_hash": action_hash(decision, receipt),
        "approver": approver,
        "not_after": not_after,
        "nonce": nonce or secrets.token_hex(16),
    }


def validate(record, log_path: Path, now: float | None = None) -> list[str]:
    """Reasons to reject the record; an empty list means it is bound and live."""
    now = time.time() if now is None else now
    if not isinstance(record, dict):
        return ["record is not a JSON object"]
    errs = [f"missing {k}" for k in RECORD_KEYS if k not in record]
    if "action_hash" not in record:
        errs.append("missing action_hash")
    if errs:
        return errs
    if record["schema"] != SCHEMA:
        errs.append(f"schema is not {SCHEMA}")
    if not isinstance(record["decision"], str) or not record["decision"].strip():
        errs.append("decision is empty")
    if not isinstance(record["approver"], str) or not record["approver"].strip():
        errs.append("approver is empty")
    na = record["not_after"]
    if isinstance(na, bool) or not isinstance(na, (int, float)):
        errs.append("not_after is not a number")
    elif na <= now:
        errs.append("record expired (not_after has passed)")
    if not isinstance(record["nonce"], str) or not _NONCE.match(record["nonce"]):
        errs.append("nonce is not 32 to 128 lowercase hex characters")
    rc = record["receipt"]
    if not isinstance(rc, dict):
        return [*errs, "receipt is not an object"]
    missing = [k for k in RECEIPT_KEYS if k not in rc]
    if missing:
        return [*errs, *(f"receipt missing {k}" for k in missing)]
    if sorted(rc) != sorted(RECEIPT_KEYS):
        errs.append("receipt has unknown keys")
    for k in ("log_head", "row_sha256"):
        if not isinstance(rc[k], str) or not _HEX64.match(rc[k]):
            errs.append(f"receipt {k} is not a sha256 hex digest")
    for k in ("row_count", "row_index"):
        if isinstance(rc[k], bool) or not isinstance(rc[k], int) or rc[k] < 0:
            errs.append(f"receipt {k} is not a non-negative integer")
    if errs:
        return errs
    if record["action_hash"] != action_hash(record["decision"], rc):
        errs.append("action_hash does not match decision and receipt")
    try:
        cg.verify_hash_chain(str(log_path))
    except Exception as exc:
        return [*errs, f"decision log does not verify: {exc}"]
    lines = _log_lines(log_path)
    if rc["row_count"] < 1 or rc["row_count"] > len(lines):
        return [*errs, "receipt row_count is not a prefix of the log"]
    if cg._hash_log_line(lines[rc["row_count"] - 1]) != rc["log_head"]:
        errs.append("receipt log_head is not the head of that log prefix")
    if not rc["row_index"] < rc["row_count"]:
        return [*errs, "receipt row_index is outside the receipted prefix"]
    line = lines[rc["row_index"]]
    if cg._hash_log_line(line) != rc["row_sha256"]:
        errs.append("receipt row_sha256 does not match the logged row")
    row = json.loads(line)
    for k in ("verdict", "tool", "skill"):
        if row.get(k) != rc[k]:
            errs.append(f"receipt {k} does not match the logged row")
    return errs


# --- demo -------------------------------------------------------------------

SKILL = "triage-agent"


def _policy(home: Path):
    return cg.load_policy(
        {
            "skills": {
                SKILL: {"tools": ["read_file"], "paths": [str(home / "work" / "**")]}
            }
        }
    )


def demo_log(home: Path) -> tuple[Path, int]:
    """A real log: one allow, one shell deny. Returns (log, deny row index)."""
    (home / "work").mkdir(parents=True, exist_ok=True)
    log = home / "logs" / "decisions.jsonl"
    gate = cg.Gate(_policy(home), str(log), mode=cg.ENFORCE)
    gate.evaluate(SKILL, "read_file", [str(home / "work" / "alert.txt")])
    d = gate.evaluate(SKILL, "terminal", [str(home / "work")], args={"command": "x"})
    if d.verdict is not cg.Verdict.DENY:
        raise RuntimeError(f"demo expected a deny row, got {d.verdict}")
    return log, 1


def _forge_cases(record: dict) -> dict[str, dict]:
    def with_receipt(**kw):
        return {**record, "receipt": {**record["receipt"], **kw}}

    def rehashed(**kw):
        # action_hash is a plain digest anyone can recompute; the log must
        # still reject the forgery.
        r = with_receipt(**kw)
        return {**r, "action_hash": action_hash(r["decision"], r["receipt"])}

    no_receipt = {k: v for k, v in record.items() if k != "receipt"}
    return {
        "missing-receipt": no_receipt,
        "forged-verdict": with_receipt(verdict="allow"),
        "forged-verdict-rehashed": rehashed(verdict="allow"),
        "forged-row-hash": with_receipt(row_sha256="0" * 64),
        "forged-row-hash-rehashed": rehashed(row_sha256="0" * 64),
        "forged-head-rehashed": rehashed(log_head="f" * 64),
        "forged-row-index-rehashed": rehashed(row_index=0),
        "forged-decision": {**record, "decision": "allow shell for " + SKILL},
        "expired": {**record, "not_after": 1.0},
    }


def run_demo(out: Path | None = None) -> dict:
    home = Path(tempfile.mkdtemp(prefix="cg-record-"))
    try:
        log, idx = demo_log(home)
        rcpt = make_receipt(log, idx)
        rec = build_record(
            f"keep terminal denied for {SKILL}",
            rcpt,
            approver="security-lead@example.invalid",
            not_after=time.time() + 3600,
        )
        rows = [{"case": "real", "expect": "accept", "errors": validate(rec, log)}]
        for name, forged in _forge_cases(rec).items():
            rows.append(
                {"case": name, "expect": "reject", "errors": validate(forged, log)}
            )
        # A rewritten log: the bound row is edited on disk after the record.
        lines = log.read_text(encoding="utf-8").splitlines(keepends=True)
        row = json.loads(lines[idx])
        row["verdict"] = "allow"
        lines[idx] = json.dumps(row, sort_keys=True) + "\n"
        log.write_text("".join(lines), encoding="utf-8")
        rows.append(
            {"case": "log-rewritten", "expect": "reject", "errors": validate(rec, log)}
        )
        for r in rows:
            r["ok"] = (
                (not r["errors"]) if r["expect"] == "accept" else bool(r["errors"])
            )
        result = {
            "record": rec,
            "cases": rows,
            "all_ok": all(r["ok"] for r in rows),
        }
        if out is not None:
            out.mkdir(parents=True, exist_ok=True)
            (out / "decision-record.json").write_text(
                json.dumps(rec, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            (out / "decision-record-cases.json").write_text(
                json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        return result
    finally:
        shutil.rmtree(home, ignore_errors=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo")
    d.add_argument("--out", type=Path, default=None)
    d.add_argument("--json", action="store_true")
    c = sub.add_parser("check")
    c.add_argument("record", type=Path)
    c.add_argument("log", type=Path)
    c.add_argument("--now", type=float, default=None)
    args = ap.parse_args(argv)
    if args.cmd == "check":
        try:
            rec = json.loads(args.record.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"REJECT unreadable record: {exc}")
            return 1
        errs = validate(rec, args.log, args.now)
        print("ACCEPT" if not errs else "REJECT " + "; ".join(errs))
        return 0 if not errs else 1
    res = run_demo(args.out)
    if args.json:
        print(json.dumps(res, indent=2, sort_keys=True))
    else:
        for r in res["cases"]:
            got = "accept" if not r["errors"] else "reject"
            why = "" if not r["errors"] else "  (" + r["errors"][0] + ")"
            print(f"{'PASS' if r['ok'] else 'FAIL'}  {r['case']:<24} {got}{why}")
        print("decision record demo:", "PASS" if res["all_ok"] else "FAIL")
    return 0 if res["all_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
