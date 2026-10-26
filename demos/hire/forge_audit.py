#!/usr/bin/env python3
"""60-second forge-reject audit: rewrite a decision log line, verify rejects.

    python demos/hire/forge_audit.py [--out DIR] [--json]

Builds a real decision log with the gate (allow and deny rows, a kill switch
throw), checks it verifies, then runs each attack on a fresh copy of the log,
witness and anchor and checks that capability_gate.verify_hash_chain rejects
it and that the gate refuses to append onto it:

  rewrite-mid     a DENY row in the middle rewritten to ALLOW
  rewrite-last    the last row rewritten (no later parent link to break)
  delete-mid      one middle row removed
  truncate-tail   the last row cut off
  rechain         every row after the edit re-hashed so parent links hold,
                  witness and anchor left alone
  rechain-witness the same plus a recomputed witness, anchor left alone
  insert-row      a forged ALLOW row spliced in with a valid parent link

The audit also names the first row whose parent link breaks, which the gate
itself does not report.

Honest limit, printed as its own row: an attacker who can rewrite the log,
the witness AND the anchor in one folder passes verification. The answer is
an anchor outside the agent's reach or the signed checkpoint
(capability_gate CheckpointConfig), not this check.
"""

from __future__ import annotations

import argparse
import importlib
import json
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

cg = importlib.import_module("capability_gate")

ATTACKS = (
    "rewrite-mid",
    "rewrite-last",
    "delete-mid",
    "truncate-tail",
    "rechain",
    "rechain-witness",
    "insert-row",
)


@dataclass
class AttackResult:
    attack: str
    rejected: bool
    append_refused: bool
    first_bad_row: int | None
    error: str

    def line(self) -> str:
        v = "REJECTED" if self.rejected else "ACCEPTED"
        a = "append refused" if self.append_refused else "APPEND ALLOWED"
        row = "-" if self.first_bad_row is None else str(self.first_bad_row)
        return f"{self.attack:<16} {v:<9} {a:<15} bad_row={row:<4} {self.error}"


@dataclass
class Audit:
    baseline_ok: bool = False
    baseline_rows: int = 0
    attacks: list[AttackResult] = field(default_factory=list)
    limit_passes: bool | None = None
    external_anchor_rejects: bool | None = None
    elapsed_s: float = 0.0

    @property
    def ok(self) -> bool:
        return (
            self.baseline_ok
            and len(self.attacks) == len(ATTACKS)
            and all(a.rejected and a.append_refused for a in self.attacks)
            and self.external_anchor_rejects is True
        )

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "baseline_ok": self.baseline_ok,
            "baseline_rows": self.baseline_rows,
            "attacks": [a.__dict__ for a in self.attacks],
            "honest_limit_full_rewrite_passes": self.limit_passes,
            "external_anchor_rejects_full_rewrite": self.external_anchor_rejects,
            "elapsed_s": round(self.elapsed_s, 3),
        }


def _lines(log: Path) -> list[str]:
    return [x for x in log.read_text(encoding="utf-8").splitlines() if x]


def _write(log: Path, lines: list[str]) -> None:
    log.write_text("".join(x + "\n" for x in lines), encoding="utf-8")


def _rechain(lines: list[str], start: int) -> list[str]:
    """Re-hash parent links from row ``start`` on (0-based)."""
    out = list(lines[:start])
    prev = cg._hash_log_line(out[-1]) if out else cg._GENESIS
    for raw in lines[start:]:
        rec = json.loads(raw)
        rec["parent"] = prev
        body = json.dumps(rec, sort_keys=True)
        out.append(body)
        prev = cg._hash_log_line(body)
    return out


def _flip(raw: str) -> str:
    rec = json.loads(raw)
    rec["verdict"] = "allow" if rec.get("verdict") != "allow" else "deny"
    rec["reason"] = "allowed by policy"
    return json.dumps(rec, sort_keys=True)


def first_bad_row(log: Path) -> int | None:
    """1-based row whose parent link does not match the row before, or the
    row count + 1 when every link holds but the witness head disagrees."""
    prev = cg._GENESIS
    lines = _lines(log)
    for i, raw in enumerate(lines, start=1):
        try:
            rec = json.loads(raw)
        except ValueError:
            return i
        if rec.get("parent") != prev:
            return i
        prev = cg._hash_log_line(raw)
    wpath = Path(cg._witness_path(str(log)))
    if wpath.exists():
        w = json.loads(wpath.read_text(encoding="utf-8"))
        if w.get("head") != prev or w.get("count") != len(lines):
            return len(lines) + 1
    return None


def _write_witness_for(log: Path, path: Path) -> None:
    lines = _lines(log)
    head = cg._hash_log_line(lines[-1]) if lines else cg._GENESIS
    cg._write_witness(str(path), head, len(lines))


def apply_attack(attack: str, log: Path) -> None:
    lines = _lines(log)
    mid = len(lines) // 2
    if attack == "rewrite-mid":
        idx = next(
            i
            for i in range(mid, len(lines))
            if json.loads(lines[i])["verdict"] == "deny"
        )
        lines[idx] = _flip(lines[idx])
        _write(log, lines)
    elif attack == "rewrite-last":
        lines[-1] = _flip(lines[-1])
        _write(log, lines)
    elif attack == "delete-mid":
        del lines[mid]
        _write(log, lines)
    elif attack == "truncate-tail":
        _write(log, lines[:-1])
    elif attack == "rechain":
        lines[mid] = _flip(lines[mid])
        _write(log, _rechain(lines, mid))
    elif attack == "rechain-witness":
        lines[mid] = _flip(lines[mid])
        _write(log, _rechain(lines, mid))
        _write_witness_for(log, Path(cg._witness_path(str(log))))
    elif attack == "insert-row":
        forged = json.loads(lines[mid])
        forged.update(verdict="allow", reason="allowed by policy", tool="shell")
        lines.insert(mid + 1, json.dumps(forged, sort_keys=True))
        _write(log, _rechain(lines, mid + 1)[: mid + 2] + lines[mid + 2 :])
    else:
        raise ValueError(f"unknown attack {attack!r}")


def build_log(folder: Path, anchor: Path | None = None) -> tuple[Path, cg.Policy]:
    work = folder / "work"
    work.mkdir(parents=True, exist_ok=True)
    policy = cg.load_policy(
        {"skills": {"writer": {"tools": ["read_file"], "paths": [f"{work}/**"]}}}
    )
    log = folder / "audit" / "decisions.jsonl"
    gate = cg.Gate(policy, str(log), anchor_path=str(anchor) if anchor else None)
    for i in range(4):
        gate.evaluate("writer", "read_file", [str(work / f"f{i}.txt")])
        gate.evaluate("writer", "shell", [])
    gate.throw("forge audit")
    gate.evaluate("writer", "read_file", [str(work / "after.txt")])
    return log, policy


def _verifies(log: Path) -> tuple[bool, str]:
    try:
        cg.verify_hash_chain(str(log))
        return True, ""
    except ValueError as exc:
        return False, str(exc)


def _append_refused(log: Path) -> bool:
    try:
        cg.record_decision(
            str(log),
            cg.ENFORCE,
            cg.Decision(cg.Verdict.DENY, "probe", "writer", "probe"),
        )
    except ValueError:
        return True
    return False


def run(sandbox: Path) -> Audit:
    t0 = time.monotonic()
    audit = Audit()
    src = sandbox / "src"
    log, _policy = build_log(src)
    ok, _err = _verifies(log)
    audit.baseline_ok = ok and first_bad_row(log) is None
    audit.baseline_rows = len(_lines(log))
    for attack in ATTACKS:
        case = sandbox / attack
        shutil.copytree(src / "audit", case)
        clog = case / "decisions.jsonl"
        apply_attack(attack, clog)
        ok, err = _verifies(clog)
        bad = first_bad_row(clog)
        audit.attacks.append(
            AttackResult(attack, not ok, _append_refused(clog), bad, err)
        )
    # Honest limit: log + witness + anchor all rewritten in one folder.
    case = sandbox / "full-rewrite"
    shutil.copytree(src / "audit", case)
    clog = case / "decisions.jsonl"
    lines = _lines(clog)
    lines[1] = _flip(lines[1])
    _write(clog, _rechain(lines, 1))
    _write_witness_for(clog, Path(cg._witness_path(str(clog))))
    _write_witness_for(clog, Path(cg._anchor_path(str(clog))))
    audit.limit_passes, _ = _verifies(clog)
    # The same full rewrite against a log whose anchor lives outside its folder.
    ext = sandbox / "ext"
    anchor = sandbox / "operator-only" / "decisions.anchor"
    anchor.parent.mkdir(parents=True)
    elog, _p = build_log(ext, anchor)
    lines = _lines(elog)
    lines[1] = _flip(lines[1])
    _write(elog, _rechain(lines, 1))
    _write_witness_for(elog, Path(cg._witness_path(str(elog))))
    _write_witness_for(elog, Path(cg._anchor_path(str(elog))))
    try:
        cg.verify_hash_chain(str(elog), anchor_path=str(anchor))
        audit.external_anchor_rejects = False
    except ValueError:
        audit.external_anchor_rejects = True
    audit.elapsed_s = time.monotonic() - t0
    return audit


def render(audit: Audit) -> str:
    out = ["capability-gate forge-reject audit (decision log hash chain)", ""]
    out.append(
        f"baseline: {audit.baseline_rows} rows, verify "
        + ("OK" if audit.baseline_ok else "FAILED")
    )
    out += [a.line() for a in audit.attacks]
    out.append("")
    out.append(
        "honest limit: log + witness + anchor rewritten in one folder -> verify "
        + ("PASSES" if audit.limit_passes else "rejects")
        + " (keep the anchor out of the agent's reach, or use the signed checkpoint)"
    )
    out.append(
        "same full rewrite, anchor kept outside the log folder -> verify "
        + ("rejects" if audit.external_anchor_rejects else "PASSES")
    )
    out.append(f"elapsed: {audit.elapsed_s:.3f}s")
    out.append("RESULT: " + ("PASS" if audit.ok else "FAIL"))
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", help="folder for forge-output.txt and forge.json")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    sandbox = Path(tempfile.mkdtemp(prefix="cg-forge-audit-"))
    try:
        audit = run(sandbox)
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)
    text = render(audit)
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "forge-output.txt").write_text(text, encoding="utf-8")
        (out / "forge.json").write_text(
            json.dumps(audit.as_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    sys.stdout.write(
        json.dumps(audit.as_dict(), sort_keys=True) + "\n" if args.json else text
    )
    return 0 if audit.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
