#!/usr/bin/env python3
"""ClaimGate: CI lint for public claims. Not the runtime gate.

ClaimGate answers "may this claim go out at this status?". It never decides a
tool call; that is capability_gate.Gate.evaluate, and the two names stay apart
(the name fence below refuses a claim that merges them).

    python claimgate/claimgate.py check [CLAIMS.yaml ...] [--root DIR] [--json]

Each claims file holds ``claims:``, a list of rows:

    claim_id          UPPER-KEBAB id, unique across the files checked
    text              the sentence said out loud, one line, no em dash
    status            REAL | PARTIAL | STUBBED | PLANNED | RETIRED
    enforcement_path  "file.py::Name.attr" (or "file.py") that does the work
    evidence          list of "tests/file.py::test_name" that check it
    pins              optional list of mutant ids from the pin registry; each
                      mutant deletes or flips the control and must turn the
                      evidence red (fail-when-removed)

The status a row may carry is computed from what resolves, and a declared
status above it is OVERREACH:

    REAL      enforcement resolves, at least one evidence test resolves, and
              at least one pin resolves to a mutant registered for this claim
    PARTIAL   enforcement and at least one evidence test resolve
    STUBBED   enforcement resolves
    PLANNED   nothing needs to resolve
    RETIRED   nothing needs to resolve; kept so the id is never reused

Every listed evidence test and pin must resolve, whatever the status (a
dangling reference is an error of its own). Absolute words ("every", "all",
"never", "always", "any") need REAL; theater words ("guarantee",
"unbreakable", "tamper-proof", "100%", "military-grade", "zero risk",
"impossible", "sandboxed", "microVM-isolated") are refused at any status.

Exit status: 0 clean, 1 findings, 2 a file could not be read.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

STATUS_RANK = {"RETIRED": 0, "PLANNED": 1, "STUBBED": 2, "PARTIAL": 3, "REAL": 4}
REQUIRED = ("claim_id", "text", "status", "enforcement_path", "evidence")
OPTIONAL = ("pins",)
CLAIM_ID = re.compile(r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$")
EVIDENCE = re.compile(r"^([\w./-]+\.py)::([A-Za-z_]\w*)$")
ENFORCEMENT = re.compile(r"^([\w./-]+\.py)(?:::([A-Za-z_][\w.]*))?$")
ABSOLUTE = re.compile(r"\b(every|all|never|always|any|none)\b", re.IGNORECASE)
THEATER = (
    "guarantee",
    "unbreakable",
    "tamper-proof",
    "tamperproof",
    "100%",
    "military-grade",
    "zero risk",
    "impossible",
    "sandboxed",
    "microvm-isolated",
    "bulletproof",
)
NAME_FENCE = re.compile(
    r"(claimgate\W+(is|as|=|renames?|replaces?)\W+(gate\.)?evaluate)"
    r"|((gate\.)?evaluate\W+(is|as|=|renamed\W+(to|as))\W+claimgate)",
    re.IGNORECASE,
)
DEFAULT_REGISTRY = "demos/hire/mutants.yaml"


@dataclass(frozen=True)
class Finding:
    claim_id: str
    code: str
    message: str

    def line(self) -> str:
        return f"ERROR {self.claim_id} {self.code}: {self.message}"


def _no_duplicate_keys(node) -> None:
    if isinstance(node, yaml.MappingNode):
        seen = set()
        for k, v in node.value:
            key = k.value if isinstance(k, yaml.ScalarNode) else id(k)
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate key {key!r}", k.start_mark
                )
            seen.add(key)
            _no_duplicate_keys(v)
    elif isinstance(node, yaml.SequenceNode):
        for item in node.value:
            _no_duplicate_keys(item)


def _strict_load(text: str):
    """safe_load, after refusing a repeated key anywhere in the document."""
    node = yaml.compose(text, Loader=yaml.SafeLoader)
    if node is not None:
        _no_duplicate_keys(node)
    return yaml.safe_load(text)


def _defs(path: Path) -> set[str]:
    """Dotted names defined in a Python file: functions, classes, methods."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out: set[str] = set()

    def walk(node, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = prefix + child.name
                out.add(name)
                if isinstance(child, ast.ClassDef):
                    walk(child, name + ".")

    walk(tree, "")
    return out


class Resolver:
    def __init__(self, root: Path, registry: dict[str, dict]):
        self.root = root.resolve()
        self.registry = registry
        self._cache: dict[Path, set[str] | None] = {}

    def _file(self, rel: str) -> Path | None:
        p = (self.root / rel).resolve()
        if self.root not in p.parents or not p.is_file():
            return None
        return p

    def _names(self, p: Path) -> set[str] | None:
        if p not in self._cache:
            try:
                self._cache[p] = _defs(p)
            except (OSError, SyntaxError, UnicodeError):
                self._cache[p] = None
        return self._cache[p]

    def enforcement(self, ref: str) -> str | None:
        """None when the reference resolves, else why not."""
        m = ENFORCEMENT.match(ref or "")
        if not m:
            return f"enforcement_path {ref!r} is not file.py or file.py::Name"
        p = self._file(m.group(1))
        if p is None:
            return f"enforcement file {m.group(1)!r} not found under the root"
        if m.group(2):
            names = self._names(p)
            if names is None or m.group(2) not in names:
                return f"{m.group(2)!r} is not defined in {m.group(1)}"
        return None

    def evidence(self, ref: str) -> str | None:
        m = EVIDENCE.match(ref) if isinstance(ref, str) else None
        if not m:
            return f"evidence {ref!r} is not tests/file.py::test_name"
        if not m.group(2).startswith("test"):
            return f"evidence {ref!r} does not name a test function"
        p = self._file(m.group(1))
        if p is None:
            return f"evidence file {m.group(1)!r} not found under the root"
        names = self._names(p)
        if names is None or m.group(2) not in names:
            return f"test {m.group(2)!r} is not defined in {m.group(1)}"
        return None

    def pin(self, mutant_id: str, claim_id: str) -> str | None:
        row = self.registry.get(mutant_id) if isinstance(mutant_id, str) else None
        if row is None:
            return f"pin {mutant_id!r} is not in the mutant registry"
        if row.get("claim_id") != claim_id:
            return f"pin {mutant_id!r} is registered for {row.get('claim_id')!r}"
        return None


def load_registry(path: Path) -> dict[str, dict]:
    if not path.is_file():
        return {}
    data = _strict_load(path.read_text(encoding="utf-8")) or {}
    rows = data.get("mutants", []) if isinstance(data, dict) else []
    return {r["id"]: r for r in rows if isinstance(r, dict) and "id" in r}


def supported_status(row: dict, res: Resolver) -> str:
    enf_ok = res.enforcement(row.get("enforcement_path", "")) is None
    ev = row.get("evidence") or []
    ev_ok = bool(ev) and all(res.evidence(e) is None for e in ev)
    pins = row.get("pins") or []
    pins_ok = bool(pins) and all(res.pin(p, row.get("claim_id")) is None for p in pins)
    if enf_ok and ev_ok and pins_ok:
        return "REAL"
    if enf_ok and ev_ok:
        return "PARTIAL"
    if enf_ok:
        return "STUBBED"
    return "PLANNED"


def check_row(row, res: Resolver) -> list[Finding]:
    if not isinstance(row, dict):
        return [Finding("?", "SCHEMA", "claim row is not a mapping")]
    cid = row.get("claim_id")
    cid_s = cid if isinstance(cid, str) and cid else "?"
    out: list[Finding] = []

    def bad(code: str, msg: str) -> None:
        out.append(Finding(cid_s, code, msg))

    missing = [k for k in REQUIRED if k not in row]
    if missing:
        bad("SCHEMA", "missing field(s): " + ", ".join(missing))
    unknown = sorted(str(k) for k in row if k not in REQUIRED + OPTIONAL)
    if unknown:
        bad("SCHEMA", "unknown field(s): " + ", ".join(unknown))
    if not isinstance(cid, str) or not CLAIM_ID.match(cid):
        bad("SCHEMA", f"claim_id {cid!r} is not UPPER-KEBAB")
    text = row.get("text")
    if not isinstance(text, str) or not text.strip():
        bad("SCHEMA", "text is empty or not a string")
        text = ""
    elif "\n" in text.strip():
        bad("SCHEMA", "text spans more than one line")
    status = row.get("status")
    if status not in STATUS_RANK:
        bad("SCHEMA", f"status {status!r} not one of {', '.join(STATUS_RANK)}")
    enf = row.get("enforcement_path")
    if not isinstance(enf, str):
        bad("SCHEMA", "enforcement_path is not a string")
    ev = row.get("evidence")
    if not isinstance(ev, list):
        bad("SCHEMA", "evidence is not a list")
    pins = row.get("pins", [])
    if not isinstance(pins, list):
        bad("SCHEMA", "pins is not a list")
    if out:
        return out

    if "\u2014" in text or "\u2013" in text:
        bad("STYLE", "text holds an em or en dash")
    low = text.casefold()
    for word in THEATER:
        if word in low:
            bad("THEATER", f"text uses {word!r}")
    if NAME_FENCE.search(text) or NAME_FENCE.search(enf):
        bad("NAME_FENCE", "ClaimGate is CI on claims, never Gate.evaluate")
    if "claimgate" in enf.casefold() and re.search(r"\btool[- ]call", low):
        bad("NAME_FENCE", "a runtime tool-call claim cannot be enforced by ClaimGate")

    if STATUS_RANK[status] >= STATUS_RANK["STUBBED"]:
        why = res.enforcement(enf)
        if why:
            bad("ENFORCEMENT", why)
    for e in ev:
        why = res.evidence(e)
        if why:
            bad("EVIDENCE", why)
    for p in pins:
        why = res.pin(p, cid)
        if why:
            bad("PIN", why)

    can = supported_status(row, res)
    if STATUS_RANK[status] > STATUS_RANK[can]:
        bad("OVERREACH", f"status {status} but the evidence supports {can}")
    if ABSOLUTE.search(text) and status != "REAL" and status != "RETIRED":
        bad("ABSOLUTE", f"absolute wording needs REAL, row is {status}")
    return out


def check_files(paths: list[Path], root: Path, registry_path: Path) -> list[Finding]:
    res = Resolver(root, load_registry(registry_path))
    out: list[Finding] = []
    seen: dict[str, str] = {}
    for path in paths:
        data = _strict_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or set(data) != {"claims"}:
            out.append(
                Finding("?", "SCHEMA", f"{path}: root must be {{claims: [...]}}")
            )
            continue
        rows = data["claims"]
        if not isinstance(rows, list) or not rows:
            out.append(
                Finding("?", "SCHEMA", f"{path}: claims must be a non-empty list")
            )
            continue
        for row in rows:
            out.extend(check_row(row, res))
            cid = row.get("claim_id") if isinstance(row, dict) else None
            if isinstance(cid, str):
                if cid in seen:
                    out.append(Finding(cid, "DUPLICATE", f"also in {seen[cid]}"))
                seen[cid] = str(path)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="claimgate", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="lint claims files")
    c.add_argument("files", nargs="*", default=["claimgate/claims.yaml"])
    c.add_argument("--root", default=".")
    c.add_argument("--registry", default=DEFAULT_REGISTRY)
    c.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    root = Path(args.root)
    try:
        findings = check_files(
            [Path(f) if Path(f).is_absolute() else root / f for f in args.files],
            root,
            root / args.registry,
        )
    except (OSError, yaml.YAMLError) as exc:
        print(f"claimgate: cannot read claims: {exc}")
        return 2
    if args.json:
        print(json.dumps([f.__dict__ for f in findings], sort_keys=True))
    else:
        for f in findings:
            print(f.line())
        print(f"claimgate: {len(findings)} finding(s) in {len(args.files)} file(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
