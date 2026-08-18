#!/usr/bin/env python3
"""
surface_qc.py - cross-surface quality control for public claims.

Standard library only, by design, the same rule as the decider it audits.

Point it at any set of files that represent a public surface: repo READMEs,
exported profile text, resume text, post drafts. It sweeps for retired
framing, unscoped numbers, and taxonomy drift, and exits non-zero if any
BLOCK-severity finding is present.

    python3 surface_qc.py README.md ../Steck43/README.md surfaces/*.txt
    python3 surface_qc.py --list        # print the rule table and exit

Severities
    BLOCK  must not ship. Exit code 1.
    WARN   ship only with a stated reason.

Rule shape
    (id, severity, scope, pattern, require, what it catches, what to do)

    scope    "line"  evaluate per line
             "para"  evaluate per blank-line-delimited block
             "doc"   evaluate over the whole file. Use this when a claim
                     must be bound somewhere in the artifact, not restated
                     in every paragraph that mentions it.
    require  None    pattern is forbidden
             regex   pattern is allowed only if require also appears in the
                     same unit. That is how a claim gets bound to its scope
                     without the rule guessing at sentence boundaries.

Rules are data, not code. Add a row, get a check.
"""

import argparse
import re
import signal
import sys

RULES = [
    (
        "RETIRED-01",
        "BLOCK",
        "line",
        r"coordinated multi[- ]agent systems",
        None,
        "Retired thesis framing.",
        "Containment layer for autonomous agents.",
    ),
    (
        "RETIRED-02",
        "BLOCK",
        "line",
        r"[Ss]ecuring LLMs,? RAG,? and multi[- ]agent systems",
        None,
        "Retired marketing headline.",
        "Runtime containment for autonomous agents.",
    ),
    (
        "STALE-01",
        "BLOCK",
        "line",
        r"(runs|running|it runs) (today )?(in|on).{0,40}observe mode",
        None,
        "Observe mode stated as current. The gate is configured in enforce.",
        "Configured in enforce on my own agent profile.",
    ),
    (
        "OVER-01",
        "BLOCK",
        "line",
        r"\*\*Complete mediation\.\*\*|^- \*\*Complete mediation",
        None,
        "Unqualified complete-mediation principle. Measured liveness is far below it.",
        "Mediation at the hook, with the not-loaded caveat.",
    ),
    (
        "OVER-02",
        "BLOCK",
        "line",
        r"zero widening|no widening across",
        None,
        "The 10,000-run figure described as adversarial containment.",
        "Held by a 10,000-run invariant test (engine_discard_identity).",
    ),
    (
        "OVER-03",
        "BLOCK",
        "line",
        r"always[- ]invoked",
        None,
        "always_invoked_claim is false and contract-enforced.",
        "Do not claim it. State mediation at named chokepoints.",
    ),
    (
        "OVER-04",
        "BLOCK",
        "line",
        r"\b36\s*[xX]\b",
        None,
        "Price-table arithmetic on max_tokens presented as a measured attack.",
        "Omit, or label as a modeled projection.",
    ),
    (
        "OVER-05",
        "BLOCK",
        "line",
        (
            r"\bpublished\b[^.]{0,60}(governance design|schema|policy-engine|lab|harness)"
            r"|(lab|harness|schema|governance design)[^.]{0,80}\band published it\b"
        ),
        None,
        (
            "Publication claim for an artifact with no public locator. The lab harness and the "
            "Unified Policy-Engine Schema are both off the public tree."
        ),
        "Say designed, or cite the finding and state that the artifact lives elsewhere.",
    ),
    (
        "OVER-06",
        "WARN",
        "line",
        r"0 FALSE-DENY",
        None,
        "Zero false denials rests on n=4 benign controls.",
        "State the denominator or drop it.",
    ),
    (
        "OVER-07",
        "WARN",
        "line",
        r"7 FALSE-ALLOW",
        None,
        "Bare numerator. The honest and stronger form carries the denominator.",
        "Fourteen had a ground truth of deny, it caught seven.",
    ),
    (
        "OVER-08",
        "BLOCK",
        "line",
        r"cannot see multi[- ]call composition",
        None,
        "Attributes all seven residuals to composition. False against the receipt.",
        "Three classes: cross-call intent, single-call provenance, arg granularity.",
    ),
    (
        "OVER-09",
        "WARN",
        "line",
        r"jailed boot measured|measured jailed boot",
        None,
        "The ~958 ms figure is unverified from the current workspace.",
        "Drop the word measured.",
    ),
    (
        "OVER-10",
        "BLOCK",
        "line",
        r"\bin production\b|\bmy agent is safe\b|\bsecured my agent\b",
        None,
        "Kill-list phrasing.",
        "Configured enforce, own profile, named scope.",
    ),
    (
        "OVER-11",
        "WARN",
        "line",
        r"\badversarial ML\b",
        None,
        "crypto-signal-confluence is multi-signal ML, not adversarial ML.",
        "Multi-signal ML research instrument.",
    ),
    (
        "SCOPE-01",
        "WARN",
        "para",
        r"37 shadow evaluations",
        r"window|month",
        "The 37 without its window. That same 37 is the numerator of a 2.9% coverage figure.",
        "37 shadow evaluations over one month.",
    ),
    (
        "SCOPE-02",
        "WARN",
        "para",
        r"12 of 12|12/12",
        r"offline",
        "The deny-matrix match must carry the word offline.",
        "12 of 12 on an offline deny matrix.",
    ),
    (
        "SCOPE-03",
        "WARN",
        "doc",
        r"\b(judge|adjudicator)\b",
        r"not consumed|not yet consumed|not in live|[Bb]uilt and measured",
        "Adjudicator appears but the apply_verdict=False scope is stated nowhere in the artifact.",
        "Built and measured, not consumed in live adjudication.",
    ),
    (
        "SCOPE-04",
        "WARN",
        "doc",
        r"(runs|running|is|it is|[Cc]onfigured) in \*{0,2}enforce",
        r"own (agent |Hermes )?profile|a Hermes profile|local Hermes|rollout",
        "An in-enforce deployment claim with no profile scope anywhere in the artifact.",
        "Configured in enforce on my own agent profile.",
    ),
    (
        "PATH-01",
        "BLOCK",
        "para",
        r"canonicaliz|realpath",
        r"\bnot\b|lexical|normpath|is not on the decide path|does not resolve",
        "Canonicalization asserted. The gate matches lexically; realpath is not on the decide path.",
        "Normalized against granted scope, or state the limit explicitly.",
    ),
    (
        "TAX-01",
        "WARN",
        "line",
        r"\bGovern\.|\*\*Defend",
        None,
        "Build/Govern/Defend taxonomy. The other surfaces argue three planes.",
        "Floor, bounded adjudicator, isolation.",
    ),
    (
        "TAX-02",
        "BLOCK",
        "line",
        r"decides what is permitted",
        None,
        "Describes a layer that can permit. The adjudicator can only subtract.",
        "Can only subtract from what the floor allows, never widen.",
    ),
    (
        "TENURE-01",
        "WARN",
        "line",
        r"over six years|6\+ years of Navy",
        None,
        "Closed by Landen: nearly seven stands, the training pipeline is service time.",
        "Nearly seven years.",
    ),
    (
        "ATTRIB-01",
        "BLOCK",
        "line",
        r"Co-Authored-By|generated by (Claude|Cursor|an AI)|AI-generated",
        None,
        "AI authorship on a public artifact.",
        "Remove. The author line is Landen Stecker only.",
    ),
    (
        "ENC-01",
        "WARN",
        "line",
        "Â·|â|â",
        None,
        "Double-encoded UTF-8 (mojibake) from a bad write.",
        "Rewrite ASCII-only, or fix the encoding on write.",
    ),
]


def paragraphs(lines):
    """Yield (start_line_no, text) for each blank-line-delimited block."""
    buf, start = [], 1
    for num, line in enumerate(lines, 1):
        if line.strip():
            if not buf:
                start = num
            buf.append(line)
        elif buf:
            yield start, "\n".join(buf)
            buf = []
    if buf:
        yield start, "\n".join(buf)


def scan(paths):
    findings = []
    line_rules = [r for r in RULES if r[2] == "line"]
    para_rules = [r for r in RULES if r[2] == "para"]
    doc_rules = [r for r in RULES if r[2] == "doc"]

    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError as exc:
            findings.append((path, 0, "IO", "BLOCK", str(exc), ""))
            continue

        for num, line in enumerate(lines, 1):
            for rid, sev, _s, pattern, _r, what, fix in line_rules:
                if re.search(pattern, line):
                    findings.append((path, num, rid, sev, what, fix))

        for start, block in paragraphs(lines):
            for rid, sev, _s, pattern, require, what, fix in para_rules:
                if re.search(pattern, block) and not re.search(require, block):
                    findings.append((path, start, rid, sev, what, fix))

        whole = "\n".join(lines)
        for rid, sev, _s, pattern, require, what, fix in doc_rules:
            hit = re.search(pattern, whole)
            if hit and not re.search(require, whole):
                line_no = whole[: hit.start()].count("\n") + 1
                findings.append((path, line_no, rid, sev, what, fix))

    return findings


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("paths", nargs="*", help="surface files to check")
    ap.add_argument("--list", action="store_true", help="print the rule table and exit")
    args = ap.parse_args()

    if args.list:
        for rid, sev, scope, pattern, require, what, fix in RULES:
            kind = "forbid" if require is None else "require-with"
            print(f"{rid:12} {sev:6} {scope:5} {kind}")
            print(f"             {what}")
            print(f"             -> {fix}\n")
        return 0

    if not args.paths:
        ap.error("give at least one file, or --list")

    findings = scan(args.paths)
    order = {"BLOCK": 0, "WARN": 1}
    findings.sort(key=lambda f: (order.get(f[3], 2), f[0], f[1]))

    blocks = sum(1 for f in findings if f[3] == "BLOCK")
    warns = sum(1 for f in findings if f[3] == "WARN")

    if not findings:
        print(f"CLEAN  {len(args.paths)} surface(s), {len(RULES)} rules, 0 findings.")
        return 0

    for path, num, rid, sev, what, fix in findings:
        print(f"{sev:6} {rid:12} {path}:{num}")
        print(f"       {what}")
        if fix:
            print(f"       -> {fix}")
        print()

    print(f"{blocks} BLOCK, {warns} WARN across {len(args.paths)} surface(s).")
    return 1 if blocks else 0


if __name__ == "__main__":
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except (AttributeError, ValueError):
        pass
    sys.exit(main())
