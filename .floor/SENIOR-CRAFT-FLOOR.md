# Senior craft floor — v0 (2026-08-18)

Goal: every allowlisted roof pushes code that reads like a careful senior engineer **and** like Landen on public surface — not like an agent dump.

## Honest bound

Automation **cannot** certify “Landen wrote this.” It can fail-closed on known AI/slop tells, missing changelog, hollow narration comments, and commit hygiene. Clone-fidelity still prefers your dictated spine for high-stakes egress; this floor is the catch-net under that.

Source patterns: skill `egress-voice` + authorship lock + Keep a Changelog discipline.

## Required CI jobs (add to `floor.yml`, then branch-protection)

| Job name (exact) | What it enforces |
|------------------|------------------|
| `craft (voice)` | Anti-slop / AI-vocab / trailer / chatbot phrases on commit range + `CHANGELOG*` / `README*` / `docs/**` / `*.md` touched in the PR |
| `craft (changelog)` | User-facing path changes require a `CHANGELOG.md` (or `CHANGELOG`) delta in the same range; Keep a Changelog section headers present |
| `craft (comments)` | Blocks narration-comment shapes in changed `*.py` (e.g. “This function…”, “Import the…”, “Loop through…”) — requires why/invariant comments when present, not play-by-play |
| existing | secrets, authorship, tests, lint (ruff) |

Local mirrors: pre-commit hooks calling the same scripts (convenience only; CI is control).

## Surfaces (“everything that leaves the seat”)

| Surface | Tool |
|---------|------|
| Commit messages | `voice_lint.py --commits` + existing no-AI-trailer |
| CHANGELOG / README / docs / PR body file | `voice_lint.py --paths` |
| Inline comments / docstrings in diff | `comment_craft.py --diff` |
| Version narrative | `changelog_gate.py` (+ optional `pyproject`/`__version__` bump warning) |

## Negative controls

1. Plant `Additionally, this pivotal landscape…` in a README → `craft (voice)` red.
2. Touch `src/` without CHANGELOG delta → `craft (changelog)` red.
3. Add `# This function reads the file` above a def → `craft (comments)` red.
4. Clean senior-style why-comment + CHANGELOG entry → all green.

## Verbs

`template-written` ≠ `installed on roof` ≠ `required in branch protection` ≠ `enforcing`.

## Fan-out

1. Land in vault `tools/repo-floor/`
2. `install_floor.py` copies scripts + updates workflow
3. Per roof: green Actions → add new contexts to branch protection
4. Never hand-widen `push_gate_allowlist` without these jobs required on that roof (once rolled)

## Out of scope for v0

- LLM-as-judge voice (false greens / cost / non-determinism)
- Forcing a comment on every function (noise > signal)
- School roofs without Landen GO
