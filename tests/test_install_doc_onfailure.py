"""The Claude Code install snippet blocks on hook failure, and the docs state the same-user limit.

adapters/CLAUDE-CODE.md: every gate hook entry in the JSON snippet must set
"onFailure": "block". Without it, Claude Code runs the call when the hook
cannot start, crashes or times out. The 15 s timeout stays as it was.

README.md and SECURITY.md must carry the sentence that says an attacker
running as the agent's OS user can rewrite the log, the witness and the anchor
together, undetected. The strict expected failure for that attack stays in
tests/test_witness_tamper.py.

.well-known/security.txt must point to the private reporting route.

Each doc check has a strip test: the same check, run on a copy with the
setting or the sentence removed, must report it.
"""

import copy
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE_HOOK = "claude_code_hook.py"
SAME_USER_LIMIT = (
    "An attacker running as the same OS user as the agent can rewrite the log, "
    "the witness and the anchor together, and capability-gate does not detect it."
)


def _settings(doc: str) -> dict:
    blocks = [b for b in re.findall(r"```json\n(.*?)```", doc, re.S) if '"hooks"' in b]
    assert len(blocks) == 1, f"expected one hooks snippet, found {len(blocks)}"
    return json.loads(blocks[0])


def _gate_hooks(settings: dict) -> list[tuple[str, dict]]:
    return [
        (event, hook)
        for event, groups in settings["hooks"].items()
        for group in groups
        for hook in group["hooks"]
        if GATE_HOOK in json.dumps(hook)
    ]


def _missing_on_failure(settings: dict) -> list[str]:
    return [
        event
        for event, hook in _gate_hooks(settings)
        if hook.get("onFailure") != "block"
    ]


def _states_limit(text: str) -> bool:
    return SAME_USER_LIMIT in " ".join(text.split())


def _install_settings() -> dict:
    return _settings((ROOT / "adapters" / "CLAUDE-CODE.md").read_text(encoding="utf-8"))


def test_every_gate_hook_blocks_on_failure():
    settings = _install_settings()
    assert sorted(event for event, _ in _gate_hooks(settings)) == [
        "PostToolUse",
        "PreToolUse",
    ]
    assert _missing_on_failure(settings) == []


def test_gate_hook_timeout_stays_15():
    assert [hook.get("timeout") for _, hook in _gate_hooks(_install_settings())] == [
        15,
        15,
    ]


def test_snippet_check_reports_a_hook_without_on_failure():
    settings = _install_settings()
    for index, (event, _) in enumerate(_gate_hooks(settings)):
        stripped = copy.deepcopy(settings)
        del _gate_hooks(stripped)[index][1]["onFailure"]
        assert _missing_on_failure(stripped) == [event]


def test_docs_state_the_same_user_limit():
    for name in ("README.md", "SECURITY.md"):
        assert _states_limit((ROOT / name).read_text(encoding="utf-8")), name


def test_limit_check_reports_a_doc_without_the_sentence():
    for name in ("README.md", "SECURITY.md"):
        text = " ".join((ROOT / name).read_text(encoding="utf-8").split())
        assert not _states_limit(text.replace(SAME_USER_LIMIT, "")), name


def test_security_txt_points_to_private_reporting():
    fields = dict(
        line.split(": ", 1)
        for line in (ROOT / ".well-known" / "security.txt")
        .read_text(encoding="utf-8")
        .splitlines()
        if ": " in line
    )
    assert (
        fields["Contact"]
        == "https://github.com/Steck43/capability-gate/security/advisories/new"
    )
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", fields["Expires"])
    assert fields["Policy"].endswith("/SECURITY.md")
