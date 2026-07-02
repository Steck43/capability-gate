"""Tests for the Stage 1 tool-gate core. Each test names the security property
it pins so a reviewer can see coverage maps to claims, not just to lines."""

import json
import os

import pytest

import capability_gate as cg
from capability_gate import Gate, Verdict, load_policy, PolicyError, ENFORCE, OBSERVE


POLICY_DICT = {
    "require_approval": ["execute_code", "delete_file"],
    "skills": {
        "note-taker": {
            "tools": ["read_file", "write_file"],
            "paths": ["~/.hermes/notes/**"],
        },
        "web-researcher": {
            "tools": ["web_search", "read_file"],
            "paths": ["~/.hermes/research/**"],
        },
        "cleaner": {
            "tools": ["delete_file"],
            "paths": ["~/.hermes/tmp/**"],
        },
    },
}


@pytest.fixture()
def gate(tmp_path):
    policy = load_policy(POLICY_DICT)
    return Gate(policy, log_path=str(tmp_path / "decisions.jsonl"))


def home(rel):
    return os.path.join(os.path.expanduser("~"), rel)


# --- deny by default ------------------------------------------------------

def test_unknown_skill_denied(gate):
    d = gate.evaluate("unlisted-skill", "read_file", [home(".hermes/notes/a.md")])
    assert d.verdict is Verdict.DENY
    assert "not in allowlist" in d.reason


def test_tool_not_granted_denied(gate):
    # note-taker has no web_search grant
    d = gate.evaluate("note-taker", "web_search", [])
    assert d.verdict is Verdict.DENY
    assert "not granted" in d.reason


def test_path_outside_allowlist_denied(gate):
    d = gate.evaluate("note-taker", "read_file", [home(".ssh/id_rsa")])
    assert d.verdict is Verdict.DENY
    assert "outside allowlist" in d.reason


# --- allow on full match --------------------------------------------------

def test_allow_on_match(gate):
    d = gate.evaluate("note-taker", "write_file", [home(".hermes/notes/2026/log.md")])
    assert d.verdict is Verdict.ALLOW


def test_allow_pathless_tool(gate):
    # web_search touches no path; empty path list must not trip the path check
    d = gate.evaluate("web-researcher", "web_search", [])
    assert d.verdict is Verdict.ALLOW


# --- ask (Stage 3 hook, Stage 1 adapter maps this to block) ---------------

def test_require_approval_returns_ask(gate):
    d = gate.evaluate("cleaner", "delete_file", [home(".hermes/tmp/x")])
    assert d.verdict is Verdict.ASK
    assert "human approval" in d.reason


def test_approval_still_gated_by_path(gate):
    # even an approval-required tool is denied first if the path is out of scope
    d = gate.evaluate("cleaner", "delete_file", [home(".hermes/notes/keep.md")])
    assert d.verdict is Verdict.DENY


# --- fail closed ----------------------------------------------------------

def test_fail_closed_on_internal_error(gate, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("simulated bug in decision path")
    monkeypatch.setattr(cg, "_decide", boom)
    d = gate.evaluate("note-taker", "read_file", [home(".hermes/notes/a.md")])
    assert d.verdict is Verdict.DENY
    assert "failing closed" in d.reason


# --- log before act (write-ahead) -----------------------------------------

def test_decision_logged_before_return(tmp_path):
    log = tmp_path / "decisions.jsonl"
    g = Gate(load_policy(POLICY_DICT), log_path=str(log))
    g.evaluate("note-taker", "write_file", [home(".hermes/notes/a.md")])
    g.evaluate("unlisted", "read_file", [])
    lines = log.read_text().strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["verdict"] == "allow" and first["skill"] == "note-taker"
    assert "ts" in first
    second = json.loads(lines[1])
    assert second["verdict"] == "deny"


# --- glob semantics -------------------------------------------------------

def test_doublestar_crosses_directories():
    r = cg._glob_to_regex("/a/**")
    assert r.match("/a/b/c/d.txt")
    assert r.match("/a/b")
    assert not r.match("/other/b")


def test_singlestar_stays_in_segment():
    r = cg._glob_to_regex("/a/*.md")
    assert r.match("/a/note.md")
    assert not r.match("/a/sub/note.md")


# --- load-time validation -------------------------------------------------

def test_malformed_policy_raises_at_load():
    bad = {"skills": {"x": {"tools": "read_file", "paths": []}}}  # tools must be a list
    with pytest.raises(PolicyError):
        load_policy(bad)


# --- mode: enforce is the default, and it acts -----------------------------

def test_enforce_is_default_and_marks_enforced(tmp_path):
    g = Gate(load_policy(POLICY_DICT), log_path=str(tmp_path / "d.jsonl"))
    assert g.mode == ENFORCE
    d = g.evaluate("note-taker", "web_search", [])  # ungranted -> deny
    assert d.verdict is Verdict.DENY and d.enforced is True


def test_invalid_mode_raises_at_construction(tmp_path):
    with pytest.raises(ValueError):
        Gate(load_policy(POLICY_DICT), log_path=str(tmp_path / "d.jsonl"), mode="watch")


# --- mode: observe decides and logs, but never acts ------------------------

def test_observe_denies_in_verdict_but_not_enforced(tmp_path):
    log = tmp_path / "d.jsonl"
    g = Gate(load_policy(POLICY_DICT), log_path=str(log), mode=OBSERVE)
    d = g.evaluate("rogue-skill", "read_file", [home(".hermes/notes/a.md")])
    # the true verdict is still deny, so the log tells the truth ...
    assert d.verdict is Verdict.DENY
    # ... but it is not enforced, so the adapter will allow it through
    assert d.enforced is False
    rec = json.loads(log.read_text().strip().splitlines()[-1])
    assert rec["verdict"] == "deny" and rec["mode"] == "observe" and rec["enforced"] is False


def test_observe_allow_still_allows(tmp_path):
    g = Gate(load_policy(POLICY_DICT), log_path=str(tmp_path / "d.jsonl"), mode=OBSERVE)
    d = g.evaluate("note-taker", "write_file", [home(".hermes/notes/a.md")])
    assert d.verdict is Verdict.ALLOW


def test_observe_does_not_enforce_even_on_internal_error(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("bug during observe rollout")
    monkeypatch.setattr(cg, "_decide", boom)
    g = Gate(load_policy(POLICY_DICT), log_path=str(tmp_path / "d.jsonl"), mode=OBSERVE)
    d = g.evaluate("note-taker", "read_file", [home(".hermes/notes/a.md")])
    # observe enforces nothing, including its own errors: verdict is deny (logged),
    # enforced is false (not acted on). protection is an enforce-mode property.
    assert d.verdict is Verdict.DENY and d.enforced is False


# --- path expansion: ~ and $VARS, portable across Hermes homes -------------

def test_env_var_in_path_expands_and_matches(tmp_path, monkeypatch):
    home = tmp_path / "hermes-home"
    monkeypatch.setenv("HERMES_HOME", str(home))
    policy = load_policy({
        "skills": {"note-taker": {"tools": ["write_file"], "paths": ["$HERMES_HOME/notes/**"]}},
    })
    g = Gate(policy, log_path=str(tmp_path / "d.jsonl"))
    inside = str(home / "notes" / "day.md")
    outside = str(home / "secrets" / "key")
    assert g.evaluate("note-taker", "write_file", [inside]).verdict is Verdict.ALLOW
    assert g.evaluate("note-taker", "write_file", [outside]).verdict is Verdict.DENY


def test_unset_env_var_fails_closed(tmp_path, monkeypatch):
    # HERMES_HOME not set: the glob stays literal "$HERMES_HOME/..." and matches
    # no real path, so the grant is effectively empty and the call is denied.
    monkeypatch.delenv("HERMES_HOME", raising=False)
    policy = load_policy({
        "skills": {"note-taker": {"tools": ["write_file"], "paths": ["$HERMES_HOME/notes/**"]}},
    })
    g = Gate(policy, log_path=str(tmp_path / "d.jsonl"))
    d = g.evaluate("note-taker", "write_file", ["/home/landen/.hermes/notes/day.md"])
    assert d.verdict is Verdict.DENY


# --- skill-agnostic "*" bucket (Stage 1 fallback when skill id is absent) ---
# Proves the skill-agnostic path is pure policy convention: a skill keyed "*"
# plus the adapter passing skill="*". No core change. Deny-by-default holds.

def test_star_bucket_is_pure_convention(tmp_path):
    policy = load_policy({
        "skills": {"*": {"tools": ["read_file", "write_file"], "paths": ["/work/**"]}},
    })
    g = Gate(policy, log_path=str(tmp_path / "d.jsonl"))
    assert g.evaluate("*", "read_file", ["/work/a.md"]).verdict is Verdict.ALLOW      # granted
    assert g.evaluate("*", "web_search", []).verdict is Verdict.DENY                   # tool not granted
    assert g.evaluate("*", "read_file", ["/etc/passwd"]).verdict is Verdict.DENY       # path off-grant


# --- identity protection by path shape, not blocklist ----------------------
# The `memories/*/**` shape (one wildcard segment before **) grants a memory
# SUBTREE while leaving top-level identity files (USER.md, SOUL.md at the
# memories root) structurally unreachable. This holds in both Branch A and the
# Branch B "*" bucket, and cannot be gotten wrong the way a maintained
# exclude-list can.

def test_memory_subtree_shape_protects_identity(tmp_path, monkeypatch):
    home = tmp_path / "hermes-home"
    monkeypatch.setenv("HERMES_HOME", str(home))
    policy = load_policy({
        "skills": {"note-taking": {"tools": ["write_file"], "paths": ["$HERMES_HOME/memories/*/**"]}},
    })
    g = Gate(policy, log_path=str(tmp_path / "d.jsonl"))
    subtree = str(home / "memories" / "notes" / "day.md")
    identity = str(home / "memories" / "USER.md")
    soul = str(home / "SOUL.md")
    assert g.evaluate("note-taking", "write_file", [subtree]).verdict is Verdict.ALLOW
    assert g.evaluate("note-taking", "write_file", [identity]).verdict is Verdict.DENY
    assert g.evaluate("note-taking", "write_file", [soul]).verdict is Verdict.DENY
