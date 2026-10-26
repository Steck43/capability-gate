"""capability_gate_sdk: Phase A acceptance tests.

Each test names the class of bug it pins. The SDK is a thin wrapper, so the
risk is a wrapper that answers without asking the gate, swallows a load error,
or reports observe as enforce. The mutant tests at the bottom rebuild the SDK
with one control removed and require the oracle to go red for each one, so a
hollow ``check`` cannot pass this file.

Synthetic allowlists only; no network.
"""

from __future__ import annotations

import errno
import json
import os
import sys
import types
from pathlib import Path

import pytest

import capability_gate as cg
import capability_gate_sdk as sdk
from capability_gate import (
    ENFORCE,
    OBSERVE,
    Decision,
    Gate,
    Verdict,
    _hash_log_line,
)

# The repo root is on sys.path through the root conftest (pytest rootdir).
ROOF = Path(__file__).resolve().parents[1]
SDK_SOURCE = (ROOF / "capability_gate_sdk.py").read_text(encoding="utf-8")
MODES = (ENFORCE, OBSERVE)


def _policy_text(work: Path) -> str:
    return (
        "version: 1\n"
        "skills:\n"
        "  reader:\n"
        "    tools: [read_file, write_file, run_shell]\n"
        f"    paths: ['{work.as_posix()}/**']\n"
        "require_approval: [write_file]\n"
        "isolate: [run_shell]\n"
    )


class Box:
    """One synthetic workspace: policy, a granted file, a log folder."""

    def __init__(self, root: Path, mod: types.ModuleType = sdk) -> None:
        self.sdk = mod
        self.work = root / "work"
        self.work.mkdir(parents=True, exist_ok=True)
        self.ok_file = self.work / "a.txt"
        self.ok_file.write_text("x", encoding="utf-8")
        self.policy = root / "allowlist.yaml"
        self.policy.write_text(_policy_text(self.work), encoding="utf-8")
        self.logs = root / "logs"

    def log(self, name: str = "decisions.jsonl") -> Path:
        return self.logs / name

    def client(self, mode: str = ENFORCE, name: str = "decisions.jsonl"):
        return self.sdk.Client.from_files(self.policy, self.log(name), mode)

    def allow(self, c):
        return c.check("reader", "read_file", [str(self.ok_file)])

    def deny(self, c):
        return c.check("reader", "delete_everything", [str(self.ok_file)])

    def ask(self, c):
        return c.check("reader", "write_file", [str(self.ok_file)])

    def isolate(self, c):
        return c.check("reader", "run_shell", [str(self.ok_file)])


def _rows(log: Path) -> list[dict]:
    if not log.exists():
        return []
    return [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines() if x]


@pytest.fixture
def box(tmp_path: Path) -> Box:
    return Box(tmp_path)


# --- 2. refuse at load ------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        "skills: [unclosed\n",
        "skills: {}\nisolat: [run_shell]\n",
        "skills:\n  r:\n    tools: [t]\n    paths: ['$CG_SDK_UNSET_VAR/**']\n",
        "skills: {}\nisolate: [t]\nrequire_approval: [t]\n",
        "- just\n- a list\n",
    ],
    ids=[
        "malformed",
        "unknown-key",
        "unset-var",
        "isolate-and-approval",
        "not-mapping",
    ],
)
def test_bad_policy_refuses(box: Box, body: str, monkeypatch) -> None:
    """Class: a broken allowlist loads as an empty or partial grant."""
    monkeypatch.delenv("CG_SDK_UNSET_VAR", raising=False)
    box.policy.write_text(body, encoding="utf-8")
    with pytest.raises(sdk.ClientRefused):
        box.client()


def test_missing_policy_refuses(box: Box) -> None:
    """Class: a missing allowlist file gives a client anyway."""
    box.policy.unlink()
    with pytest.raises(sdk.ClientRefused):
        box.client()


class _Sneaky(str):
    pass


@pytest.mark.parametrize(
    "mode", ["Enforce", "", "observe ", None, 1, _Sneaky("enforce")]
)
def test_bad_mode_refuses(box: Box, mode) -> None:
    """Class: a typo or odd type in mode builds a client in an unknown mode."""
    with pytest.raises(sdk.ClientRefused):
        box.client(mode)


def test_direct_construct_refuses(box: Box) -> None:
    """Class: Client(...) skips the policy load and still answers."""
    with pytest.raises(sdk.ClientRefused):
        sdk.Client(object(), None, ENFORCE, str(box.log()), None, None)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX folder modes")
@pytest.mark.parametrize("mode", MODES)
def test_unwritable_log_folder_never_allows(box: Box, mode: str) -> None:
    """Class: a log folder the gate cannot write still lets a call through as enforced."""
    box.logs.mkdir()
    box.logs.chmod(0o500)
    try:
        if os.access(box.logs, os.W_OK):
            pytest.skip("folder mode is not enforced for this user (root)")
        try:
            c = box.client(mode)
        except sdk.ClientRefused:
            return
        d = box.allow(c)
        assert d.verdict is Verdict.DENY
        assert d.enforced is (mode == ENFORCE)
    finally:
        box.logs.chmod(0o700)


@pytest.mark.parametrize("mode", MODES)
def test_enospc_denies(box: Box, mode: str, monkeypatch) -> None:
    """Class: a full disk on the decision log write still lets a call through."""
    c = box.client(mode)
    assert box.allow(c).verdict is Verdict.ALLOW
    log = str(box.log())
    before = box.log().read_bytes()
    head = c.verify_log()

    real_open, real_write = os.open, os.write
    log_fds: set[int] = set()
    hits: list[int] = []

    def tracking_open(path, flags, *a, **k):
        fd = real_open(path, flags, *a, **k)
        if os.path.abspath(os.fspath(path)) == log and flags & os.O_APPEND:
            log_fds.add(fd)
        return fd

    def full_disk_write(fd, data):
        if fd in log_fds:
            hits.append(fd)
            raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC), log)
        return real_write(fd, data)

    monkeypatch.setattr(os, "open", tracking_open)
    monkeypatch.setattr(os, "write", full_disk_write)
    d = box.allow(c)
    monkeypatch.undo()

    assert hits, "ENOSPC was never raised on the decision log write"
    assert d.verdict is Verdict.DENY
    assert d.enforced is (mode == ENFORCE)
    assert sdk.may_run(d) is (mode == OBSERVE)
    assert box.log().read_bytes() == before
    assert c.verify_log() == head


# --- 1. check always asks the gate -------------------------------------------


def test_check_calls_evaluate_once_per_call(box: Box, monkeypatch) -> None:
    """Class: check answers from a cache or a constant instead of the gate."""
    calls = []
    real = Gate.evaluate

    def spy(self, *a, **k):
        calls.append((a, k))
        return real(self, *a, **k)

    monkeypatch.setattr(Gate, "evaluate", spy)
    c = box.client()
    box.allow(c)
    box.deny(c)
    box.allow(c)
    assert len(calls) == 3
    assert [r["verdict"] for r in _rows(box.log())] == ["allow", "deny", "allow"]


def test_check_passes_every_argument_through(box: Box, monkeypatch) -> None:
    """Class: check drops refuse or base_dir, so a refused call is decided on paths."""
    c = box.client()
    d = c.check("reader", "read_file", [str(box.ok_file)], refuse="unparseable args")
    assert d.verdict is Verdict.DENY and "arguments refused" in d.reason
    d = c.check("reader", "read_file", ["a.txt"])
    assert d.verdict is Verdict.DENY
    d = c.check("reader", "read_file", ["a.txt"], base_dir=str(box.work))
    assert d.verdict is Verdict.ALLOW


def test_real_gate_verdicts_and_rows(box: Box) -> None:
    """Class: the SDK reshapes or drops the gate's verdict or its log row."""
    c = box.client()
    got = [box.allow(c), box.deny(c), box.ask(c), box.isolate(c)]
    assert [d.verdict for d in got] == [
        Verdict.ALLOW,
        Verdict.DENY,
        Verdict.ASK,
        Verdict.ISOLATE,
    ]
    assert got[3].route_ticket
    assert [r["verdict"] for r in _rows(box.log())] == [
        "allow",
        "deny",
        "ask",
        "isolate",
    ]


# --- fail-closed on gate error ----------------------------------------------


@pytest.mark.parametrize("mode", MODES)
def test_gate_exception_is_deny(box: Box, mode: str, monkeypatch) -> None:
    """Class: an exception inside the gate escapes as allow, or as a crash the caller ignores."""

    def boom(self, *a, **k):
        raise RuntimeError("injected")

    c = box.client(mode)
    monkeypatch.setattr(Gate, "evaluate", boom)
    d = box.allow(c)
    assert d.verdict is Verdict.DENY
    assert d.enforced is (mode == ENFORCE)
    assert sdk.may_run(d) is (mode == OBSERVE)


@pytest.mark.parametrize("bad", [None, "allow", {"verdict": "allow"}])
def test_non_decision_is_deny(box: Box, bad, monkeypatch) -> None:
    """Class: a gate that returns something odd is read as a pass."""
    c = box.client()
    monkeypatch.setattr(Gate, "evaluate", lambda self, *a, **k: bad)
    d = box.allow(c)
    assert isinstance(d, Decision) and d.verdict is Verdict.DENY and d.enforced


# --- 3. broken chain ---------------------------------------------------------


def _edit_row(log: Path) -> None:
    lines = log.read_text(encoding="utf-8").splitlines(keepends=True)
    lines[0] = lines[0].replace('"allow"', '"ALLOW"', 1)
    log.write_text("".join(lines), encoding="utf-8")


def _cut_tail(log: Path) -> None:
    lines = log.read_text(encoding="utf-8").splitlines(keepends=True)
    log.write_text("".join(lines[:-1]), encoding="utf-8")


@pytest.mark.parametrize(
    "damage", [_edit_row, _cut_tail], ids=["edited-row", "cut-tail"]
)
def test_broken_chain_enforce_denies_and_verify_raises(box: Box, damage) -> None:
    """Class: a tampered log is appended to, or verify reports it clean."""
    c = box.client()
    box.allow(c)
    box.allow(c)
    damage(box.log())
    before = box.log().read_bytes()
    d = box.allow(c)
    assert d.verdict is Verdict.DENY and d.enforced is True
    assert sdk.may_run(d) is False
    assert box.log().read_bytes() == before
    with pytest.raises(ValueError):
        c.verify_log()


def test_broken_chain_observe_logs_nothing_and_blocks_nothing(box: Box) -> None:
    """Class: observe is described as stopping a call on a broken log. It does not."""
    c = box.client(OBSERVE)
    box.allow(c)
    _edit_row(box.log())
    d = box.allow(c)
    assert d.verdict is Verdict.DENY and d.enforced is False
    assert sdk.may_run(d) is True


def test_verify_log_returns_head(box: Box) -> None:
    """Class: verify_log returns a constant instead of the real head."""
    c = box.client()
    box.allow(c)
    box.deny(c)
    last = box.log().read_text(encoding="utf-8").splitlines()[-1]
    assert c.verify_log() == _hash_log_line(last)


# --- 4. kill switch ----------------------------------------------------------


def test_kill_switch_across_clients_and_modes(box: Box) -> None:
    """Class: a second client, or an observe client, does not see the thrown switch."""
    a = box.client()
    b = box.client()
    o = box.client(OBSERVE)
    assert sdk.may_run(box.allow(b))
    assert a.throw("drill") is True
    assert a.throw("again") is False
    for c in (a, b):
        for d in (box.allow(c), box.ask(c), box.isolate(c)):
            assert d.verdict is Verdict.DENY and "kill switch" in d.reason
            assert sdk.may_run(d) is False
    od = box.allow(o)
    assert od.verdict is Verdict.DENY and od.enforced is False
    assert sdk.may_run(od) is True
    assert _rows(box.log())[-1]["verdict"] == "deny"
    assert any(os.path.lexists(p) for p in a._gate.halt_paths)


def test_no_sdk_call_clears_the_switch(box: Box) -> None:
    """Class: an SDK helper removes the marker, so an agent can undo the stop."""
    surface = {n for n in dir(sdk.Client) if not n.startswith("_")}
    assert surface == {"from_files", "check", "verify_log", "throw", "mode"}
    assert set(sdk.__all__) == {
        "Client",
        "ClientRefused",
        "KillSwitchUnthrowable",
        "may_run",
    }
    c = box.client()
    c.throw("drill")
    c.verify_log()
    box.allow(c)
    assert box.deny(c).verdict is Verdict.DENY
    assert any(os.path.lexists(p) for p in c._gate.halt_paths)


# --- no set_mode, mode fixed --------------------------------------------------


def test_mode_is_fixed(box: Box) -> None:
    """Class: a caller flips a live client to observe."""
    c = box.client()
    assert not hasattr(c, "set_mode")
    with pytest.raises(AttributeError):
        c.mode = OBSERVE
    with pytest.raises(AttributeError):
        c.set_mode = lambda m: None


def test_gate_mode_drift_denies_enforced(box: Box) -> None:
    """Class: the private gate is flipped to observe and the client keeps answering."""
    c = box.client()
    c._gate.set_mode(OBSERVE)
    d = box.allow(c)
    assert d.verdict is Verdict.DENY and d.enforced is True
    assert sdk.may_run(d) is False


# --- 5. parity, 6. may_run table ---------------------------------------------


def test_observe_enforce_parity(box: Box) -> None:
    """Class: observe decides differently from enforce, so a shadow run proves nothing."""
    e = box.client(ENFORCE, "e.jsonl")
    o = box.client(OBSERVE, "o.jsonl")
    for c in (e, o):
        for step in (box.allow, box.deny, box.ask, box.isolate, box.allow):
            step(c)
    ev = [r["verdict"] for r in _rows(box.log("e.jsonl"))]
    ov = [r["verdict"] for r in _rows(box.log("o.jsonl"))]
    assert ev == ov == ["allow", "deny", "ask", "isolate", "allow"]
    assert {r["enforced"] for r in _rows(box.log("e.jsonl"))} == {True}
    assert {r["enforced"] for r in _rows(box.log("o.jsonl"))} == {False}


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "step,verdict",
    [
        ("allow", Verdict.ALLOW),
        ("deny", Verdict.DENY),
        ("ask", Verdict.ASK),
        ("isolate", Verdict.ISOLATE),
    ],
)
def test_may_run_table(box: Box, mode: str, step: str, verdict: Verdict) -> None:
    """Class: may_run lets ask or isolate run on the host in enforce, or blocks in observe."""
    d = getattr(box, step)(box.client(mode))
    assert d.verdict is verdict
    expected = verdict is Verdict.ALLOW or mode == OBSERVE
    assert sdk.may_run(d) is expected


@pytest.mark.parametrize(
    "bad", [None, True, "allow", {"verdict": "allow", "enforced": False}]
)
def test_may_run_rejects_non_decision(bad) -> None:
    """Class: may_run reads a dict or a truthy value as permission."""
    assert sdk.may_run(bad) is False


def test_may_run_thrown_row_enforced_is_no() -> None:
    """Class: the kill switch arming row is read as a pass in enforce."""
    assert (
        sdk.may_run(Decision(Verdict.THROWN, "x", "", "", (), enforced=True)) is False
    )


# --- 1. mutants: each removed control must turn the oracle red ---------------


def _oracle(mod: types.ModuleType, root: Path) -> None:
    """The load-bearing claims in one pass. Raises AssertionError on any miss."""
    b = Box(root, mod)
    c = b.client()
    assert b.allow(c).verdict is Verdict.ALLOW
    assert len(_rows(b.log())) == 1
    d = b.deny(c)
    assert d.verdict is Verdict.DENY and mod.may_run(d) is False
    assert mod.may_run(b.ask(c)) is False
    assert mod.may_run(b.isolate(c)) is False
    o = b.client(OBSERVE, "o.jsonl")
    assert mod.may_run(b.deny(o)) is True
    last = b.log().read_text(encoding="utf-8").splitlines()[-1]
    assert c.verify_log() == _hash_log_line(last)
    real = Gate.evaluate
    try:
        Gate.evaluate = lambda self, *a, **k: (_ for _ in ()).throw(RuntimeError("x"))
        assert mod.may_run(b.allow(c)) is False
    finally:
        Gate.evaluate = real
    c._gate.set_mode(OBSERVE)
    assert mod.may_run(b.allow(c)) is False
    c._gate.set_mode(ENFORCE)
    gone = Box(root / "missing", mod)
    gone.policy.unlink()
    try:
        gone.client()
    except mod.ClientRefused:
        pass
    else:
        raise AssertionError("missing policy built a client")


_EVAL = "decision = self._gate.evaluate("
MUTANTS = {
    "hollow-allow": (
        _EVAL,
        "decision = Decision(Verdict.ALLOW, 'm', str(skill), str(tool)) if True else self._gate.evaluate(",
    ),
    "hollow-deny": (
        _EVAL,
        "decision = Decision(Verdict.DENY, 'm', str(skill), str(tool)) if True else self._gate.evaluate(",
    ),
    "error-is-allow": (
        'return self._deny(skill, tool, f"sdk: gate raised, failing closed: {exc!r}")',
        "return Decision(Verdict.ALLOW, 'm', str(skill), str(tool))",
    ),
    "may-run-always": (
        "    if not isinstance(decision, Decision):\n        return False\n",
        "    return True\n",
    ),
    "may-run-ignores-enforced": (
        "    if decision.enforced is False:\n        return True\n",
        "",
    ),
    "verify-soft-pass": (
        "head = verify_hash_chain(",
        "head = '0' * 64 if True else verify_hash_chain(",
    ),
    "load-swallowed": (
        'raise ClientRefused(f"capability-gate client refused: {exc!r}") from exc',
        "return None",
    ),
    "drift-ignored": ("        if drifted:\n", "        if False:\n"),
}


def _build(source: str, name: str) -> types.ModuleType:
    # Other test modules reload capability_gate. Build every copy against the
    # gate module this file imported, so Verdict and Gate are the same objects
    # the oracle compares against and patches.
    mod = types.ModuleType(f"capability_gate_sdk_{name}")
    saved = sys.modules.get("capability_gate")
    sys.modules["capability_gate"] = cg
    try:
        exec(compile(source, f"<sdk mutant {name}>", "exec"), mod.__dict__)
    finally:
        if saved is None:
            sys.modules.pop("capability_gate", None)
        else:
            sys.modules["capability_gate"] = saved
    return mod


def test_oracle_passes_on_real_sdk(tmp_path: Path) -> None:
    """Class: the oracle is wrong, so every mutant 'dies' for the wrong reason."""
    _oracle(_build(SDK_SOURCE, "real"), tmp_path)


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_mutant_is_killed(tmp_path: Path, name: str) -> None:
    """Class: removing one control from the SDK leaves every test green."""
    old, new = MUTANTS[name]
    assert SDK_SOURCE.count(old) == 1, f"mutant anchor drifted: {name}"
    mod = _build(SDK_SOURCE.replace(old, new), name)
    with pytest.raises(AssertionError):
        _oracle(mod, tmp_path)
