# This test pins the receipt contract. A test-side fake can satisfy it until
# prove.rs emits a digest over a value the test cannot compute, such as a
# box-side nonce (A6).
"""One call, three bindings: atoms records the gate decision, the box echoes atoms' ticket.

test_siblings_pinned owns every presence and load check. The boundary test stays
red until the three named misses clear; fixture problems fail with "fixture:"
text instead. Clearing the misses in CI is a receipt contract, not a jailer
proof: Actions cannot boot the box, so the real run is attached from aegisbox.
The chain helper below stands in for the harness until the harness exists.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import inspect
import json
import os
import subprocess
import sys
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

import pytest
import yaml

ROOF = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOF))

from capability_gate import ENFORCE, Gate, Verdict, load_policy  # noqa: E402

_ATOMS = "aegis-atoms"
_ISOLATION = "isolation-layer"
_ENV = {
    _ATOMS: "AEGIS_ATOMS_ROOT",
    _ISOLATION: "ISOLATION_LAYER_ROOT",
}
# Same commits floor.yml checks out. Move both together, forward only.
_PINS = {
    _ATOMS: "46db989ea78e7bb635f46beaec6826817935de7e",
    _ISOLATION: "2a8bfa815b2bd7d2b3fe72c5b3a58155adefc716",
}
_DECISION_PARAMS = (
    "decision",
    "gate_decision",
    "gate",
    "capability_decision",
)
_CATALOG = "catalog/Aegis-Atoms-v0.yaml"
_HANDOFF = "scripts/conflicting_handoff.py"
# Keys from the json! summary in crates/isolation-manager/src/prove.rs.
_MANAGER_PROVE = "crates/isolation-manager/src/prove.rs"
_MANAGER_MODE = "jailed-via-helper"
_PROVE_BOOLS = (
    "vsock_roundtrip_ok",
    "vestibule_framed_ok",
    "dropbox_handoff_ok",
    "inspector_stage_ok",
    "inspector_vm_ok",
    "inspector_verdict_ok",
)
_SPOT_KEYS = (
    "kvm_absent",
    "host_invisible",
    "vsock_ok",
    "vestibule_framed_ok",
    "dropbox_handoff_ok",
    "inspector_stage_ok",
    "inspector_vm_ok",
    "inspector_verdict_ok",
)
# The box entry point the chain must call. It does not exist yet; it lands with
# the harness work. Until then misses 2 and 3 stay red by design.
_BOX_ENTRY = ("scripts/box_entry.py", "run")

MISS_DECISION = "gate decision was not the input to evaluate_tool_call"
MISS_ATOMS = "atoms result was not the input to the next step"
MISS_BOX = "box step is not a prove receipt bound to this call"


class PinnedMiss(AssertionError):
    """The one failure the strict xfails accept. Any other error fails the test."""


# ---------------------------------------------------------------- siblings


@dataclass(frozen=True)
class Siblings:
    atoms_root: Path
    isolation_root: Path
    engine: ModuleType
    handoff: ModuleType


def _require_sibling(name: str, rel: str) -> Path:
    raw = os.environ.get(_ENV[name], "").strip()
    candidates = [Path(raw)] if raw else []
    candidates.append(ROOF.parent / name)
    for root in candidates:
        if (root / rel).is_file():
            return root.resolve()
    raise AssertionError(f"missing sibling checkout: {name} ({rel})")


def _load_file_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_siblings() -> Siblings:
    atoms_root = _require_sibling(_ATOMS, "engine.py")
    if not (atoms_root / _CATALOG).is_file():
        raise AssertionError(f"missing sibling checkout: {_ATOMS} ({_CATALOG})")
    isolation_root = _require_sibling(_ISOLATION, _HANDOFF)
    prove = isolation_root / _MANAGER_PROVE
    # Present is not loaded: an empty touched file must not pass for the checkout.
    if not prove.is_file() or _MANAGER_MODE not in prove.read_text(encoding="utf-8"):
        raise AssertionError(f"{_ISOLATION} checkout has no real {_MANAGER_PROVE}")

    # A cached engine module wins over sys.path, so drop it before importing.
    sys.modules.pop("engine", None)
    if str(atoms_root) in sys.path:
        sys.path.remove(str(atoms_root))
    sys.path.insert(0, str(atoms_root))
    engine = importlib.import_module("engine")
    loaded = Path(engine.__file__).resolve()
    if not loaded.is_relative_to(atoms_root):
        raise AssertionError(
            f"engine loaded from {loaded}, not the pinned {atoms_root}"
        )

    handoff = _load_file_module("pinned_conflicting_handoff", isolation_root / _HANDOFF)
    # Run isolation code, not just find it: accept() is the box handoff rule.
    if (
        handoff.accept("CONFLICTING") is not True
        or handoff.accept("ALLOW") is not False
    ):
        raise AssertionError(f"{_HANDOFF} did not run the handoff rule")
    return Siblings(atoms_root, isolation_root, engine, handoff)


def _siblings_or_skip() -> Siblings:
    try:
        return _load_siblings()
    except Exception as exc:  # test_siblings_pinned raises the same error
        pytest.skip(f"siblings not pinned, test_siblings_pinned owns this red: {exc}")


def test_siblings_pinned() -> None:
    sib = _load_siblings()
    for name, root in ((_ATOMS, sib.atoms_root), (_ISOLATION, sib.isolation_root)):
        raw = os.environ.get(_ENV[name], "").strip()
        if raw:
            assert root == Path(raw).resolve(), (
                f"{name} resolved {root}, env pins {raw}"
            )
        # Right file contents at the wrong commit still passes the checks above.
        head = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
        )
        assert head.returncode == 0, f"{name} at {root}: {head.stderr.strip()}"
        assert head.stdout.strip() == _PINS[name], (
            f"{name} is at {head.stdout.strip()}, pinned {_PINS[name]}"
        )
        # Right commit with uncommitted files on top is a different tree.
        dirty = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain"],
            capture_output=True,
            text=True,
        )
        assert dirty.returncode == 0, f"{name} at {root}: {dirty.stderr.strip()}"
        assert dirty.stdout == "", f"{name} has uncommitted changes:\n{dirty.stdout}"
    assert Path(sib.engine.__file__).resolve().is_relative_to(sib.atoms_root)
    assert Path(sib.handoff.__file__).resolve().is_relative_to(sib.isolation_root)


# ---------------------------------------------------------------- receipts


@contextmanager
def _watch(owner, name: str):
    hits: list[tuple[tuple, dict, object]] = []
    real = getattr(owner, name)

    def wrapped(*args, **kwargs):
        out = real(*args, **kwargs)
        hits.append((args, kwargs, out))
        return out

    setattr(owner, name, wrapped)
    try:
        yield hits, real
    finally:
        setattr(owner, name, real)


def _bound_values(fn, args, kwargs) -> list:
    try:
        bound = inspect.signature(fn).bind(*args, **kwargs)
    except TypeError:
        return []
    bound.apply_defaults()
    return list(bound.arguments.values())


def _was_input(fn, obj, hits) -> bool:
    if obj is None:
        return False
    return any(
        any(value is obj for value in _bound_values(fn, args, kwargs))
        for args, kwargs, _out in hits
    )


def _decision_kwargs(fn, decision) -> dict:
    params = inspect.signature(fn).parameters
    for name in _DECISION_PARAMS:
        if name in params:
            return {name: decision}
    return {}


def _receipt_text(receipt) -> str:
    if receipt is None:
        return ""
    if isinstance(receipt, str):
        return receipt
    stdout = getattr(receipt, "stdout", None)
    if stdout:
        return str(stdout)
    return str(receipt)


def _get(receipt, key: str):
    if isinstance(receipt, Mapping):
        return receipt.get(key)
    return getattr(receipt, key, None)


def _is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_jailer_prove_receipt(receipt) -> bool:
    """True only after the prove.rs summary would emit: checks passed, not present."""
    if receipt is None:
        return False
    if "HANDOFF_OK" in _receipt_text(receipt):
        return False
    if _get(receipt, "mode") != _MANAGER_MODE:
        return False
    if not _get(receipt, "jail_id"):
        return False
    for key in ("time_to_userspace_ms", "time_to_workload_ms"):
        value = _get(receipt, key)
        if not _is_number(value) or value < 0:
            return False
    dropbox_hash = _get(receipt, "dropbox_hash")
    if not isinstance(dropbox_hash, str) or len(dropbox_hash) != 64:
        return False
    if any(_get(receipt, key) is not True for key in _PROVE_BOOLS):
        return False
    spots = _get(receipt, "spot_checks")
    if spots is None:
        return False
    return not any(_get(spots, key) is not True for key in _SPOT_KEYS)


def _call_digest(decision, tool: str, path: str) -> str:
    """The test computes this itself. A planted constant summary cannot carry it."""
    body = json.dumps([decision.verdict.value, decision.skill, tool, path])
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _decision_digest(decision) -> str:
    """What atoms must record to show it read the gate decision, not just accepted it."""
    body = json.dumps(
        [
            decision.verdict.value,
            decision.skill,
            decision.tool,
            list(decision.paths),
            decision.reason,
        ]
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _ticket_digest(ticket) -> str | None:
    """The box must echo this digest of the ticket atoms issued. The test never mints the ticket."""
    if not isinstance(ticket, str) or not ticket:
        return None
    return hashlib.sha256(ticket.encode("utf-8")).hexdigest()


def _content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _box_receipt_ok(receipt, call_digest: str, content: str) -> bool:
    """Prove-shaped, bound to this call, and the dropbox hash is the content argument handed to the box."""
    return (
        _is_jailer_prove_receipt(receipt)
        and _get(receipt, "call_digest") == call_digest
        and _get(receipt, "dropbox_hash") == _content_hash(content)
    )


def _prove_summary(
    *, passed: bool, call_digest: str | None = None, dropbox_hash: str = "a" * 64
) -> dict:
    """Shape of the json! in prove.rs. passed=False is a false-flag copy."""
    out = {
        "jail_id": "mgr-pin",
        "mode": _MANAGER_MODE,
        "time_to_userspace_ms": 1.2,
        "time_to_workload_ms": 3.4,
        **{key: passed for key in _PROVE_BOOLS},
        "dropbox_hash": dropbox_hash,
        "spot_checks": {key: passed for key in _SPOT_KEYS},
    }
    if call_digest is not None:
        out["call_digest"] = call_digest
    return out


def test_receipt_rule_rejects_flags_shapes_and_plants() -> None:
    passed = _prove_summary(passed=True)
    assert _is_jailer_prove_receipt(passed) is True
    assert _is_jailer_prove_receipt(_prove_summary(passed=False)) is False
    assert _is_jailer_prove_receipt("HANDOFF_OK CONFLICTING") is False
    assert _is_jailer_prove_receipt({**passed, "time_to_workload_ms": -1}) is False
    assert _is_jailer_prove_receipt({**passed, "dropbox_hash": "x"}) is False
    # A passing prove shape is rejected without this call's digest and content hash.
    bound = _prove_summary(
        passed=True, call_digest="0" * 64, dropbox_hash=_content_hash("x")
    )
    assert _box_receipt_ok(passed, "0" * 64, "x") is False
    assert _box_receipt_ok({**bound, "dropbox_hash": "a" * 64}, "0" * 64, "x") is False
    assert _box_receipt_ok(bound, "0" * 64, "x") is True


# ---------------------------------------------------------------- the chain


@dataclass
class Chain:
    decision: object
    atoms_result: object
    atoms_fn: object
    atoms_hits: list
    # Copied off atoms_result before the box runs, so the box cannot write them.
    decision_digest_seen: object
    ticket_seen: object
    box_hits: list
    receipt: object


def _box_entry(isolation_root: Path):
    rel, name = _BOX_ENTRY
    path = isolation_root / rel
    if not path.is_file():
        return None
    # box_entry may import its sibling scripts, as it would when run from scripts/.
    if str(path.parent) not in sys.path:
        sys.path.insert(0, str(path.parent))
    module = _load_file_module("pinned_box_entry", path)
    return (module, name) if callable(getattr(module, name, None)) else None


def _run_chain(
    sib: Siblings,
    gate: Gate,
    skill: str,
    tool: str,
    path: str,
    content: str,
    env: dict,
) -> Chain:
    """The order the harness must keep: gate, then atoms, then the box, each only if the last allowed."""
    with _watch(Gate, "evaluate") as (gate_hits, _):
        decision = gate.evaluate(skill, tool, [path])
    assert gate_hits, "Gate.evaluate was skipped"

    catalog = sib.engine.load_catalog(sib.atoms_root / _CATALOG, env)
    extra = _decision_kwargs(sib.engine.evaluate_tool_call, decision)
    with _watch(sib.engine, "evaluate_tool_call") as (atoms_hits, atoms_fn):
        atoms_result = sib.engine.evaluate_tool_call(
            catalog,
            tool,
            {"path": path, "content": content},
            env=env,
            plugin_mode=ENFORCE,
            **extra,
        )
    assert atoms_hits, "evaluate_tool_call was skipped"

    decision_digest_seen = getattr(atoms_result, "decision_digest", None)
    ticket_seen = getattr(atoms_result, "box_ticket", None)
    box_hits, receipt = [], None
    entry = _box_entry(sib.isolation_root)
    if entry is not None and atoms_result.block_message is None:
        module, name = entry
        with _watch(module, name) as (box_hits, _):
            receipt = getattr(module, name)(
                atoms_result=atoms_result,
                decision=decision,
                tool=tool,
                path=path,
                content=content,
            )
    return Chain(
        decision,
        atoms_result,
        atoms_fn,
        atoms_hits,
        decision_digest_seen,
        ticket_seen,
        box_hits,
        receipt,
    )


def _env(tmp_path: Path) -> dict:
    return {
        "HERMES_HOME": str(tmp_path),
        "OBSIDIAN_VAULT_PATH": str(tmp_path / "vault"),
    }


def _shipped_gate(tmp_path: Path, monkeypatch) -> Gate:
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    policy = load_policy(
        yaml.safe_load((ROOF / "allowlist.example.yaml").read_text(encoding="utf-8"))
    )
    return Gate(policy, log_path=str(tmp_path / "decisions.jsonl"), mode=ENFORCE)


# Today's misses, exactly: three per call, plus the repeat ticket (both None).
# Any change to this list, a miss closing or a new one, fails outright.
_PINNED_MISSES = [MISS_DECISION, MISS_ATOMS, MISS_BOX] * 2 + [MISS_ATOMS]


# Strict: green on main while the misses stand, XPASS fails once they all close.
# The xfail accepts only PinnedMiss, raised once below for the exact pinned list.
# Any other error, a plain assert here, a skipped gate or atoms step in
# _run_chain, or an error inside sibling code, fails the test outright.
@pytest.mark.xfail(
    strict=True,
    raises=PinnedMiss,
    reason="; ".join((MISS_DECISION, MISS_ATOMS, MISS_BOX)),
)
def test_one_write_needs_three_receipts(tmp_path: Path, monkeypatch) -> None:
    sib = _siblings_or_skip()
    gate = _shipped_gate(tmp_path, monkeypatch)
    env = _env(tmp_path)

    # Two calls, two contents. A constant ticket or a canned receipt cannot match both.
    runs = []
    for n in (1, 2):
        path = str(tmp_path / "notes" / f"boundary-{n}.md")
        content = f"boundary write {n}"
        chain = _run_chain(sib, gate, "*", "write_file", path, content, env)
        # The call must be one the shipped grant allows and atoms forwards, or the
        # misses below would be about a call that should never reach the box.
        if chain.decision.verdict is not Verdict.ALLOW:
            pytest.fail(
                f"fixture: shipped grant denied {path}: {chain.decision.reason}"
            )
        if chain.atoms_result.block_message is not None:
            pytest.fail(
                f"fixture: atoms blocked {path}: {chain.atoms_result.winning_effect}"
            )
        runs.append((chain, path, content))

    misses: list[str] = []
    for chain, path, content in runs:
        # A parameter named "decision" is not enough; atoms must record what it read.
        if not (
            _was_input(chain.atoms_fn, chain.decision, chain.atoms_hits)
            and chain.decision_digest_seen == _decision_digest(chain.decision)
        ):
            misses.append(MISS_DECISION)
        # Atoms issues the ticket before the box runs; the box receipt must echo it.
        ticket = _ticket_digest(chain.ticket_seen)
        if ticket is None or _get(chain.receipt, "ticket_digest") != ticket:
            misses.append(MISS_ATOMS)
        call = _call_digest(chain.decision, "write_file", path)
        if not _box_receipt_ok(chain.receipt, call, content):
            misses.append(MISS_BOX)
    if runs[0][0].ticket_seen == runs[1][0].ticket_seen:
        misses.append(MISS_ATOMS)
    if misses and misses != _PINNED_MISSES:
        pytest.fail(f"misses changed from the pinned list, update the xfail: {misses}")
    if misses:
        raise PinnedMiss("; ".join(dict.fromkeys(misses)))


def test_atoms_block_never_reaches_box(tmp_path: Path, monkeypatch) -> None:
    sib = _siblings_or_skip()
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    policy = load_policy(
        {"skills": {"*": {"tools": ["write_file"], "paths": [str(tmp_path / "**")]}}}
    )
    gate = Gate(policy, log_path=str(tmp_path / "decisions.jsonl"), mode=ENFORCE)
    chain = _run_chain(
        sib, gate, "*", "write_file", str(tmp_path / "SOUL.md"), "x", _env(tmp_path)
    )

    # Checks the stand-in chain's order only. It cannot see a box call atoms makes itself.
    assert chain.decision.verdict is Verdict.ALLOW, (
        f"fixture: grant denied SOUL.md: {chain.decision.reason}"
    )
    assert chain.atoms_result.block_message is not None, (
        "fixture: atoms forwarded SOUL.md"
    )
    assert chain.box_hits == [], "the box ran on a call atoms blocked"
    assert chain.receipt is None


_NO_DECISION_PARAM = "evaluate_tool_call has no parameter for the gate decision yet"


# Strict, same rule: the xfail accepts only PinnedMiss, raised for the missing
# decision parameter. A forward of a denied call, or any other error, fails outright.
def test_deny_decision_makes_atoms_block(tmp_path: Path, monkeypatch) -> None:
    sib = _siblings_or_skip()
    gate = _shipped_gate(tmp_path, monkeypatch)
    path = str(tmp_path / "outside.md")
    decision = gate.evaluate("*", "write_file", [path])
    if decision.verdict is not Verdict.DENY:
        pytest.fail(f"fixture: grant allowed {path}")

    extra = _decision_kwargs(sib.engine.evaluate_tool_call, decision)
    if not extra:
        raise PinnedMiss(_NO_DECISION_PARAM)
    catalog = sib.engine.load_catalog(sib.atoms_root / _CATALOG, _env(tmp_path))
    result = sib.engine.evaluate_tool_call(
        catalog,
        "write_file",
        {"path": path, "content": "x"},
        env=_env(tmp_path),
        plugin_mode=ENFORCE,
        **extra,
    )
    if result.block_message is None:
        pytest.fail("atoms forwarded a call the gate denied")
