"""C4 write boundary, option a3: the decision log is checked against a signed checkpoint.

Each attack below is the reviewer's C4 attack (attack_c4.py, sha256 59c6788c...)
with one change: before the attack, the CI signer has signed a checkpoint of
the four honest rows. Without a checkpoint the attacks are allowed
(attack_c4.out: A1, A2 and A3b ALLOW). With one, each is denied, because the
signing key is not on the box. A4 is the signer's own rule: it signs a new
checkpoint only when a consistency proof shows the log extends the last one.

The keys here are test keys made per test. No real key is read or printed.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

import capability_gate as cgm
from capability_gate import (
    CheckpointConfig,
    CheckpointError,
    Gate,
    Verdict,
    checkpoint_request,
    checkpoint_vkey,
    load_policy,
    read_checkpoint,
    sign_extending,
)

ed25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")

ORIGIN = "capability-gate/test/decisions"


def _pub(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


@pytest.fixture
def signer():
    key = ed25519.Ed25519PrivateKey.generate()
    return key, checkpoint_vkey("cg-test-signer", _pub(key))


def _policy(work: Path):
    return load_policy(
        {"skills": {"s": {"tools": ["write_file"], "paths": [str(work) + "/**"]}}}
    )


def _sign_now(log: Path, cfg: CheckpointConfig, key, *, first: bool = False) -> str:
    """What the CI job does: take the request, check it extends, sign, store the note."""
    req = checkpoint_request(str(log), cfg, first=first)
    latest = cgm._cp_latest(cfg.folder)
    prev = Path(latest[0]).read_text(encoding="utf-8") if latest else None
    note = sign_extending(prev, req, cfg.vkey, key)
    Path(cfg.folder, f"{req['size']}.note").write_text(
        note, encoding="utf-8", newline=""
    )
    return note


def _setup(tmp_path: Path, signer, anchor=None):
    """Four honest decisions, then a signed checkpoint of all four."""
    key, vkey = signer
    work = tmp_path / "work"
    work.mkdir()
    log = tmp_path / "logs" / "decisions.jsonl"
    folder = tmp_path / "checkpoints"
    folder.mkdir()
    cfg = CheckpointConfig(str(folder), vkey, ORIGIN)
    _sign_now(log, cfg, key, first=True)  # size 0, before any row
    g = Gate(
        _policy(work),
        log_path=str(log),
        anchor_path=anchor(tmp_path) if anchor else None,
        checkpoint=cfg,
    )
    for _ in range(4):
        assert (
            g.evaluate("s", "write_file", [str(work / "a.md")]).verdict is Verdict.ALLOW
        )
    _sign_now(log, cfg, key)
    return work, log, g, cfg


def _forge(log: Path, targets) -> None:
    """The reviewer's forge: keep two rows, rewrite witness and anchor to match."""
    kept = log.read_text(encoding="utf-8").splitlines(keepends=True)[:2]
    log.write_text("".join(kept), encoding="utf-8")
    head = hashlib.sha256(kept[-1].rstrip("\n").encode()).hexdigest()
    for t in targets:
        Path(t).parent.mkdir(parents=True, exist_ok=True)
        Path(t).write_text(
            json.dumps({"count": 2, "head": head}) + "\n", encoding="utf-8"
        )


def _denied(g: Gate, work: Path) -> str:
    """A deny, or the raised error an enforce gate gives when it cannot record
    its own decision (the adapter blocks on it); never an allow. As
    test_witness_tamper._not_allowed."""
    try:
        d = g.evaluate("s", "write_file", [str(work / "a.md")])
    except ValueError as exc:
        return str(exc)
    assert d.verdict is Verdict.DENY, d.reason
    return d.reason


def _operator_anchor(t: Path) -> str:
    return str(t / "operator" / "audit.anchor")


# ---- The attacks ----


def test_A1_all_three_rewritten_coherently_is_denied(tmp_path, signer):
    work, log, g, _cfg = _setup(tmp_path, signer, _operator_anchor)
    _forge(log, [str(log) + ".witness", _operator_anchor(tmp_path)])
    assert "signed checkpoint covers 4" in _denied(g, work)


def test_A2_anchor_swapped_for_a_symlink_is_denied(tmp_path, signer):
    work, log, g, _cfg = _setup(tmp_path, signer, _operator_anchor)
    evil = work / "evil.anchor"
    _forge(log, [str(log) + ".witness", str(evil)])
    op = Path(_operator_anchor(tmp_path))
    op.unlink()
    try:
        op.symlink_to(evil)
    except OSError:
        pytest.skip("this account cannot make symlinks")
    assert "symlink" in _denied(g, work)


def test_A3b_relocated_default_anchor_rewritten_is_denied(
    tmp_path, signer, monkeypatch
):
    monkeypatch.setattr(
        cgm,
        "_anchor_path",
        lambda lp: str(Path(lp).parent.parent / "elsewhere" / "audit.anchor"),
    )
    work, log, g, _cfg = _setup(tmp_path, signer)
    _forge(log, [str(log) + ".witness", cgm._anchor_path(str(log))])
    assert "signed checkpoint" in _denied(g, work)


def test_A4_the_signer_refuses_a_rewritten_log(tmp_path, signer):
    key, _ = signer
    _work, log, _g, cfg = _setup(tmp_path, signer)
    prev = Path(cfg.folder, "4.note").read_text(encoding="utf-8")
    # The agent rewrites history and adds rows, then asks for a fresh checkpoint.
    rows = log.read_text(encoding="utf-8").splitlines(keepends=True)
    rows[1] = rows[1].replace('"allow"', '"deny"')
    log.write_text("".join(rows) + rows[-1], encoding="utf-8")
    leaves = [cgm._cp_leaf(x) for x in cgm._cp_log_lines(str(log))]
    forged = {
        "origin": ORIGIN,
        "old_size": 4,
        "size": len(leaves),
        "root": cgm._cp_b64(cgm._cp_root(leaves)),
        "proof": [cgm._cp_b64(h) for h in cgm._cp_consistency_proof(4, leaves)],
    }
    with pytest.raises(CheckpointError, match="does not extend"):
        sign_extending(prev, forged, cfg.vkey, key)
    # The request tool itself refuses too: the log no longer matches the note.
    with pytest.raises(CheckpointError):
        checkpoint_request(str(log), cfg)


@pytest.mark.parametrize(
    "change",
    [
        {"old_size": 0},  # claim nothing was signed before
        {"old_size": 2},  # claim a smaller signed prefix
        {"origin": "capability-gate/other/decisions"},
        {"proof": []},
    ],
)
def test_A4_requests_that_skip_the_signed_prefix_are_refused(tmp_path, signer, change):
    key, _ = signer
    work, log, g, cfg = _setup(tmp_path, signer)
    g.evaluate("s", "write_file", [str(work / "a.md")])
    prev = Path(cfg.folder, "4.note").read_text(encoding="utf-8")
    req = checkpoint_request(str(log), cfg)
    req.update(change)
    with pytest.raises(CheckpointError):
        sign_extending(prev, req, cfg.vkey, key)


def test_honest_rows_extend_and_the_next_checkpoint_is_signed(tmp_path, signer):
    key, _ = signer
    work, log, g, cfg = _setup(tmp_path, signer)
    for _ in range(3):
        assert (
            g.evaluate("s", "write_file", [str(work / "a.md")]).verdict is Verdict.ALLOW
        )
    note = _sign_now(log, cfg, key)
    assert read_checkpoint(note, cfg.vkey)[:2] == (ORIGIN, 7)
    assert g.evaluate("s", "write_file", [str(work / "a.md")]).verdict is Verdict.ALLOW


# ---- Fail closed on the checkpoint itself ----


def test_a_note_signed_by_another_key_is_refused(tmp_path, signer):
    work, log, g, cfg = _setup(tmp_path, signer)
    other = ed25519.Ed25519PrivateKey.generate()
    leaves = [cgm._cp_leaf(x) for x in cgm._cp_log_lines(str(log))[:2]]
    fake = cgm.sign_checkpoint(ORIGIN, 9, cgm._cp_root(leaves), "cg-test-signer", other)
    Path(cfg.folder, "9.note").write_text(fake, encoding="utf-8", newline="")
    assert "pinned key" in _denied(g, work)


def test_a_symlinked_note_is_refused(tmp_path, signer):
    work, _log, g, cfg = _setup(tmp_path, signer)
    note = Path(cfg.folder, "4.note")
    copy = tmp_path / "copy.note"
    copy.write_bytes(note.read_bytes())
    note.unlink()
    try:
        note.symlink_to(copy)
    except OSError:
        pytest.skip("this account cannot make symlinks")
    assert "symlink" in _denied(g, work)


@pytest.mark.parametrize("target", ["anchor", "note"])
def test_a_wrong_owner_anchor_or_note_is_refused(tmp_path, signer, monkeypatch, target):
    work, _log, g, cfg = _setup(tmp_path, signer, _operator_anchor)
    owned = (
        _operator_anchor(tmp_path)
        if target == "anchor"
        else str(Path(cfg.folder, "4.note"))
    )
    real_lstat = os.lstat

    class Other:
        def __init__(self, st):
            self._st = st

        def __getattr__(self, name):
            return self._st.st_uid + 1 if name == "st_uid" else getattr(self._st, name)

    def lstat(path, *a, **k):
        st = real_lstat(path, *a, **k)
        return Other(st) if os.path.abspath(path) == os.path.abspath(owned) else st

    monkeypatch.setattr(cgm.os, "lstat", lstat)
    if not hasattr(os, "getuid"):
        monkeypatch.setattr(
            cgm.os, "getuid", lambda: real_lstat(owned).st_uid, raising=False
        )
    assert "owned by another user" in _denied(g, work)


def test_no_note_in_the_folder_is_denied(tmp_path, signer):
    work, _log, g, cfg = _setup(tmp_path, signer)
    for f in Path(cfg.folder).iterdir():
        f.unlink()
    assert "no signed checkpoint" in _denied(g, work)


def test_a_note_for_another_origin_is_refused(tmp_path, signer):
    _key, vkey = signer
    work, log, _g, cfg = _setup(tmp_path, signer)
    other = CheckpointConfig(cfg.folder, vkey, "capability-gate/other/decisions")
    g2 = Gate(_policy(work), log_path=str(log), checkpoint=other)
    assert "another log" in _denied(g2, work)


def test_the_checkpoint_folder_is_a_guarded_name(tmp_path, signer):
    _work, log, _g, cfg = _setup(tmp_path, signer)
    policy = load_policy(
        {"skills": {"s": {"tools": ["write_file"], "paths": [str(tmp_path) + "/**"]}}}
    )
    g2 = Gate(policy, log_path=str(log), checkpoint=cfg)
    d = g2.evaluate("s", "write_file", [str(Path(cfg.folder, "9.note"))])
    assert d.verdict is Verdict.DENY and "signed checkpoint folder" in d.reason


# ---- RFC 9162 trees and consistency proofs ----


@pytest.mark.parametrize("n", range(34))
def test_every_prefix_proof_verifies_and_a_changed_leaf_does_not(n):
    leaves = [cgm._cp_leaf(f"row {i}".encode()) for i in range(n)]
    new_root = cgm._cp_root(leaves)
    for m in range(n + 1):
        old_root = cgm._cp_root(leaves[:m])
        proof = cgm._cp_consistency_proof(m, leaves)
        assert cgm._cp_verify_consistency(m, n, old_root, new_root, proof), (m, n)
        if 0 < m:
            bent = list(leaves)
            bent[m - 1] = cgm._cp_leaf(b"rewritten")
            bad_proof = cgm._cp_consistency_proof(m, bent)
            bad_root = cgm._cp_root(bent)
            assert not cgm._cp_verify_consistency(
                m, n, old_root, bad_root, bad_proof
            ), (m, n)


def test_the_tree_hash_matches_rfc_9162_for_small_trees():
    a, b, c = (cgm._cp_leaf(x) for x in (b"a", b"b", b"c"))
    assert cgm._cp_root([]) == hashlib.sha256(b"").digest()
    assert cgm._cp_root([a]) == hashlib.sha256(b"\x00a").digest()
    ab = hashlib.sha256(b"\x01" + a + b).digest()
    assert cgm._cp_root([a, b, c]) == hashlib.sha256(b"\x01" + ab + c).digest()


def test_a_note_body_is_exactly_origin_size_and_root(signer):
    key, vkey = signer
    note = cgm.sign_checkpoint(ORIGIN, 3, b"\x07" * 32, "cg-test-signer", key)
    body = note.split("\n\n")[0].split("\n")
    assert body == [ORIGIN, "3", cgm._cp_b64(b"\x07" * 32)]
    assert note.split("\n\n")[1].startswith("\u2014 cg-test-signer ")
    assert read_checkpoint(note, vkey) == (ORIGIN, 3, b"\x07" * 32)
    padded = note.replace("\n3\n", "\n3\nextra line\n", 1)
    with pytest.raises(CheckpointError):
        read_checkpoint(padded, vkey)


# ---- Strip tests: take the boundary out and the attacks pass again ----


def test_strip_the_checkpoint_check_and_A1_is_allowed(tmp_path, signer, monkeypatch):
    work, log, g, _cfg = _setup(tmp_path, signer, _operator_anchor)
    monkeypatch.setattr(cgm, "_cp_check", lambda cfg, lines: None)
    _forge(log, [str(log) + ".witness", _operator_anchor(tmp_path)])
    assert g.evaluate("s", "write_file", [str(work / "a.md")]).verdict is Verdict.ALLOW


def test_strip_the_extends_rule_and_A4_is_signed(tmp_path, signer, monkeypatch):
    key, _ = signer
    _work, _log, _g, cfg = _setup(tmp_path, signer)
    prev = Path(cfg.folder, "4.note").read_text(encoding="utf-8")
    monkeypatch.setattr(cgm, "_cp_verify_consistency", lambda *a: True)
    leaves = [cgm._cp_leaf(b"forged")] * 5
    forged = {
        "origin": ORIGIN,
        "old_size": 4,
        "size": 5,
        "root": cgm._cp_b64(cgm._cp_root(leaves)),
        "proof": [],
    }
    assert (
        read_checkpoint(sign_extending(prev, forged, cfg.vkey, key), cfg.vkey)[1] == 5
    )


# ---- The signer command writes the same bytes on every platform ----


def test_the_sign_command_writes_utf8_notes(tmp_path, signer):
    import base64
    import subprocess

    key, vkey = signer
    seed = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    folder = tmp_path / "notes"
    folder.mkdir()
    cfg = CheckpointConfig(str(folder), vkey, ORIGIN)
    req = tmp_path / "req.json"
    req.write_text(json.dumps(checkpoint_request("absent.jsonl", cfg, first=True)))
    out = subprocess.run(
        [
            sys.executable,
            "-I",
            str(Path(cgm.__file__)),
            "checkpoint-sign",
            "--prev",
            "none",
            "--request",
            str(req),
            "--vkey",
            vkey,
        ],
        capture_output=True,
        env=dict(os.environ, CG_CHECKPOINT_SIGNING_KEY=base64.b64encode(seed).decode()),
        check=False,
    )
    assert out.returncode == 0, out.stdout
    assert "\u2014 cg-test-signer ".encode() in out.stdout
    assert read_checkpoint(out.stdout.decode("utf-8"), vkey)[:2] == (ORIGIN, 0)
