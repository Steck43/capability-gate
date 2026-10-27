"""
The tool-gate. Stage 1, the decider.

An agent thinks and it acts. Thinking is text and it is harmless. Acting is a
tool call, and every real consequence runs through one. In most setups the line
from thought to action is unbroken. This closes it. The agent does not run the
tool. It asks the gate, and the gate answers allow, deny, or ask. The model
proposes. The gate disposes.

The decision is deterministic code I can read, not the probabilistic model I
cannot fully trust, because the model is the thing being guarded against.
Safety is a property of what a skill can reach, not of what the model can be
talked into. Deny by default. If it is not on the list, it does not happen.

This file is the decider only, and it holds no Hermes import on purpose. The
logic has to be testable without the runtime in the loop and swappable under a
clean boundary. The Hermes adapter is the doorway. This is the doorman.

Four properties, each pinned by a test:
- Deny by default. An unlisted skill, tool, or path is denied.
- Complete mediation. Every call and every path it touches is checked.
- Least privilege. A skill does only what its entry grants.
- Fail closed. Any error in the decision path is a denial. This one is
  load-bearing. The Hermes hook framework catches hook errors and lets the
  agent continue, so it fails open. A gate cannot lean on the thing it guards.
  It stops itself.

Log before act. The decision is flushed to durable storage before it returns,
so the record survives a crash mid-action and the audit trail is real from the
first day.

Two modes, for safe rollout. In enforce mode a denial blocks. In observe mode
the gate decides and logs exactly as it would, and blocks nothing. Observe is
how a new allowlist gets built against real behavior without breaking the
skills already running. Read the log, write the grants to match, then flip to
enforce. Observe enforces nothing, including its own errors, because that is
what observe means. Protection lives in enforce mode. Do not lean on observe.

One kill switch. Throwing it creates a marker file beside the decision log and
appends one THROWN row to the hash chain. Every call after that is denied, in
the gate that threw it and in any gate already running on the same log, with no
restart. A human clears it by removing the marker; the gate never clears it.
Observe mode still blocks nothing, the switch included.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import sys
import time
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import IO

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None  # type: ignore[assignment]

try:
    import msvcrt
except ImportError:
    msvcrt = None  # type: ignore[assignment]

_GENESIS = "0" * 64


class _StrictLoader(yaml.SafeLoader):
    """Refuse duplicate keys and YAML merge keys (``<<``)."""


def _construct_mapping_strict(loader: yaml.SafeLoader, node: MappingNode, deep=False):
    if not isinstance(node, MappingNode):
        raise ConstructorError(
            None,
            None,
            f"expected a mapping node, got {node.id}",
            node.start_mark,
        )
    mapping: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key == "<<":
            raise ConstructorError(
                None,
                None,
                "YAML merge keys are refused",
                key_node.start_mark,
            )
        if key in mapping:
            raise ConstructorError(
                None,
                None,
                f"duplicate YAML key: {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


def _refuse_merge(loader: yaml.SafeLoader, node) -> None:
    raise ConstructorError(
        None,
        None,
        "YAML merge keys are refused",
        node.start_mark,
    )


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping_strict,
)
_StrictLoader.add_constructor("tag:yaml.org,2002:merge", _refuse_merge)


def load_yaml_mapping(text: str) -> dict:
    """Parse YAML that must be a mapping, without duplicate or merge keys."""
    data = yaml.load(text, Loader=_StrictLoader)  # noqa: S506 (SafeLoader subclass)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"YAML root must be a mapping, got {type(data).__name__}")
    return data


@contextmanager
def _audit_lock(log_path: str):
    """Exclusive lock around read-head and append so two writers cannot fork."""
    lock_path = f"{log_path}.lock"
    directory = os.path.dirname(lock_path) or "."
    os.makedirs(directory, exist_ok=True)
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if os.fstat(fd).st_size == 0:
            os.write(fd, b"0")
            os.lseek(fd, 0, os.SEEK_SET)
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        elif msvcrt is not None:
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        yield
    finally:
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
            elif msvcrt is not None:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        finally:
            os.close(fd)


_TRACE_FIELDS = ("session_id", "turn_id", "task_id", "tool_call_id")
_LOG_ALLOWED = frozenset(
    {
        "ts",
        "mode",
        "verdict",
        "reason",
        "skill",
        "tool",
        "paths",
        "enforced",
        "session_id",
        "turn_id",
        "task_id",
        "tool_call_id",
        "arg_summary",
        "trace_id",
        "span_id",
        "parent",
        "start",
        "end",
        "input",
        "output",
        "score",
        "run_id",
        "route_ticket",
        # B9 grant wiring: present only on rows from a gate built with grants.
        "principal_id",
        "grant_id",
        "parent_grant_id",
        "gate",
        "manifest_hash",
        "approval_id",
    }
)


def checked_log_record(record: Mapping) -> dict:
    """Unknown JSONL keys fail closed. Sitting run_id is optional."""
    out = dict(record)
    extra = sorted(k for k in out if k not in _LOG_ALLOWED)
    if extra:
        raise ValueError("unknown jsonl keys: " + ", ".join(extra))
    return out


def _hash_log_line(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def _witness_path(log_path: str) -> str:
    return f"{log_path}.witness"


def _read_witness(witness_path: str) -> dict:
    with open(witness_path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("audit log witness malformed")
    head = data.get("head")
    count = data.get("count")
    if not isinstance(head, str) or not isinstance(count, int) or count < 0:
        raise ValueError("audit log witness malformed")
    return {"head": head, "count": count}


def _write_witness(witness_path: str, head: str, count: int) -> None:
    payload = json.dumps({"head": head, "count": count}, sort_keys=True) + "\n"
    directory = os.path.dirname(witness_path) or "."
    os.makedirs(directory, exist_ok=True)
    fd = os.open(witness_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, payload.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


def _anchor_path(log_path: str) -> str:
    """Default anchor location: beside the log. An operator can set another."""
    return f"{log_path}.anchor"


_REANCHOR = "an operator must re-anchor (python capability_gate.py reanchor)"


def _owned_regular_file(path: str, what: str) -> None:
    """Refuse a symlink, a non-file, or (where uids exist) a file another user owns."""
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"{what} is a symlink, failing closed")
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"{what} is not a regular file, failing closed")
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise ValueError(f"{what} is owned by another user, failing closed")


def _read_anchor(anchor_path: str) -> dict | None:
    if not os.path.lexists(anchor_path):
        return None
    try:
        _owned_regular_file(anchor_path, "audit log anchor")
        return _read_witness(anchor_path)
    except (OSError, ValueError) as exc:
        raise ValueError(
            f"audit log anchor unreadable, failing closed: {exc!r}"
        ) from exc


def _verify_log(
    log_path: str,
    anchor_path: str | None = None,
    checkpoint: CheckpointConfig | None = None,
) -> tuple[str, int]:
    """Return (head hash, record count). Check parent links, witness, and anchor.

    The anchor holds the same head and count as the witness, written on every
    append. Once it exists, a missing log, a missing witness, or a chain that
    does not reach the anchored head and count is tamper, not a first run.
    With a checkpoint configured, the log must also match the newest signed
    checkpoint in its folder (see the signed checkpoints section below).
    """
    witness_path = _witness_path(log_path)
    witness = _read_witness(witness_path) if os.path.exists(witness_path) else None
    anchor = _read_anchor(anchor_path or _anchor_path(log_path))

    prev = _GENESIS
    count = 0
    lines: list[bytes] = []
    if not os.path.exists(log_path):
        if witness is not None and (
            witness["count"] != 0 or witness["head"] != _GENESIS
        ):
            raise ValueError("audit log missing but witness present")
        if anchor is not None and (anchor["count"] != 0 or anchor["head"] != _GENESIS):
            raise ValueError(
                f"audit log missing but its anchor records {anchor['count']} "
                f"row(s); {_REANCHOR}"
            )
        # BEGIN C4-CHECKPOINT (an empty log must still match the signed size)
        if checkpoint is not None:
            _cp_check(checkpoint, lines)
        # END C4-CHECKPOINT
        return _GENESIS, 0

    with open(log_path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line:
                continue
            rec = json.loads(line)
            if rec.get("parent") != prev:
                raise ValueError("audit log hash chain broken")
            prev = _hash_log_line(line)
            count += 1
            lines.append(line.encode("utf-8"))

    if witness is None and anchor is not None and count > 0:
        raise ValueError(f"audit log witness missing; {_REANCHOR}")
    if witness is not None and (witness["count"] != count or witness["head"] != prev):
        raise ValueError("audit log witness mismatch")
    if anchor is not None and (anchor["count"] != count or anchor["head"] != prev):
        raise ValueError(
            "audit log does not match its anchor (shortened, rewritten, or "
            f"replaced); {_REANCHOR}"
        )
    # BEGIN C4-CHECKPOINT (the witness and anchor are a cache; this is the root)
    if checkpoint is not None:
        _cp_check(checkpoint, lines)
    # END C4-CHECKPOINT
    return prev, count


def verify_hash_chain(
    log_path: str,
    anchor_path: str | None = None,
    checkpoint: CheckpointConfig | None = None,
) -> str:
    """Return the hash of the last JSONL line, or genesis if none exist.

    Each record's parent is the hash of the previous line. A sibling witness
    file and an anchor (beside the log unless an operator sets another
    location) store the head hash and record count, so truncation, deletion,
    and a recomputed witness fail closed the same way a rewrite does. Fail
    closed instead of appending onto a broken chain.
    """
    head, _count = _verify_log(log_path, anchor_path, checkpoint)
    return head


def reanchor_audit_log(log_path: str, anchor_path: str | None = None) -> list[str]:
    """Operator action: retire the current log, witness, and anchor.

    Nothing is deleted. Each file present is renamed with a ``.retired-<time>``
    suffix, so the damaged record stays available to inspect, and the next
    decision starts a new chain and a new anchor. The gate never does this on
    its own. Returns the retired paths.
    """
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    retired = []
    for path in (
        log_path,
        _witness_path(log_path),
        anchor_path or _anchor_path(log_path),
    ):
        if os.path.lexists(path):
            target = f"{path}.retired-{stamp}"
            os.replace(path, target)
            retired.append(target)
    return retired


# ---- Signed checkpoints (C4 boundary, option a3) ----
#
# The log, witness and anchor above all live where the agent's OS user can
# write, so an agent that can write the log folder can rewrite all three
# together (C4 attacks A1, A2 and A3b). Here the root of trust leaves the box.
# A CI job that alone holds the signing key signs a C2SP checkpoint of the log
# (origin, tree size, RFC 9162 Merkle root), and only after a consistency proof
# shows the new log extends the last signed one (attack A4). The gate checks
# its log against the newest signed checkpoint in a local folder on every
# decision; the witness and anchor stay as a cache.
#
# What this does not stop: rows written after the newest signed checkpoint are
# only as safe as the cache until the next one is signed, and an agent that
# deletes the newest note falls back to an older one until the folder is synced
# again from the signed branch. Both show up as a refused signing request or a
# mismatch at the next sync.

_CP_SIG_PREFIX = "\u2014 "  # C2SP signed-note signature lines start with an em dash
_CP_NOTE = re.compile(r"^(\d{1,20})\.note$")


class CheckpointError(ValueError):
    """A checkpoint, a signed note or a consistency proof did not check out."""


@dataclass(frozen=True)
class CheckpointConfig:
    """Where the gate finds signed checkpoints for one log, and whose key signs them.

    folder: local copy of the signed notes, one file per checkpoint, named
        ``<tree size>.note``.
    vkey: the C2SP verifier key, ``<name>+<key id hex>+<base64(0x01 || key)>``.
    origin: the log's origin line; one origin per log.
    """

    folder: str
    vkey: str
    origin: str


def _cp_leaf(line: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + line).digest()


def _cp_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _cp_split(n: int) -> int:
    """The largest power of two smaller than n (RFC 9162 section 2.1.1)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _cp_root(leaves: Sequence[bytes]) -> bytes:
    """RFC 9162 Merkle tree hash over leaf hashes."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    k = _cp_split(len(leaves))
    return _cp_node(_cp_root(leaves[:k]), _cp_root(leaves[k:]))


def _cp_subproof(m: int, leaves: Sequence[bytes], whole: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if whole else [_cp_root(leaves)]
    k = _cp_split(n)
    if m <= k:
        return _cp_subproof(m, leaves[:k], whole) + [_cp_root(leaves[k:])]
    return _cp_subproof(m - k, leaves[k:], False) + [_cp_root(leaves[:k])]


def _cp_consistency_proof(m: int, leaves: Sequence[bytes]) -> list[bytes]:
    """RFC 9162 section 2.1.4.1: proof that the first m leaves are a prefix."""
    if m < 0 or m > len(leaves):
        raise CheckpointError(f"no consistency proof from size {m} to {len(leaves)}")
    if m in (0, len(leaves)):
        return []
    return _cp_subproof(m, leaves, True)


def _cp_verify_consistency(
    m: int, n: int, old_root: bytes, new_root: bytes, proof: Sequence[bytes]
) -> bool:
    """RFC 9162 section 2.1.4.2."""
    if m < 0 or m > n:
        return False
    if m == n:
        return not proof and old_root == new_root
    if m == 0:
        return not proof
    if not proof:
        return False
    path = list(proof)
    if m & (m - 1) == 0:
        path.insert(0, old_root)
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = _cp_node(c, fr)
            sr = _cp_node(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _cp_node(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root


def _cp_b64(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")


def _cp_unb64(text: str, what: str) -> bytes:
    import base64
    import binascii

    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise CheckpointError(f"{what} is not base64") from exc


def _cp_key_id(name: str, key: bytes) -> bytes:
    return hashlib.sha256(name.encode("utf-8") + b"\n" + key).digest()[:4]


def _cp_parse_vkey(vkey: str) -> tuple[str, bytes, bytes]:
    """(name, key id, raw Ed25519 public key) from a C2SP verifier key."""
    parts = vkey.strip().split("+", 2)  # base64 key data may hold "+"
    if len(parts) != 3 or not parts[0]:
        raise CheckpointError("verifier key is not name+id+key")
    name, kid_hex, key_b64 = parts
    key = _cp_unb64(key_b64, "verifier key")
    if len(key) != 33 or key[0] != 1:
        raise CheckpointError("verifier key is not an Ed25519 key")
    kid = _cp_key_id(name, key)
    if kid.hex() != kid_hex.lower():
        raise CheckpointError("verifier key id does not match its key")
    return name, kid, key[1:]


def checkpoint_vkey(name: str, public_key: bytes) -> str:
    """The C2SP verifier key string for a raw 32-byte Ed25519 public key."""
    key = b"\x01" + public_key
    return f"{name}+{_cp_key_id(name, key).hex()}+{_cp_b64(key)}"


def _cp_body(origin: str, size: int, root: bytes) -> str:
    if not origin or "\n" in origin:
        raise CheckpointError("origin must be one non-empty line")
    return f"{origin}\n{size}\n{_cp_b64(root)}\n"


def read_checkpoint(text: str, vkey: str) -> tuple[str, int, bytes]:
    """(origin, size, root) from a signed note, or CheckpointError.

    The body must be exactly three lines (origin, size, root) and carry a
    valid Ed25519 signature from vkey. Unknown signers are ignored, as the
    signed-note format allows, but one signature must be vkey's.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    name, kid, pub = _cp_parse_vkey(vkey)
    body, sep, sigs = text.partition("\n\n")
    if not sep or not sigs.endswith("\n"):
        raise CheckpointError("signed note is malformed")
    body += "\n"
    fields = body.split("\n")[:-1]
    if len(fields) != 3:
        raise CheckpointError("checkpoint body is not origin, size and root")
    origin, size_text, root_b64 = fields
    if not re.fullmatch(r"0|[1-9]\d{0,19}", size_text):
        raise CheckpointError("checkpoint size is not a number")
    root = _cp_unb64(root_b64, "checkpoint root")
    if len(root) != 32:
        raise CheckpointError("checkpoint root is not 32 bytes")
    verified = False
    for line in sigs[:-1].split("\n"):
        if not line.startswith(_CP_SIG_PREFIX):
            raise CheckpointError("signed note has a line that is not a signature")
        signer, _, sig_b64 = line[len(_CP_SIG_PREFIX) :].partition(" ")
        if signer != name:
            continue
        sig = _cp_unb64(sig_b64, "note signature")
        if len(sig) != 68 or sig[:4] != kid:
            continue
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(
                sig[4:], body.encode("utf-8")
            )
        except InvalidSignature:
            raise CheckpointError("checkpoint signature does not verify") from None
        verified = True
    if not verified:
        raise CheckpointError("checkpoint carries no signature from the pinned key")
    return origin, int(size_text), root


def sign_checkpoint(origin: str, size: int, root: bytes, name: str, private_key) -> str:
    """A signed note over (origin, size, root). private_key is an Ed25519PrivateKey."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    body = _cp_body(origin, size, root)
    pub = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    kid = _cp_key_id(name, b"\x01" + pub)
    sig = private_key.sign(body.encode("utf-8"))
    return f"{body}\n{_CP_SIG_PREFIX}{name} {_cp_b64(kid + sig)}\n"


def _cp_latest(folder: str) -> tuple[str, int] | None:
    """(path, size) of the newest note in folder; None if it holds none."""
    _owned_folder(folder)
    best = None
    for entry in os.listdir(folder):
        m = _CP_NOTE.match(entry)
        if m and (best is None or int(m.group(1)) > best[1]):
            best = (os.path.join(folder, entry), int(m.group(1)))
    return best


def _owned_folder(folder: str) -> None:
    st = os.lstat(folder)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise CheckpointError("checkpoint folder is a symlink or not a folder")
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise CheckpointError("checkpoint folder is owned by another user")


def _cp_read_latest(cfg: CheckpointConfig) -> tuple[int, bytes] | None:
    latest = _cp_latest(cfg.folder)
    if latest is None:
        return None
    path, size = latest
    try:
        _owned_regular_file(path, "signed checkpoint")
    except ValueError as exc:
        raise CheckpointError(str(exc)) from None
    try:
        with open(path, encoding="utf-8", newline="") as fh:
            text = fh.read()
    except UnicodeDecodeError:
        raise CheckpointError("signed checkpoint is not UTF-8") from None
    origin, note_size, root = read_checkpoint(text, cfg.vkey)
    if origin != cfg.origin:
        raise CheckpointError("signed checkpoint is for another log")
    if note_size != size:
        raise CheckpointError("signed checkpoint size does not match its file name")
    return size, root


def _cp_check(cfg: CheckpointConfig, lines: Sequence[bytes]) -> None:
    """The log must start with exactly the rows the newest signed checkpoint covers."""
    try:
        latest = _cp_read_latest(cfg)
    except OSError as exc:
        raise CheckpointError(
            f"signed checkpoint unreadable, failing closed: {exc!r}"
        ) from exc
    if latest is None:
        raise CheckpointError("no signed checkpoint for this log, failing closed")
    size, root = latest
    if size > len(lines):
        raise CheckpointError(
            f"audit log has {len(lines)} row(s) but its signed checkpoint covers {size}"
        )
    if _cp_root([_cp_leaf(x) for x in lines[:size]]) != root:
        raise CheckpointError("audit log does not match its signed checkpoint")


def _cp_log_lines(log_path: str) -> list[bytes]:
    if not os.path.exists(log_path):
        return []
    with open(log_path, encoding="utf-8") as fh:
        return [ln.rstrip("\n").encode("utf-8") for ln in fh if ln.rstrip("\n")]


def checkpoint_request(
    log_path: str, cfg: CheckpointConfig, *, first: bool = False
) -> dict:
    """What the signer needs to extend the newest signed checkpoint: hashes only.

    The log must still match the newest signed checkpoint. ``first`` asks for
    the first checkpoint of a log that has none yet.
    """
    lines = _cp_log_lines(log_path)
    latest = _cp_read_latest(cfg)
    if latest is None:
        if not first:
            raise CheckpointError("no signed checkpoint yet; ask for the first one")
        old_size = 0
    else:
        _cp_check(cfg, lines)
        old_size = latest[0]
    leaves = [_cp_leaf(x) for x in lines]
    return {
        "origin": cfg.origin,
        "old_size": old_size,
        "size": len(leaves),
        "root": _cp_b64(_cp_root(leaves)),
        "proof": [_cp_b64(h) for h in _cp_consistency_proof(old_size, leaves)],
    }


def sign_extending(
    prev_note: str | None, request: Mapping, vkey: str, private_key
) -> str:
    """The signer's rule (attack A4): sign only a log that extends the last signed one.

    prev_note is the newest note on the signed branch for this origin, or None
    when there is none yet. The request must name that note's size as its old
    size and carry a consistency proof from that note's root to the new root.
    """
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    name, _kid, pub = _cp_parse_vkey(vkey)
    own = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    if own != pub:
        raise CheckpointError("signing key does not match the pinned verifier key")
    try:
        origin = request["origin"]
        old_size = request["old_size"]
        size = request["size"]
        root = _cp_unb64(request["root"], "requested root")
        proof = [_cp_unb64(h, "proof hash") for h in request["proof"]]
    except (KeyError, TypeError) as exc:
        raise CheckpointError("checkpoint request is malformed") from exc
    if not all(
        isinstance(x, int) and not isinstance(x, bool) for x in (old_size, size)
    ):
        raise CheckpointError("checkpoint request sizes are not integers")
    if len(root) != 32 or any(len(h) != 32 for h in proof):
        raise CheckpointError("checkpoint request hashes are not 32 bytes")
    if prev_note is None:
        if old_size != 0:
            raise CheckpointError(
                "no signed checkpoint yet, but the request extends one"
            )
        prev_root = hashlib.sha256(b"").digest()
    else:
        prev_origin, prev_size, prev_root = read_checkpoint(prev_note, vkey)
        if prev_origin != origin:
            raise CheckpointError("request is for another log than the signed one")
        if old_size != prev_size:
            raise CheckpointError(
                "request does not extend the newest signed checkpoint"
            )
    # BEGIN C4-EXTENDS (refuse a log that does not extend the signed prefix)
    if not _cp_verify_consistency(old_size, size, prev_root, root, proof):
        raise CheckpointError(
            "the log does not extend the last signed checkpoint; refusing to sign"
        )
    # END C4-EXTENDS
    return sign_checkpoint(origin, size, root, name, private_key)


_PATH_LIKE_KEYS = frozenset(
    {
        "path",
        "target",
        "workdir",
        "output_path",
        "workspace_path",
        "file_path",
        "directory",
        "cwd",
    }
)
_CONTENT_KEYS = frozenset(
    {
        "content",
        "file_content",
        "patch",
        "code",
        "command",
        "text",
        "body",
        "message",
        "data",
        "stdout",
        "stderr",
        "output",
    }
)


def summarize_args(args: Mapping | None) -> dict:
    """Safe argument summary: keys, path-like values, content byte lengths only."""
    if not isinstance(args, Mapping):
        return {"keys": []}
    keys = sorted(str(k) for k in args.keys())
    paths: dict[str, str] = {}
    content_lengths: dict[str, int] = {}
    for key, val in args.items():
        ks = str(key)
        if ks in _PATH_LIKE_KEYS or ks.endswith("_path"):
            if isinstance(val, str) and val:
                paths[ks] = val
        if ks in _CONTENT_KEYS or ks.endswith("_content"):
            if isinstance(val, str):
                content_lengths[ks] = len(val.encode("utf-8", errors="surrogatepass"))
            elif val is not None and not isinstance(val, (bool, int, float)):
                content_lengths[ks] = len(
                    str(val).encode("utf-8", errors="surrogatepass")
                )
    out: dict = {"keys": keys}
    if paths:
        out["paths"] = paths
    if content_lengths:
        out["content_lengths"] = content_lengths
    return out


def _normalize_trace(trace: Mapping[str, str] | None) -> dict[str, str]:
    if not isinstance(trace, Mapping):
        return {}
    out: dict[str, str] = {}
    for field in _TRACE_FIELDS:
        val = trace.get(field)
        if val is not None and str(val):
            out[field] = str(val)
    return out


class Verdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"  # reserved for Stage 3; the Stage 1 adapter maps ASK -> block
    THROWN = "thrown"  # kill switch arming row; not a tool-call decision
    ISOLATE = "isolate"  # the call runs in the isolation box, never on the host


ENFORCE = "enforce"
OBSERVE = "observe"
HALT_SUFFIX = ".halt"


def halt_marker_path(log_path: str) -> str:
    """The kill switch marker for a decision log: the log path plus ``.halt``."""
    return log_path + HALT_SUFFIX


def _same_file_name(a: str, b: str) -> bool:
    return os.path.normcase(os.path.realpath(a)) == os.path.normcase(
        os.path.realpath(b)
    )


def _canon_path(p: str) -> str:
    return os.path.normcase(os.path.realpath(p))


def _is_same_or_ancestor(path: str, folder: str) -> bool:
    """True when path is folder or a folder that contains it."""
    a, f = _canon_path(path), _canon_path(folder)
    return a == f or f.startswith(a.rstrip(os.sep) + os.sep)


FOLDER_TOKEN_NAME = ".capability-gate-folder"


def _folder_token(folder: str, create: bool = False) -> str | None:
    """The random token that names this log folder, or None when it is gone.

    Created once, by the first gate to use the folder, and only read after
    that. A folder that was removed and made again has no token or a new one,
    which an inode number cannot show: filesystems reuse inode numbers.
    """
    path = os.path.join(folder, FOLDER_TOKEN_NAME)
    if create:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            try:
                os.write(fd, secrets.token_hex(16).encode())
                os.fsync(fd)
            finally:
                os.close(fd)
    try:
        with open(path, encoding="ascii") as f:
            return f.read().strip() or None
    except (OSError, UnicodeError):
        return None


def _can_create_in(folder: str) -> bool:
    """Whether a marker could be made at folder, creating missing parents first.

    The nearest existing ancestor decides: it must be a folder this process can
    write, as os.makedirs would need.
    """
    folder = os.path.abspath(folder)
    while not os.path.lexists(folder):
        parent = os.path.dirname(folder)
        if parent == folder:
            return False
        folder = parent
    return os.path.isdir(folder) and os.access(folder, os.W_OK | os.X_OK)


class KillSwitchUnthrowable(RuntimeError):
    """No halt location could take the marker; the switch is not thrown."""


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: str
    skill: str
    tool: str
    paths: tuple[str, ...] = ()
    enforced: bool = True  # in observe mode this is False; a non-allow verdict is logged but not acted on
    # Set on an enforced ISOLATE verdict: the single-use ticket the route to
    # the box must answer, and on the denial row that records the outcome.
    route_ticket: str | None = None
    # B9 grant wiring. Unset on every legacy row, so legacy rows are unchanged.
    # gate is "admission" (is this tool available to this principal at all)
    # or "execution" (this action, these paths, this policy, now).
    principal_id: str | None = None
    grant_id: str | None = None
    parent_grant_id: str | None = None
    gate: str | None = None
    manifest_hash: str | None = None
    approval_id: str | None = None

    def as_dict(self) -> dict:
        out = {
            "verdict": self.verdict.value,
            "reason": self.reason,
            "skill": self.skill,
            "tool": self.tool,
            "paths": list(self.paths),
            "enforced": self.enforced,
        }
        if self.route_ticket is not None:
            out["route_ticket"] = self.route_ticket
        for key in _GRANT_ROW_KEYS:
            value = getattr(self, key)
            if value is not None:
                out[key] = value
        return out


_GRANT_ROW_KEYS = (
    "principal_id",
    "grant_id",
    "parent_grant_id",
    "gate",
    "manifest_hash",
    "approval_id",
)


@dataclass(frozen=True)
class SkillRule:
    tools: frozenset[str]
    path_globs: tuple[str, ...]


@dataclass(frozen=True)
class Policy:
    skills: Mapping[str, SkillRule]
    require_approval: frozenset[str] = field(default_factory=frozenset)
    isolate: frozenset[str] = field(default_factory=frozenset)


class PolicyError(ValueError):
    """Raised only at load time. A malformed policy fails loudly here, never
    silently at decision time where the failure would be a security gap."""


# --- policy loading -------------------------------------------------------


POLICY_KEYS = frozenset({"version", "skills", "require_approval", "isolate"})


def load_policy(mapping: Mapping) -> Policy:
    if not isinstance(mapping, Mapping):
        raise PolicyError("policy root must be a mapping")
    # A misspelled key would load as an empty list; for 'isolate' that turns
    # isolation off without a word, so every unknown key is refused.
    unknown = sorted(str(k) for k in mapping if k not in POLICY_KEYS)
    if unknown:
        raise PolicyError("unknown top-level allowlist keys: " + ", ".join(unknown))
    skills_in = mapping.get("skills", {})
    if not isinstance(skills_in, Mapping):
        raise PolicyError("'skills' must be a mapping")
    skills: dict[str, SkillRule] = {}
    for name, rule in skills_in.items():
        if not isinstance(rule, Mapping):
            raise PolicyError(f"skill '{name}' must be a mapping")
        tools = rule.get("tools", [])
        paths = rule.get("paths", [])
        if not isinstance(tools, Sequence) or isinstance(tools, str):
            raise PolicyError(f"skill '{name}': 'tools' must be a list")
        if not isinstance(paths, Sequence) or isinstance(paths, str):
            raise PolicyError(f"skill '{name}': 'paths' must be a list")
        expanded: list[str] = []
        for p in paths:
            ep = _expand(str(p))
            if "$" in ep:
                raise PolicyError(
                    f"skill '{name}': path '{p}' has an unresolved variable after expansion "
                    f"('{ep}'). Set the variable (e.g. HERMES_HOME) before loading, or use an "
                    f"absolute path. Refusing to load a grant that would silently match nothing."
                )
            expanded.append(ep)
        skills[str(name)] = SkillRule(
            tools=frozenset(str(t) for t in tools),
            path_globs=tuple(expanded),
        )
    approval = mapping.get("require_approval", [])
    if not isinstance(approval, Sequence) or isinstance(approval, str):
        raise PolicyError("'require_approval' must be a list")
    isolate = mapping.get("isolate", [])
    if not isinstance(isolate, Sequence) or isinstance(isolate, str):
        raise PolicyError("'isolate' must be a list")
    isolate_set = frozenset(str(t) for t in isolate)
    approval_set = frozenset(str(t) for t in approval)
    both = sorted(isolate_set & approval_set)
    if both:
        raise PolicyError(
            "tools listed in both 'isolate' and 'require_approval': " + ", ".join(both)
        )
    return Policy(skills=skills, require_approval=approval_set, isolate=isolate_set)


# --- path expansion and glob matching -------------------------------------
# Supports ~ and $VARS in policy paths, so an allowlist written against
# $HERMES_HOME is portable across machines and Hermes homes. An unset variable
# is left literal, which then matches no real path, so a missing env var fails
# closed (denies) rather than silently widening a grant.
#
# Glob syntax: ** (any depth, including separators), * (within one segment), ? .
# Small and readable on purpose, so the matching rule is auditable rather than
# hidden inside a glob dependency.


def _expand(path: str) -> str:
    return os.path.expandvars(os.path.expanduser(path))


def _glob_to_regex(glob: str) -> re.Pattern:
    i, n = 0, len(glob)
    out = ["^"]
    while i < n:
        c = glob[i]
        if c == "*":
            if i + 1 < n and glob[i + 1] == "*":
                out.append(".*")  # ** crosses separators
                i += 2
                if i < n and glob[i] in "/\\":
                    i += 1  # collapse the separator after **
                continue
            # * and ? stay within one segment. Both separators count, because a
            # Windows path is spelled with backslashes.
            out.append(r"[^/\\]*")
        elif c == "?":
            out.append(r"[^/\\]")
        else:
            out.append(re.escape(c))
        i += 1
    # \Z, not $: $ also matches before a final newline, and a POSIX name can
    # end in one. DOTALL lets ** cross a newline inside a name too.
    out.append(r"\Z")
    return re.compile("".join(out), re.DOTALL)


def _real_glob(glob: str) -> str:
    # Resolve the literal prefix of a grant, so a grant rooted at a symlink
    # still matches its own files once request paths are resolved.
    # Split on both separators: a Windows grant is spelled with backslashes.
    parts = re.split(r"[\\/]", glob)
    i = next((k for k, seg in enumerate(parts) if "*" in seg or "?" in seg), len(parts))
    prefix = os.path.realpath(os.sep.join(parts[:i]) or os.sep)
    rest = parts[i:]
    return os.path.join(prefix, *rest) if rest else prefix


def _shared_hardlink(path: str) -> bool:
    """True when ``path`` names a regular file with more than one hard link.

    Realpath of an in-grant hardlink is the in-grant name, so the grant match
    cannot see that the same inode is also reachable off-grant. Refusing any
    regular file with ``st_nlink > 1`` closes that hole. Directories often have
    ``nlink > 1`` for ``.`` / ``..`` and are not treated here. An ``os.stat``
    ``OSError`` returns False (treat as not shared), which is fine for write
    targets that do not exist yet.
    """
    try:
        st = os.stat(path, follow_symlinks=True)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and st.st_nlink > 1


# A folder bigger than this is denied rather than vetted entry by entry.
_TREE_VET_LIMIT = 50_000


def _tree_escape(folder: str, globs: Sequence[str]) -> str | None:
    """Why a folder a tool will walk reaches outside the grant, or None.

    A search reads every file under the folder, so each entry must pass the
    same checks a direct read does: its resolved path matches the grant (a
    symlink, or a Windows junction the walk descends into, cannot point out),
    and no regular file shares its inode through a hard link. Links are not
    followed into folders; their own resolved path is checked. A walk error is
    a deny, since the unvetted part could hold anything.
    """
    errors: list[OSError] = []
    seen = 0
    for dirpath, dirnames, filenames in os.walk(
        folder, onerror=errors.append, followlinks=False
    ):
        for name in (*dirnames, *filenames):
            seen += 1
            if seen > _TREE_VET_LIMIT:
                return (
                    f"folder '{folder}' has more than {_TREE_VET_LIMIT} entries; "
                    "too large to vet"
                )
            entry = os.path.join(dirpath, name)
            if not _path_allowed(entry, globs):
                return f"'{entry}' under '{folder}' resolves outside the grant"
            if _shared_hardlink(entry):
                return f"'{entry}' under '{folder}' has multiple hard links"
    if errors:
        return f"could not walk folder '{folder}', failing closed: {errors[0]!r}"
    return None


def _path_allowed(path: str, globs: Iterable[str]) -> bool:
    # Request paths are not expanded. The tool may expand "~" or "$VAR"
    # differently, or not at all, so the gate refuses to guess.
    if "$" in path or path.startswith("~"):
        return False
    # Match the file the name resolves to, not the string. An in-grant symlink
    # to an off-grant file is denied. A swap between this check and the
    # tool's open is not closed here; that needs open-by-fd in the host.
    real = os.path.realpath(path)
    return any(
        _glob_to_regex(os.path.normpath(_real_glob(g))).match(real) for g in globs
    )


# A grant glob allows every name under it. The Phase 1 canary planted
# secret-canary.txt inside a granted workspace and the floor allowed both
# the write and the read. That basename is denied even when the parent matches.
_CANARY_BASENAMES = frozenset({"secret-canary.txt"})


def _windows_name(name: str) -> str:
    """The name as Windows opens it: any case, trailing dots and spaces dropped.

    Used on every OS, so a policy denies the same names wherever it runs.
    """
    return name.rstrip(". ").casefold()


def _canary_secret(path: str) -> bool:
    """True when the name as given, or the file it resolves to, is the canary.

    The resolved name catches an in-grant symlink to the canary and, on
    Windows, its 8.3 short name.
    """
    expanded = os.path.normpath(_expand(path))
    names = [os.path.basename(expanded)]
    try:
        names.append(os.path.basename(os.path.realpath(expanded)))
    except OSError:
        pass
    return any(_windows_name(n) in _CANARY_BASENAMES for n in names)


def _protected_segment(name: str) -> bool:
    """True for .env / .aegis / .env.* / .envrc (any case, trailing dots and
    spaces dropped, since Windows creates ``.env`` for a write to ``.env ``)."""
    if not name:
        return False
    lower = _windows_name(name)
    if lower in {".env", ".aegis", ".envrc"}:
        return True
    # .env.local, .env.production, …
    return lower.startswith(".env.")


def _path_has_protected_segment(path: str) -> bool:
    parts = os.path.normpath(path).replace("\\", "/").split("/")
    return any(_protected_segment(part) for part in parts if part)


def _protected_path(path: str) -> bool:
    """True when the request path or its realpath names a protected segment.

    Symlink bypass: notes/envl → .env must deny. For a new file under a
    symlinked directory (notes/dl/new with dl → .aegis), also check the
    realpath of the parent.
    """
    expanded = os.path.normpath(_expand(path))
    candidates = [expanded]
    try:
        candidates.append(os.path.realpath(expanded))
    except OSError:
        pass
    parent = os.path.dirname(expanded)
    if parent and parent not in (expanded, ""):
        try:
            real_parent = os.path.realpath(parent)
            candidates.append(real_parent)
            candidates.append(os.path.join(real_parent, os.path.basename(expanded)))
        except OSError:
            pass
    return any(_path_has_protected_segment(c) for c in candidates)


# --- the decision ---------------------------------------------------------


def _absolute(path: str, base_dir: str | None) -> str | None:
    """The absolute path a relative request names, or None with no usable base.

    A path that needs ``~`` or ``$VAR`` expansion is returned as given, so
    ``_path_allowed`` refuses it the same way it always has.
    """
    if os.path.isabs(path) or "$" in path or path.startswith("~"):
        return path
    if not base_dir or not os.path.isabs(base_dir):
        return None
    # Never normpath first: collapsing "link/.." as text names a different file
    # than a POSIX open, which follows the link before "..". realpath on the
    # folder part follows links in order; the last part stays as named so the
    # checks after this still see a symlinked file as a symlink.
    parent, name = os.path.split(os.path.join(base_dir, path))
    return os.path.join(os.path.realpath(parent), name)


def _decide(
    policy: Policy,
    skill: str,
    tool: str,
    paths: Sequence[str],
    base_dir: str | None = None,
) -> Decision:
    resolved = []
    for p in paths:
        a = _absolute(p, base_dir)
        if a is None:
            return Decision(
                Verdict.DENY,
                f"relative path '{p}' has no base folder to resolve against",
                skill,
                tool,
                tuple(paths),
            )
        resolved.append(a)
    paths = resolved
    ptuple = tuple(paths)
    rule = policy.skills.get(skill)
    if rule is None:
        return Decision(
            Verdict.DENY, f"skill '{skill}' not in allowlist", skill, tool, ptuple
        )
    if tool not in rule.tools:
        return Decision(
            Verdict.DENY, f"tool '{tool}' not granted to '{skill}'", skill, tool, ptuple
        )
    for p in paths:
        if _canary_secret(p):
            return Decision(
                Verdict.DENY,
                f"path '{p}' is a canary secret inside a grant",
                skill,
                tool,
                ptuple,
            )
        if _protected_path(p):
            return Decision(
                Verdict.DENY,
                f"path '{p}' names a protected .env or .aegis segment",
                skill,
                tool,
                ptuple,
            )
        if _shared_hardlink(p):
            return Decision(
                Verdict.DENY,
                f"path '{p}' has multiple hard links; refuse shared inode",
                skill,
                tool,
                ptuple,
            )
        if not _path_allowed(p, rule.path_globs):
            return Decision(
                Verdict.DENY,
                f"path '{p}' outside allowlist for '{skill}'",
                skill,
                tool,
                ptuple,
            )
        if os.path.isdir(p):
            escape = _tree_escape(p, rule.path_globs)
            if escape is not None:
                return Decision(Verdict.DENY, escape, skill, tool, ptuple)
    if tool in policy.isolate:
        return Decision(
            Verdict.ISOLATE,
            f"tool '{tool}' runs in the isolation box",
            skill,
            tool,
            ptuple,
        )
    if tool in policy.require_approval:
        return Decision(
            Verdict.ASK, f"tool '{tool}' requires human approval", skill, tool, ptuple
        )
    return Decision(Verdict.ALLOW, "allowed by policy", skill, tool, ptuple)


class Gate:
    """Wraps the decision with mode, fail-closed handling, and log-before-act."""

    def __init__(
        self,
        policy: Policy,
        log_path: str,
        mode: str = ENFORCE,
        *,
        halt_path: str | None = None,
        fallback_halt_path: str | None = None,
        anchor_path: str | None = None,
        checkpoint: CheckpointConfig | None = None,
        grants=None,
    ):
        if mode not in (ENFORCE, OBSERVE):
            raise ValueError(f"mode must be '{ENFORCE}' or '{OBSERVE}', got {mode!r}")
        self._policy = policy
        # With a checkpoint the log must match a note only the CI signer can
        # make; the folder of notes is guarded like the log's own files.
        self._checkpoint = checkpoint
        # Absolute paths so a relative HERMES_HOME does not move the marker
        # when the process cwd changes (independent review R2-3).
        self._log_path = os.path.abspath(log_path)
        beside_log = halt_marker_path(self._log_path)
        self._halt_path = os.path.abspath(halt_path or beside_log)
        # An operator-set marker location falls back to the one beside the log,
        # so one unwritable folder cannot make the switch unthrowable.
        fallback = fallback_halt_path or (beside_log if halt_path else None)
        self._halt_paths = tuple(
            dict.fromkeys(os.path.abspath(p) for p in (self._halt_path, fallback) if p)
        )
        # The log folder exists from here on, and this gate remembers which
        # folder it is. Its removal or replacement later is tamper, not a first
        # run: the gate denies and does not re-create it.
        log_dir = os.path.dirname(self._log_path) or "."
        os.makedirs(log_dir, exist_ok=True)
        self._log_dir_token = _folder_token(log_dir, create=True)
        self._log_folder_lost = False
        # An anchor outside the agent's tree survives deletion of the log
        # folder; the default beside the log survives deletion of the log.
        self._anchor_path = os.path.abspath(anchor_path or _anchor_path(self._log_path))
        self._mode = mode
        # B9: with a GrantConfig every call must carry a principal and a live
        # grant, re-verified on every call. None keeps the legacy path.
        self._grants = grants
        self._ledger = None
        self._policy_hash = None
        if grants is not None:
            from capability_gate_grants import GrantStore, Ledger, policy_hash

            GrantStore(grants.store_path).ensure()
            self._ledger = Ledger(grants.ledger_path)
            self._ledger.ensure()
            self._policy_hash = policy_hash(policy)

    @property
    def mode(self) -> str:
        return self._mode

    def set_mode(self, mode: str) -> None:
        """Update mode without rebuilding policy (E2: config flip mid-process)."""
        if mode not in (ENFORCE, OBSERVE):
            raise ValueError(f"mode must be '{ENFORCE}' or '{OBSERVE}', got {mode!r}")
        self._mode = mode

    @property
    def halt_path(self) -> str:
        return self._halt_path

    @property
    def halt_paths(self) -> tuple[str, ...]:
        """Every marker location, primary first; a marker at any of them is thrown."""
        return self._halt_paths

    def throw(self, reason: str = "") -> bool:
        """Throw the kill switch. True if this call threw it, False if already thrown.

        The marker goes in the first location that takes it. If none does, this
        raises KillSwitchUnthrowable rather than returning as if it worked; the
        gate already denies every call in that state. The marker goes down before
        the THROWN row. If the log write then fails, the switch is still thrown
        and the error is raised.
        """
        if any(os.path.lexists(p) for p in self._halt_paths):
            return False
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        failures = []
        for path in self._halt_paths:
            try:
                os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            except OSError as exc:
                failures.append(f"{path}: {exc!r}")
                continue
            try:
                fd = os.open(path, flags, 0o600)
            except FileExistsError:
                return False
            except OSError as exc:
                failures.append(f"{path}: {exc!r}")
                continue
            break
        else:
            raise KillSwitchUnthrowable(
                "kill switch NOT thrown, no halt location took the marker: "
                + "; ".join(failures)
            )
        try:
            os.write(fd, f"thrown at {time.time()}: {reason}\n".encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        decision = Decision(
            Verdict.THROWN,
            f"kill switch thrown: {reason or 'no reason given'}",
            "",
            "",
            (path,),
            enforced=True,
        )
        # Through _log, so the THROWN row moves the operator's anchor (and the
        # signed checkpoint check) in step with the log, like every other row.
        try:
            self._log(decision)
        finally:
            if self._grants is not None:
                # Revoke-on-throw (W5): every grant issued up to now stays dead
                # after a person clears the marker. The marker is already down,
                # so a failure here raises with the switch still thrown.
                from capability_gate_grants import GrantStore

                GrantStore(self._grants.store_path).revoke_before(self._grants.clock())
        return True

    def _halt_state(self) -> str | None:
        """Deny reason from the switch, or None when calls may proceed.

        Read on every call and never cached. Only FileNotFoundError means a
        marker is absent; any other error reading one is a deny. A switch that
        could not be thrown (no marker location writable) and a missing log
        folder are both denies: the operator would have no way to stop the gate.
        """
        for path in self._halt_paths:
            try:
                os.lstat(path)
            except (FileNotFoundError, NotADirectoryError):
                # Not there, or a parent is a file so it can never be there.
                continue
            except Exception as exc:
                return f"kill switch state unreadable, failing closed: {exc!r}"
            return f"kill switch thrown: {path} exists; a human removes it"
        log_dir = os.path.dirname(self._log_path) or "."
        if self._log_dir_token is None or _folder_token(log_dir) != self._log_dir_token:
            # Writing a row now would re-create the folder and start a fresh
            # chain, so this denial is returned without a log row.
            self._log_folder_lost = True
            return (
                f"decision log folder {log_dir} was removed or replaced, failing closed"
            )
        if not any(_can_create_in(os.path.dirname(p) or ".") for p in self._halt_paths):
            return (
                "kill switch cannot be thrown (no halt location is writable), "
                "failing closed"
            )
        return None

    def _guarded_name(self, p: str, a: str) -> str | None:
        """Why a tool path would reach the switch or the log, or None."""
        log = self._log_path
        if any(_same_file_name(a, h) for h in self._halt_paths):
            return f"path '{p}' is the kill switch marker"
        if _same_file_name(a, self._anchor_path):
            return f"path '{p}' is the audit log anchor"
        token = os.path.join(os.path.dirname(log), FOLDER_TOKEN_NAME)
        own = (
            log,
            log + ".lock",
            log + ".witness",
            log + ".route-tickets",
            log + ".route-tickets.lock",
            log + ".route.lock",
            token,
        )
        if any(_same_file_name(a, f) for f in own):
            return f"path '{p}' is the gate's own decision log file"
        if self._grants is not None:
            # M1-A5: the agent principal cannot reach the grant store, the
            # ledger, the approval nonce file, or the key file through a tool.
            for f in self._grants.protected_files():
                if _same_file_name(a, f) or _is_same_or_ancestor(a, f):
                    return f"path '{p}' is a grant state or key file"
        folders = {os.path.dirname(h) for h in self._halt_paths}
        folders.add(os.path.dirname(log))
        for folder in folders:
            if _is_same_or_ancestor(a, folder):
                return f"path '{p}' holds the kill switch or decision log folder"
        if self._checkpoint is not None:
            cp = self._checkpoint.folder
            inside = _canon_path(a).startswith(_canon_path(cp).rstrip(os.sep) + os.sep)
            if inside or _is_same_or_ancestor(a, cp):
                return f"path '{p}' is or holds the signed checkpoint folder"
        return None

    def _kill_switch(
        self, skill: str, tool: str, paths: Sequence[str], base_dir: str | None
    ) -> Decision | None:
        reason = self._halt_state()
        if reason is None:
            # The agent must not clear or throw the switch through a tool path,
            # nor remove the folder that holds it or the log.
            for p in paths:
                a = _absolute(p, base_dir)
                if a is not None:
                    reason = self._guarded_name(p, a)
                    if reason is not None:
                        break
        if reason is None:
            return None
        return Decision(Verdict.DENY, reason, skill, tool, tuple(paths))

    def evaluate(
        self,
        skill: str,
        tool: str,
        paths: Sequence[str] = (),
        *,
        trace: Mapping[str, str] | None = None,
        args: Mapping | None = None,
        refuse: str | None = None,
        base_dir: str | None = None,
        principal_id: str | None = None,
        grant: str | None = None,
        session_key: str | None = None,
        approval: str | None = None,
    ) -> Decision:
        """Decide one call. ``refuse`` is set by an adapter that could not read
        the call's files from its arguments; the call is then denied and logged
        like any other denial. ``base_dir`` is the absolute folder the tool will
        resolve a relative path against; without one a relative path is denied.
        The decision, and the log, carry the absolute paths that were checked."""
        # Everything that can throw before a recorded decision sits inside this
        # boundary (H1-1 / T-FAIL-05). Keep an empty list available for the
        # denial row if path coercion itself fails.
        path_list: list[str] = []
        try:
            # Materialize once (R4-1). A one-shot iterable must not be drained
            # by the kill-switch walk before policy sees the same paths.
            path_list = [str(p) for p in paths]
            norm_trace = _normalize_trace(trace)
            arg_summary = summarize_args(args)
            halted = self._kill_switch(str(skill), str(tool), path_list, base_dir)
            if halted is not None:
                decision = halted
            elif refuse is not None:
                decision = Decision(
                    Verdict.DENY,
                    f"arguments refused: {refuse}",
                    str(skill),
                    str(tool),
                    tuple(path_list),
                )
            elif self._grants is not None:
                decision = self._evaluate_granted(
                    str(skill),
                    str(tool),
                    path_list,
                    base_dir,
                    principal_id,
                    grant,
                    session_key,
                    approval,
                    args,
                )
            else:
                decision = _decide(
                    self._policy,
                    str(skill),
                    str(tool),
                    path_list,
                    base_dir,
                )
            if self._grants is not None and decision.gate is None:
                # Kill switch and refuse rows: nothing is admitted.
                decision = replace(
                    decision,
                    gate="admission",
                    principal_id=principal_id if isinstance(principal_id, str) else None,
                )
            # observe mode records the true verdict but does not act on it
            decision = replace(decision, enforced=(self._mode == ENFORCE))
            if decision.verdict is Verdict.ISOLATE and decision.enforced:
                decision = replace(decision, route_ticket=secrets.token_hex(16))
            if not self._log_folder_lost:
                self._log(decision, trace=norm_trace, arg_summary=arg_summary)
            return decision
        except Exception as exc:  # any failure is a denial, on purpose
            decision = Decision(
                Verdict.DENY,
                f"gate error, failing closed: {exc!r}",
                str(skill),
                str(tool),
                tuple(path_list),
            )
            decision = replace(decision, enforced=(self._mode == ENFORCE))
            try:
                self._log(decision, trace=None, arg_summary=None)
            except Exception:
                # Still return the denial. Enforce callers that need the raise
                # see it from _log only when the outer path did not already
                # catch; here the record attempt failed after a prior error.
                if self._mode == ENFORCE:
                    raise
            return decision

    def _evaluate_granted(
        self,
        skill: str,
        tool: str,
        path_list: list[str],
        base_dir: str | None,
        principal_id,
        grant,
        session_key,
        approval,
        args,
    ) -> Decision:
        """Step 3b of the wiring spec plus the execution gate.

        Gate 1 (admission): principal present, grant verified this call, the
        grant names this principal, label and tool. Gate 2 (execution): every
        path inside the grant, then policy decides exactly as without grants,
        then an ASK may be lifted by a bound approval receipt, then the ledger
        cap check. The grant only narrows; it never turns a policy DENY, ASK,
        or ISOLATE into ALLOW.
        """
        from capability_gate_grants import (
            CredentialRefused,
            GrantStore,
            StoreError,
            approval_id,
            check_approval,
            manifest_hash,
            verify,
        )

        cfg = self._grants
        pid = principal_id if isinstance(principal_id, str) and principal_id else None
        ptuple = tuple(path_list)

        def deny(reason: str, gate: str, g=None) -> Decision:
            return Decision(
                Verdict.DENY,
                f"grant: {reason}",
                skill,
                tool,
                ptuple,
                principal_id=pid,
                grant_id=g.grant_id if g is not None else None,
                parent_grant_id=g.parent_grant_id if g is not None else None,
                gate=gate,
            )

        if pid is None:
            return deny("missing principal_id", "admission")
        if grant is None:
            return deny("no grant", "admission")
        try:
            g = verify(cfg, grant, session_key)
        except CredentialRefused as exc:
            return deny(str(exc), "admission")
        if pid != g.principal_id:
            return deny("principal does not match grant", "admission", g)
        if skill != g.skill:
            return deny("label does not match grant", "admission", g)
        if tool not in g.tools:
            return deny("tool outside grant", "admission", g)
        for p in path_list:
            a = _absolute(p, base_dir)
            if a is None:
                return deny(f"relative path '{p}' has no base folder", "execution", g)
            if not _path_allowed(a, g.paths):
                return deny(f"path '{p}' outside grant", "execution", g)
        decision = _decide(self._policy, skill, tool, path_list, base_dir)
        manifest = manifest_hash(
            principal_id=pid,
            skill=skill,
            tool=tool,
            paths=decision.paths,
            args=args,
            pol_hash=self._policy_hash,
        )
        decision = replace(
            decision,
            principal_id=pid,
            grant_id=g.grant_id,
            parent_grant_id=g.parent_grant_id,
            gate="execution",
            manifest_hash=manifest,
        )
        if decision.verdict is Verdict.ASK and approval is not None:
            why = check_approval(
                cfg,
                approval,
                manifest=manifest,
                principal_id=pid,
                pol_hash=self._policy_hash,
                now=cfg.clock(),
            )
            if why is not None:
                return replace(decision, verdict=Verdict.DENY, reason=f"grant: {why}")
            decision = replace(
                decision,
                verdict=Verdict.ALLOW,
                reason="approved by bound receipt",
                approval_id=approval_id(approval),
            )
        if decision.verdict is Verdict.ALLOW:
            try:
                store = GrantStore(cfg.store_path)
                lineage = store.load()["lineage"]
                chain = [
                    (lineage[gid]["principal_id"], gid, lineage[gid]["budget"])
                    for gid in store.lineage_chain(g.grant_id)
                ]
                why = self._ledger.check_and_charge(
                    chain=chain,
                    tool=tool,
                    manifest=manifest,
                    cfg=cfg,
                    now=cfg.clock(),
                    charge={"calls": 1},
                )
            except StoreError as exc:
                why = f"ledger unreadable, failing closed: {exc}"
            if why is not None:
                return replace(decision, verdict=Verdict.DENY, reason=f"grant: {why}")
        return decision

    def admitted_tools(self, skill, tools, *, principal_id=None, grant=None, session_key=None):
        """M1-A2: the tool list a harness may show this principal. A tool the
        grant or policy does not admit is absent. Hiding is not the control:
        a forced call is still denied by evaluate."""
        rule = self._policy.skills.get(skill)
        if rule is None:
            return []
        allowed = [t for t in tools if t in rule.tools]
        if self._grants is None:
            return allowed
        from capability_gate_grants import CredentialRefused, verify

        try:
            g = verify(self._grants, grant, session_key)
        except CredentialRefused:
            return []
        if g.principal_id != principal_id or g.skill != skill:
            return []
        return [t for t in allowed if t in g.tools]

    def _log(
        self,
        decision: Decision,
        *,
        trace: Mapping[str, str] | None = None,
        arg_summary: Mapping | None = None,
    ) -> None:
        record_decision(
            self._log_path,
            self._mode,
            decision,
            trace=trace,
            arg_summary=arg_summary,
            anchor_path=self._anchor_path,
            checkpoint=self._checkpoint,
        )


@dataclass(frozen=True)
class AuthorizedRead:
    """One gate decision bound to the file object the host must consume."""

    decision: Decision
    stream: IO[str] | None
    opened_path: str | None


@contextmanager
def open_authorized_read(
    gate: Gate,
    skill: str,
    path: str,
    *,
    tool: str = "read_file",
    trace: Mapping[str, str] | None = None,
    args: Mapping | None = None,
    base_dir: str | None = None,
    encoding: str = "utf-8",
) -> Iterator[AuthorizedRead]:
    """Open once, authorize the opened object, and keep that descriptor bound.

    Linux exposes the opened object through ``/proc/self/fd``. The gate checks
    that object rather than re-resolving the caller's name, and the host reads
    from the same descriptor. A platform without this identity surface denies
    instead of falling back to a check-then-open sequence.
    """

    fd = -1
    stream: IO[str] | None = None
    opened_path: str | None = None
    decision_args = args if args is not None else {"path": path}
    absolute = _absolute(path, base_dir)
    refuse: str | None = None
    try:
        if absolute is None:
            refuse = "open-by-fd requires an absolute path or a trusted base directory"
        elif os.name != "posix" or not os.path.isdir("/proc/self/fd"):
            refuse = "open-by-fd requires the Linux /proc/self/fd identity surface"
        elif not hasattr(os, "O_NOFOLLOW"):
            refuse = "open-by-fd requires O_NOFOLLOW"
        else:
            flags = os.O_RDONLY | os.O_NOFOLLOW
            flags |= getattr(os, "O_CLOEXEC", 0)
            try:
                fd = os.open(absolute, flags)
                opened = os.fstat(fd)
                if not stat.S_ISREG(opened.st_mode):
                    refuse = "opened object is not a regular file"
                else:
                    opened_path = os.path.realpath(f"/proc/self/fd/{fd}")
            except OSError as exc:
                refuse = f"descriptor open failed: {exc.strerror or exc!s}"

        checked_paths = [opened_path] if opened_path is not None else [path]
        decision = gate.evaluate(
            skill,
            tool,
            checked_paths,
            trace=trace,
            args=decision_args,
            refuse=refuse,
            base_dir=base_dir if opened_path is None else None,
        )
        if decision.verdict is Verdict.ALLOW or not decision.enforced:
            if fd < 0:
                raise RuntimeError("descriptor-backed passthrough has no descriptor")
            stream = os.fdopen(fd, "r", encoding=encoding)
            fd = -1
        yield AuthorizedRead(decision, stream, opened_path)
    finally:
        if stream is not None:
            stream.close()
        if fd >= 0:
            os.close(fd)


def record_decision(
    log_path: str,
    mode: str,
    decision: Decision,
    *,
    trace: Mapping[str, str] | None = None,
    arg_summary: Mapping | None = None,
    anchor_path: str | None = None,
    checkpoint: CheckpointConfig | None = None,
) -> None:
    """Write one durable decision row with parent link, witness, and anchor update.

    Shared by Gate._log and the adapter's fail-closed branches, so a denial that
    never reached evaluate() is still on the record (2026-09-28 incident: nine
    days of fail-closed denials, 0 rows).
    """
    record = {"ts": time.time(), "mode": mode, **decision.as_dict()}
    if trace:
        for field in _TRACE_FIELDS:
            if field in trace:
                record[field] = trace[field]
    if arg_summary:
        record["arg_summary"] = dict(arg_summary)
    run_id = os.environ.get("SITTING_RUN_ID", "").strip()
    if run_id:
        record["run_id"] = run_id
    try:
        os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
        with _audit_lock(log_path):
            # F-3: verify and append under one lock so two processes cannot
            # both parent the same head.
            head, count = _verify_log(log_path, anchor_path, checkpoint)
            record["parent"] = head
            checked = checked_log_record(record)
            body = json.dumps(checked, sort_keys=True)
            line = body + "\n"
            fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                before = os.fstat(fd).st_size
                payload = line.encode("utf-8")
                written = os.write(fd, payload)
                if written != len(payload):
                    # F-2: roll back a torn line so the chain stays readable.
                    os.ftruncate(fd, before)
                    raise OSError(
                        f"short audit log write: {written} of {len(payload)} bytes"
                    )
                os.fsync(fd)  # durable before the action runs
            finally:
                os.close(fd)
            _write_witness(
                _witness_path(log_path),
                _hash_log_line(body),
                count + 1,
            )
            _write_witness(
                anchor_path or _anchor_path(log_path),
                _hash_log_line(body),
                count + 1,
            )
    except Exception:
        # A gate that cannot record its own decisions is not trustworthy.
        # Re-raise so the adapter treats that as a denial in enforce mode.
        raise


def _main(argv: Sequence[str] | None = None) -> int:
    """Operator commands. The agent never runs these; they act on the record."""
    import argparse

    parser = argparse.ArgumentParser(prog="capability_gate.py")
    sub = parser.add_subparsers(dest="command", required=True)
    re_cmd = sub.add_parser(
        "reanchor",
        help="retire a damaged decision log, witness, and anchor so a new chain starts",
    )
    re_cmd.add_argument("--log", required=True, help="decision log path")
    re_cmd.add_argument("--anchor", help="anchor path, when not beside the log")
    for name, text in (
        (
            "checkpoint-request",
            "print the hashes-only request to extend the signed checkpoint",
        ),
        ("checkpoint-verify", "check the log against the newest signed checkpoint"),
    ):
        c = sub.add_parser(name, help=text)
        c.add_argument("--log", required=True, help="decision log path")
        c.add_argument("--folder", required=True, help="folder of signed notes")
        c.add_argument("--vkey", required=True, help="C2SP verifier key")
        c.add_argument("--origin", required=True, help="the log's origin line")
        if name == "checkpoint-request":
            c.add_argument("--first", action="store_true", help="first checkpoint")
    s = sub.add_parser(
        "checkpoint-sign",
        help="CI only: sign a request that extends the last signed note; "
        "the key comes from CG_CHECKPOINT_SIGNING_KEY and is never printed",
    )
    s.add_argument("--prev", required=True, help="newest signed note, or 'none'")
    s.add_argument("--request", required=True, help="request JSON file")
    s.add_argument("--vkey", required=True, help="C2SP verifier key")
    args = parser.parse_args(argv)
    if args.command.startswith("checkpoint-"):
        return _checkpoint_command(args)
    retired = reanchor_audit_log(args.log, anchor_path=args.anchor)
    if retired:
        print("retired: " + ", ".join(retired))
    else:
        print("nothing to retire")
    return 0


def _checkpoint_command(args) -> int:
    """Run one checkpoint command; any failure prints one line and exits 1."""
    try:
        if args.command == "checkpoint-sign":
            import base64

            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )

            seed = os.environ.get("CG_CHECKPOINT_SIGNING_KEY", "")
            if not seed:
                raise CheckpointError("CG_CHECKPOINT_SIGNING_KEY is not set")
            key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(seed))
            prev = None
            if args.prev != "none":
                with open(args.prev, encoding="utf-8", newline="") as fh:
                    prev = fh.read()
            with open(args.request, encoding="utf-8") as fh:
                request = json.load(fh)
            note = sign_extending(prev, request, args.vkey, key)
            # UTF-8 bytes on every platform: the signature line starts with
            # an em dash, which a Windows console code page would rewrite.
            sys.stdout.buffer.write(note.encode("utf-8"))
            sys.stdout.flush()
            return 0
        cfg = CheckpointConfig(args.folder, args.vkey, args.origin)
        if args.command == "checkpoint-request":
            req = checkpoint_request(args.log, cfg, first=args.first)
            print(json.dumps(req, sort_keys=True))
            return 0
        _cp_check(cfg, _cp_log_lines(args.log))
        print("checkpoint: the log matches its newest signed checkpoint")
        return 0
    except (CheckpointError, OSError, ValueError, KeyError) as exc:
        print(f"checkpoint: BLOCKED, {exc}. Fix: sync the signed notes or re-anchor.")
        return 1


if __name__ == "__main__":
    raise SystemExit(_main())
