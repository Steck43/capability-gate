"""Per-call grants for capability-gate (B9 wiring, scratch build).

Ported from the B9 seed (``aegis_b9/credential.py`` and ``receipts.py``) and
wired into ``Gate.evaluate`` as step 3b of the wiring spec. Standard library
only, like the decider.

What this module holds:

* ``GrantConfig``: the key, audience, and the three state files (grant store,
  ledger, approval nonce file). A Gate built without one behaves exactly as
  before.
* Grant tickets: base64url(canonical JSON) "." base64url(HMAC-SHA256). The
  gate re-verifies the ticket on every call. A ticket is bound to one session
  key (only its hash is stored), so a grant is not a bearer token.
* ``GrantStore``: current nonce per grant (refresh rotates it), revoked
  grants, retired principals, a revoke-before time set by the kill switch,
  lineage, and the session each principal is bound to. Missing or corrupt
  after first use means every grant is refused.
* ``Ledger``: per (principal, grant, tool, unit) counters, checked before the
  call and charged on ALLOW, charged up the lineage so a child can never
  spend more than its parent has left. Missing, corrupt, or rolled back means
  DENY.
* Approval receipts for ASK: bound to the action manifest hash (tool, skill,
  resolved paths, full args hash, principal, policy hash), a named approver who
  is not an agent principal, a not_after, and a nonce consumed once.

Limits, stated plainly: tickets and receipts are local HMAC tokens with file
stores. They are not an identity provider and a stranger cannot verify them.
The key lives in the gate's process, on the same host as the agent; the gate
refuses tool paths that name the key file or any state file, which is
separation by process and path, not an external authority.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field

MIN_KEY_BYTES = 32
MAX_TTL_SECONDS = 3600
MAX_LINEAGE = 16
# Grant lifetime cap by risk tier (NHI7). A grant over its tier cap is
# refused at mint, so no setting gives a grant an unbounded life.
RISK_TTL_CAPS: Mapping[str, int] = {"low": 3600, "medium": 900, "high": 300}
UNITS = frozenset({"calls", "tokens", "wall_seconds", "egress_bytes"})

_DOMAIN = b"capability-gate-grant-v1\x00"
_RECEIPT_DOMAIN = b"capability-gate-approval-v1\x00"
_B64 = re.compile(r"^[A-Za-z0-9_-]+$")
_ID = re.compile(r"^[A-Za-z0-9._:/-]{1,128}$")
FIELDS = (
    "grant_id",
    "principal_id",
    "skill",
    "tools",
    "paths",
    "audience",
    "issued_at",
    "not_after",
    "nonce",
    "parent_principal_id",
    "parent_grant_id",
    "risk",
    "session",
    "budget",
)
_STORE_KEYS = frozenset(
    {
        "initialized",
        "nonces",
        "revoked_grants",
        "revoked_principals",
        "revoked_before",
        "lineage",
        "sessions",
    }
)


class CredentialRefused(Exception):
    """A grant or receipt is not usable. The message is the denial reason."""


class StoreError(Exception):
    """A state file is missing, corrupt, or rolled back."""


@dataclass(frozen=True)
class GrantConfig:
    key: bytes
    audience: str
    store_path: str
    ledger_path: str
    approval_nonce_path: str | None = None
    approvers: frozenset[str] = frozenset()
    key_paths: tuple[str, ...] = ()
    rate_limit: tuple[int, float] | None = None  # (max calls, window seconds) per principal and tool
    loop_limit: int | None = None  # max identical manifests inside the rate window
    clock: Callable[[], float] = time.time

    def protected_files(self) -> tuple[str, ...]:
        out = [self.store_path, self.store_path + ".lock", self.ledger_path, self.ledger_path + ".lock"]
        if self.approval_nonce_path:
            out += [self.approval_nonce_path, self.approval_nonce_path + ".lock"]
        out += list(self.key_paths)
        return tuple(os.path.abspath(p) for p in out)


@dataclass(frozen=True)
class Grant:
    grant_id: str
    principal_id: str
    skill: str
    tools: tuple
    paths: tuple
    audience: str
    issued_at: float
    not_after: int
    nonce: str
    parent_principal_id: str | None = None
    parent_grant_id: str | None = None
    risk: str = "low"
    session: str = ""
    budget: Mapping[str, int] = field(default_factory=dict)


# --- encoding -----------------------------------------------------------------


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    if not _B64.match(s):
        raise CredentialRefused("malformed ticket encoding")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError) as exc:
        raise CredentialRefused("malformed ticket encoding") from exc


def _check_key(key) -> None:
    if not isinstance(key, bytes) or len(key) < MIN_KEY_BYTES:
        raise CredentialRefused("signing key missing or too short")


def _mac(key: bytes, payload: bytes, domain: bytes = _DOMAIN) -> bytes:
    return hmac.new(key, domain + payload, hashlib.sha256).digest()


def session_hash(session_key: str) -> str:
    if not isinstance(session_key, str) or len(session_key) < 16:
        raise CredentialRefused("session key missing or too short")
    return hashlib.sha256(b"capability-gate-session\x00" + session_key.encode()).hexdigest()


def valid_pattern(pat) -> bool:
    """Grant path patterns: an absolute exact path or '<dir>/**', nothing else.

    Narrower than policy globs on purpose, so "is this child inside its
    parent" stays decidable as text.
    """
    if not isinstance(pat, str) or not pat.startswith("/") or "\x00" in pat:
        return False
    if "$" in pat or "~" in pat:
        return False
    base = pat[:-3] if pat.endswith("/**") else pat
    if pat == "/**":
        return True
    if any(c in base for c in "*?["):
        return False
    return os.path.normpath(base) == base


def pattern_within(child: str, parent: str) -> bool:
    if not (valid_pattern(child) and valid_pattern(parent)):
        return False
    if parent == "/**":
        return True
    if parent.endswith("/**"):
        pbase = parent[:-3]
        cbase = child[:-3] if child.endswith("/**") else child
        return cbase == pbase and child.endswith("/**") or cbase.startswith(pbase + "/")
    return child == parent


def validate(g: Grant) -> None:
    def ident(v, name, optional=False):
        if v is None and optional:
            return
        if not isinstance(v, str) or not _ID.match(v):
            raise CredentialRefused(f"bad {name}")

    ident(g.grant_id, "grant_id")
    ident(g.principal_id, "principal_id")
    ident(g.skill, "skill")
    ident(g.audience, "audience")
    ident(g.parent_principal_id, "parent_principal_id", optional=True)
    ident(g.parent_grant_id, "parent_grant_id", optional=True)
    if (g.parent_principal_id is None) != (g.parent_grant_id is None):
        raise CredentialRefused("parent fields must be set together")
    if not isinstance(g.tools, tuple) or not g.tools or not all(
        isinstance(t, str) and _ID.match(t) for t in g.tools
    ):
        raise CredentialRefused("bad tools")
    if not isinstance(g.paths, tuple) or not g.paths or not all(valid_pattern(p) for p in g.paths):
        raise CredentialRefused("bad paths")
    if not isinstance(g.not_after, int) or isinstance(g.not_after, bool):
        raise CredentialRefused("bad not_after")
    if not isinstance(g.issued_at, (int, float)) or isinstance(g.issued_at, bool):
        raise CredentialRefused("bad issued_at")
    if not isinstance(g.nonce, str) or len(g.nonce) < 16:
        raise CredentialRefused("bad nonce")
    if g.risk not in RISK_TTL_CAPS:
        raise CredentialRefused("bad risk tier")
    if not isinstance(g.session, str) or not re.fullmatch(r"[0-9a-f]{64}", g.session):
        raise CredentialRefused("grant not bound to a session")
    if not isinstance(g.budget, Mapping) or not all(
        u in UNITS and isinstance(v, int) and not isinstance(v, bool) and v >= 0
        for u, v in g.budget.items()
    ):
        raise CredentialRefused("bad budget")


def encode(g: Grant, key: bytes) -> str:
    _check_key(key)
    validate(g)
    d = asdict(g)
    d["tools"], d["paths"], d["budget"] = list(g.tools), list(g.paths), dict(g.budget)
    payload = _canon(d)
    return f"{_b64e(payload)}.{_b64e(_mac(key, payload))}"


def decode_verified(ticket, key: bytes) -> Grant:
    _check_key(key)
    if not isinstance(ticket, str) or ticket.count(".") != 1 or len(ticket) > 16384:
        raise CredentialRefused("missing or malformed ticket")
    p64, m64 = ticket.split(".")
    payload, mac = _b64d(p64), _b64d(m64)
    if not hmac.compare_digest(mac, _mac(key, payload)):
        raise CredentialRefused("bad signature")
    try:
        d = json.loads(payload)
    except ValueError as exc:
        raise CredentialRefused("bad payload") from exc
    if not isinstance(d, dict) or set(d) != set(FIELDS):
        raise CredentialRefused("bad payload fields")
    if not isinstance(d["tools"], list) or not isinstance(d["paths"], list):
        raise CredentialRefused("bad payload types")
    d["tools"], d["paths"] = tuple(d["tools"]), tuple(d["paths"])
    g = Grant(**d)
    validate(g)
    return g


# --- locked JSON state files ------------------------------------------------------


def _locked(path: str):
    # Same lock the decision log uses: flock on "<path>.lock".
    from capability_gate import _audit_lock

    return _audit_lock(path)


def _read_state(path: str, what: str) -> dict:
    from capability_gate import _owned_regular_file

    if not os.path.lexists(path):
        raise StoreError(f"{what} missing after first use")
    try:
        _owned_regular_file(path, what)
        with open(path, encoding="utf-8") as fh:
            st = json.load(fh)
    except (OSError, ValueError) as exc:
        raise StoreError(f"{what} unreadable: {type(exc).__name__}") from exc
    if not isinstance(st, dict):
        raise StoreError(f"{what} malformed")
    return st


def _write_state(path: str, st: dict) -> None:
    tmp = f"{path}.tmp-{secrets.token_hex(4)}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, json.dumps(st, sort_keys=True).encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


class GrantStore:
    def __init__(self, path: str):
        self.path = os.path.abspath(str(path))

    def ensure(self) -> None:
        """Create the store once. After this, a missing store is tamper."""
        with _locked(self.path):
            if not os.path.lexists(self.path):
                _write_state(
                    self.path,
                    {
                        "initialized": True,
                        "nonces": {},
                        "revoked_grants": [],
                        "revoked_principals": [],
                        "revoked_before": None,
                        "lineage": {},
                        "sessions": {},
                    },
                )

    def load(self) -> dict:
        st = _read_state(self.path, "grant store")
        if set(st) != _STORE_KEYS or st.get("initialized") is not True:
            raise StoreError("grant store malformed")
        return st

    def _update(self, fn) -> None:
        with _locked(self.path):
            st = self.load()
            fn(st)
            _write_state(self.path, st)

    def register(self, g: Grant) -> None:
        def go(st):
            bound = st["sessions"].get(g.principal_id)
            if bound is not None and bound != g.session:
                # NHI5/NHI9: one principal per agent instance.
                raise CredentialRefused("principal id already bound to another session")
            st["sessions"][g.principal_id] = g.session
            st["nonces"][g.grant_id] = g.nonce
            st["lineage"][g.grant_id] = {
                "principal_id": g.principal_id,
                "parent_grant_id": g.parent_grant_id,
                "not_after": g.not_after,
                "budget": dict(g.budget),
            }

        self._update(go)

    def revoke_grant(self, grant_id: str) -> None:
        self._update(lambda st: st["revoked_grants"].append(grant_id))

    def retire_principal(self, principal_id: str) -> None:
        """NHI1: every grant of this principal, and every descendant, is dead."""
        self._update(lambda st: st["revoked_principals"].append(principal_id))

    def revoke_before(self, ts: float) -> None:
        def go(st):
            cur = st["revoked_before"]
            st["revoked_before"] = ts if cur is None else max(cur, ts)

        self._update(go)

    def lineage_chain(self, grant_id: str) -> list[str]:
        st = self.load()
        out, cur = [], grant_id
        while cur is not None:
            rec = st["lineage"].get(cur)
            if rec is None:
                raise StoreError("grant not in lineage")
            out.append(cur)
            if len(out) > MAX_LINEAGE:
                raise StoreError("lineage too deep")
            cur = rec["parent_grant_id"]
        return out

    def agent_principals(self) -> frozenset[str]:
        st = self.load()
        return frozenset(rec["principal_id"] for rec in st["lineage"].values())


def _ttl_ok(ttl, risk) -> None:
    if risk not in RISK_TTL_CAPS:
        raise CredentialRefused("bad risk tier")
    if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0:
        raise CredentialRefused("ttl outside short-lived window")
    if ttl > min(MAX_TTL_SECONDS, RISK_TTL_CAPS[risk]):
        raise CredentialRefused(f"ttl over the {risk} risk cap")


def issue(
    cfg: GrantConfig,
    *,
    principal_id: str,
    skill: str,
    tools: Sequence[str],
    paths: Sequence[str],
    session_key: str,
    ttl: int,
    risk: str = "low",
    budget: Mapping[str, int] | None = None,
    grant_id: str | None = None,
) -> str:
    """Bootstrap issuer (issuer of record is still a Landen pick)."""
    _ttl_ok(ttl, risk)
    now = cfg.clock()
    g = Grant(
        grant_id=grant_id or "g-" + secrets.token_hex(8),
        principal_id=principal_id,
        skill=skill,
        tools=tuple(tools),
        paths=tuple(paths),
        audience=cfg.audience,
        issued_at=now,
        not_after=int(now) + ttl,
        nonce=secrets.token_hex(16),
        risk=risk,
        session=session_hash(session_key),
        budget=dict(budget or {}),
    )
    ticket = encode(g, cfg.key)
    GrantStore(cfg.store_path).register(g)
    return ticket


def verify(cfg: GrantConfig, ticket, session_key) -> Grant:
    now = cfg.clock()
    g = decode_verified(ticket, cfg.key)
    if g.audience != cfg.audience:
        raise CredentialRefused("wrong audience")
    if now >= g.not_after:
        raise CredentialRefused("expired")
    if session_key is None:
        raise CredentialRefused("no session key; grants are not bearer tokens")
    if not hmac.compare_digest(session_hash(session_key), g.session):
        raise CredentialRefused("session does not match grant")
    try:
        st = GrantStore(cfg.store_path).load()
    except StoreError as exc:
        raise CredentialRefused(str(exc)) from exc
    if st["nonces"].get(g.grant_id) != g.nonce:
        raise CredentialRefused("nonce not current (refreshed or unknown grant)")
    rb = st["revoked_before"]
    if rb is not None and g.issued_at <= rb:
        raise CredentialRefused("revoked by kill switch; a fresh grant is required")
    cur, hops = g.grant_id, 0
    while cur is not None:
        rec = st["lineage"].get(cur)
        if rec is None:
            raise CredentialRefused("grant not in lineage")
        if cur in st["revoked_grants"] or rec["principal_id"] in st["revoked_principals"]:
            raise CredentialRefused("revoked" if cur == g.grant_id else "ancestor revoked")
        if now >= rec["not_after"]:
            raise CredentialRefused("ancestor expired")
        hops += 1
        if hops > MAX_LINEAGE:
            raise CredentialRefused("lineage too deep")
        cur = rec["parent_grant_id"]
    return g


def refresh(cfg: GrantConfig, ticket: str, session_key: str, ttl: int) -> str:
    """New nonce and life. Never past the parent's not_after; never wider."""
    old = verify(cfg, ticket, session_key)
    _ttl_ok(ttl, old.risk)
    now = cfg.clock()
    new_after = int(now) + ttl
    if old.parent_grant_id is not None:
        parent_after = GrantStore(cfg.store_path).load()["lineage"][old.parent_grant_id]["not_after"]
        new_after = min(new_after, parent_after)
    d = asdict(old)
    d.update(not_after=new_after, nonce=secrets.token_hex(16), issued_at=now)
    d["tools"], d["paths"] = tuple(old.tools), tuple(old.paths)
    new = Grant(**d)
    out = encode(new, cfg.key)
    GrantStore(cfg.store_path).register(new)
    return out


def attenuate(
    cfg: GrantConfig,
    parent_ticket: str,
    parent_session_key: str,
    *,
    principal_id: str,
    session_key: str,
    tools: Sequence[str],
    paths: Sequence[str],
    ttl: int,
    budget: Mapping[str, int] | None = None,
    grant_id: str | None = None,
) -> str:
    """Child grant that can only shrink: tools subset, paths within, life within,
    budget within. Spawn wiring (B10a) stays frozen; this is the grant math only."""
    parent = verify(cfg, parent_ticket, parent_session_key)
    if principal_id == parent.principal_id:
        raise CredentialRefused("child must be a distinct principal")
    if not set(tools) <= set(parent.tools):
        raise CredentialRefused("attenuate: tools not a subset of parent")
    for p in paths:
        if not any(pattern_within(p, pp) for pp in parent.paths):
            raise CredentialRefused("attenuate: path not within parent")
    child_budget = dict(budget or {})
    for unit, cap in parent.budget.items():
        if unit not in child_budget or child_budget[unit] > cap:
            raise CredentialRefused("attenuate: budget not within parent")
    _ttl_ok(ttl, parent.risk)
    now = cfg.clock()
    g = Grant(
        grant_id=grant_id or "g-" + secrets.token_hex(8),
        principal_id=principal_id,
        skill=parent.skill,
        tools=tuple(tools),
        paths=tuple(paths),
        audience=cfg.audience,
        issued_at=now,
        not_after=min(int(now) + ttl, parent.not_after),
        nonce=secrets.token_hex(16),
        parent_principal_id=parent.principal_id,
        parent_grant_id=parent.grant_id,
        risk=parent.risk,
        session=session_hash(session_key),
        budget=child_budget,
    )
    out = encode(g, cfg.key)
    GrantStore(cfg.store_path).register(g)
    return out


def end(cfg: GrantConfig, grant_id: str) -> None:
    """Expire on complete."""
    GrantStore(cfg.store_path).revoke_grant(grant_id)


# --- action manifest and policy hash ------------------------------------------


def policy_hash(policy) -> str:
    body = {
        "skills": {
            name: {"tools": sorted(rule.tools), "paths": list(rule.path_globs)}
            for name, rule in sorted(policy.skills.items())
        },
        "require_approval": sorted(policy.require_approval),
        "isolate": sorted(policy.isolate),
    }
    return hashlib.sha256(_canon(body)).hexdigest()


def args_hash(args: Mapping | None) -> str:
    try:
        body = _canon(args if args is not None else None)
    except (TypeError, ValueError):
        body = repr(args).encode()
    return hashlib.sha256(body).hexdigest()


def manifest_hash(*, principal_id, skill, tool, paths, args, pol_hash) -> str:
    body = {
        "principal_id": principal_id,
        "skill": skill,
        "tool": tool,
        "paths": sorted(paths),
        "args_hash": args_hash(args),
        "policy_hash": pol_hash,
    }
    return hashlib.sha256(_canon(body)).hexdigest()


# --- ledger (D5) ------------------------------------------------------------------


class Ledger:
    """Counters keyed by principal|grant|tool|unit plus a call history for rate
    and loop checks. ``seq`` only grows; a file whose seq is below the last one
    this process saw was rolled back or replaced, and that is a DENY."""

    def __init__(self, path: str):
        self.path = os.path.abspath(str(path))
        self._seen_seq = -1

    def ensure(self) -> None:
        with _locked(self.path):
            if not os.path.lexists(self.path):
                _write_state(self.path, {"seq": 0, "used": {}, "history": []})
            self._seen_seq = max(self._seen_seq, self._load()["seq"])

    def _load(self) -> dict:
        st = _read_state(self.path, "ledger")
        if set(st) != {"seq", "used", "history"} or not isinstance(st["seq"], int):
            raise StoreError("ledger malformed")
        if st["seq"] < self._seen_seq:
            raise StoreError("ledger stale (rolled back or replaced)")
        return st

    @staticmethod
    def key(principal_id, grant_id, tool, unit) -> str:
        return f"{principal_id}|{grant_id}|{tool}|{unit}"

    def check_and_charge(
        self,
        *,
        chain: Sequence[tuple[str, str, Mapping[str, int]]],
        tool: str,
        manifest: str,
        cfg: GrantConfig,
        now: float,
        charge: Mapping[str, int],
    ) -> str | None:
        """chain: (principal_id, grant_id, budget) for the grant and each ancestor.
        Returns a deny reason, or None after charging every level."""
        with _locked(self.path):
            st = self._load()
            principal = chain[0][0]
            if cfg.rate_limit is not None:
                max_calls, window = cfg.rate_limit
                recent = [h for h in st["history"] if now - h["ts"] < window]
                same_tool = [h for h in recent if h["p"] == principal and h["tool"] == tool]
                if len(same_tool) >= max_calls:
                    return f"rate limit: {max_calls} calls of '{tool}' per {window}s for this principal"
                if cfg.loop_limit is not None:
                    loops = [h for h in recent if h["p"] == principal and h["m"] == manifest]
                    if len(loops) >= cfg.loop_limit:
                        return "loop guard: identical action repeated"
            for p, gid, budget in chain:
                for unit, cap in budget.items():
                    have = sum(
                        v for k, v in st["used"].items()
                        if k.split("|")[1] == gid and k.split("|")[3] == unit
                    )
                    # Children charge their ancestors, so each level's keys hold
                    # its own spend plus every descendant's. A unit this call
                    # does not charge is denied once it is already spent.
                    want = charge.get(unit, 0)
                    if (want and have + want > cap) or (not want and have >= cap):
                        return f"budget: {unit} cap {cap} reached for grant {gid}"
            for p, gid, _budget in chain:
                for unit, amount in charge.items():
                    k = self.key(p, gid, tool, unit)
                    st["used"][k] = st["used"].get(k, 0) + amount
            st["history"].append({"ts": now, "p": principal, "tool": tool, "m": manifest})
            st["history"] = st["history"][-1000:]
            st["seq"] += 1
            _write_state(self.path, st)
            self._seen_seq = st["seq"]
            return None

    def charge_usage(self, chain, tool: str, usage: Mapping[str, int]) -> None:
        """Post-call usage (tokens, wall seconds, egress bytes) reported by the host.
        Counts against the next pre-call check; it is not itself a control."""
        for unit in usage:
            if unit not in UNITS:
                raise StoreError(f"unknown unit {unit}")
        with _locked(self.path):
            st = self._load()
            for p, gid, _b in chain:
                for unit, amount in usage.items():
                    k = self.key(p, gid, tool, unit)
                    st["used"][k] = st["used"].get(k, 0) + int(amount)
            st["seq"] += 1
            _write_state(self.path, st)
            self._seen_seq = st["seq"]


# --- approval receipts (D4) -----------------------------------------------------


def mint_approval(
    key: bytes,
    *,
    manifest: str,
    principal_id: str,
    approver: str,
    tool: str,
    pol_hash: str,
    not_after: int,
    nonce: str | None = None,
) -> str:
    """Made by the out-of-band approval path, never by the agent."""
    _check_key(key)
    body = {
        "manifest": manifest,
        "principal_id": principal_id,
        "approver": approver,
        "tool": tool,
        "policy_hash": pol_hash,
        "not_after": int(not_after),
        "nonce": nonce or secrets.token_hex(16),
    }
    payload = _canon(body)
    return f"{_b64e(payload)}.{_b64e(_mac(key, payload, _RECEIPT_DOMAIN))}"


def approval_id(receipt: str) -> str:
    return hashlib.sha256(receipt.encode()).hexdigest()[:16]


def check_approval(
    cfg: GrantConfig, receipt, *, manifest: str, principal_id: str, pol_hash: str, now: float
) -> str | None:
    """None when the receipt is good and its nonce is now spent; else the reason."""
    try:
        _check_key(cfg.key)
        if cfg.approval_nonce_path is None:
            return "approval receipts not configured"
        if not isinstance(receipt, str) or receipt.count(".") != 1 or len(receipt) > 8192:
            return "no bound approval receipt"
        p64, m64 = receipt.split(".")
        payload, mac = _b64d(p64), _b64d(m64)
        if not hmac.compare_digest(mac, _mac(cfg.key, payload, _RECEIPT_DOMAIN)):
            return "approval receipt bad mac"
        body = json.loads(payload)
        want = {"manifest", "principal_id", "approver", "tool", "policy_hash", "not_after", "nonce"}
        if not isinstance(body, dict) or set(body) != want:
            return "approval receipt malformed"
        if body["policy_hash"] != pol_hash:
            return "approval receipt minted under another policy"
        if body["manifest"] != manifest:
            return "approval receipt bound to another action"
        if body["principal_id"] != principal_id:
            return "approval receipt for another principal"
        if now >= body["not_after"]:
            return "approval receipt expired"
        approver = body["approver"]
        if approver == principal_id:
            return "approver is the requesting principal"
        if approver not in cfg.approvers:
            return "approver not a named human approver"
        if approver in GrantStore(cfg.store_path).agent_principals():
            return "approver is an agent principal"
        path = cfg.approval_nonce_path
        with _locked(path):
            seen: list[str] = []
            if os.path.lexists(path):
                seen = _read_state(path, "approval nonce file").get("spent", [])
            if body["nonce"] in seen:
                return "approval receipt replay"
            seen.append(body["nonce"])
            _write_state(path, {"spent": seen})
        return None
    except CredentialRefused as exc:
        return f"approval receipt refused: {exc}"
    except Exception as exc:  # fail closed
        return f"approval check failed: {type(exc).__name__}"
