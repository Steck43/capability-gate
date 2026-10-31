"""Per-call grant issuance, verification, accounting, and revocation.

This module is wired into ``Gate.evaluate`` and uses only the standard
library, like the decider.

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
  is not an agent principal, a not_after, and a nonce consumed once. Receipts
  use their own approval key, never the grant key.
* Seals and clock: the store records the highest seq of the ledger and of the
  approval nonce file and the highest gate clock seen. A state file that is
  missing after first use or below its seal is a DENY in every process, and
  time never runs backward for tickets and receipts.

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
_RENEWAL_DOMAIN = b"capability-gate-renewal-v1\x00"
CLOCK_BACKWARD = "clock moved backward; grants refused until reviewed"
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
        "seals",
        "clock_high",
    }
)
# Grant not-before slack in seconds. A ticket whose issued_at is ahead of the
# gate clock by more than this is refused (H4: no nbf).
NBF_SKEW_SECONDS = 0.0


class CredentialRefused(Exception):
    """A grant or receipt is not usable. The message is the denial reason."""


class StoreError(Exception):
    """A state file is missing, corrupt, or rolled back."""


@dataclass(frozen=True)
class GrantConfig:
    key: bytes = field(repr=False)
    audience: str
    store_path: str
    ledger_path: str
    approval_nonce_path: str | None = None
    approvers: frozenset[str] = frozenset()
    key_paths: tuple[str, ...] = ()
    rate_limit: tuple[int, float] | None = (
        None  # (max calls, window seconds) per principal and tool
    )
    loop_limit: int | None = None  # max identical manifests inside the rate window
    clock: Callable[[], float] = time.time
    # I4: how far the raw clock may fall below the store's high-water before
    # every grant is refused. Placeholder, uncalibrated: 0 means any step back.
    clock_backward_slack: float = 0.0
    # H2: approval receipts use their own key, never the grant key, so a
    # holder of the grant issuer key cannot mint a human approval with it.
    approval_key: bytes | None = field(default=None, repr=False)

    def __post_init__(self):
        if self.approval_key is not None and hmac.compare_digest(
            self.approval_key, self.key
        ):
            raise ValueError("approval_key must differ from the grant key")

    def protected_files(self) -> tuple[str, ...]:
        out = [
            self.store_path,
            self.store_path + ".lock",
            self.ledger_path,
            self.ledger_path + ".lock",
        ]
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
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


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
    return hashlib.sha256(
        b"capability-gate-session\x00" + session_key.encode()
    ).hexdigest()


def valid_pattern(pat) -> bool:
    """Grant path patterns: an absolute exact path or '<dir>/**', nothing else.

    Narrower than policy globs on purpose, so "is this child inside its
    parent" stays decidable as text.
    """
    if not isinstance(pat, str) or not pat.startswith("/") or "\x00" in pat:
        return False
    if "$" in pat or "~" in pat:
        return False
    base = pat.removesuffix("/**")
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
        cbase = child.removesuffix("/**")
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
    if (
        not isinstance(g.tools, tuple)
        or not g.tools
        or not all(isinstance(t, str) and _ID.match(t) for t in g.tools)
    ):
        raise CredentialRefused("bad tools")
    if (
        not isinstance(g.paths, tuple)
        or not g.paths
        or not all(valid_pattern(p) for p in g.paths)
    ):
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
                        # High-water seq of the ledger and approval nonce
                        # file (H3, H3b). None means that file was never made.
                        "seals": {"ledger": None, "approvals": None},
                        # Highest gate clock seen; time never runs backward
                        # for grants and receipts (H4).
                        "clock_high": None,
                    },
                )

    def load(self) -> dict:
        st = _read_state(self.path, "grant store")
        if set(st) != _STORE_KEYS or st.get("initialized") is not True:
            raise StoreError("grant store malformed")
        if not isinstance(st["seals"], dict) or set(st["seals"]) != {
            "ledger",
            "approvals",
        }:
            raise StoreError("grant store malformed")
        return st

    def advance_clock(self, raw: float, slack: float = 0.0) -> tuple[dict, float]:
        """Load the store and move its clock high-water to ``raw`` if ahead.
        Returns (state, effective now). A clock rolled back cannot revive an
        expired ticket or receipt (H4), and a step back past ``slack`` refuses
        every grant (I4)."""
        with _locked(self.path):
            st = self.load()
            _check_clock(raw, st, slack)
            now = effective_now(raw, st)
            if st["clock_high"] is None or raw > st["clock_high"]:
                st["clock_high"] = raw
                _write_state(self.path, st)
            return st, now

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
                "issued_at": g.issued_at,
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

    def revoke_all_registered(self, raw_now: float) -> None:
        """Kill-switch revoke: every grant registered so far is dead, even one
        whose issued_at is ahead of the clock (H4 family on the throw path)."""

        def go(st):
            ts = effective_now(raw_now, st)
            for rec in st["lineage"].values():
                ia = rec.get("issued_at")
                if isinstance(ia, (int, float)) and not isinstance(ia, bool):
                    ts = max(ts, ia)
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


def effective_now(raw: float, st: Mapping) -> float:
    high = st.get("clock_high")
    return raw if high is None else max(raw, high)


def _check_clock(raw: float, st: Mapping, slack: float) -> None:
    """I4: the gate clock never runs backward. A raw clock below the
    high-water by more than ``slack`` is a refusal, not a clamp, so a grant
    that is still live at the high-water stops working until the clock is
    reviewed. The caller turns the refusal into a DENY row."""
    high = st.get("clock_high")
    if high is not None and raw < high - slack:
        raise CredentialRefused(CLOCK_BACKWARD)


def _issue_now(cfg: GrantConfig) -> float:
    """Clock for a new grant: never behind the store's high-water."""
    try:
        return effective_now(cfg.clock(), GrantStore(cfg.store_path).load())
    except StoreError:
        return cfg.clock()


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
    """Mint a root grant after validating its requested lifetime and risk."""
    _ttl_ok(ttl, risk)
    now = _issue_now(cfg)
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


def _verify_ticket(cfg: GrantConfig, ticket, session_key) -> Grant:
    """MAC, audience, and session binding. No state is read."""
    g = decode_verified(ticket, cfg.key)
    if g.audience != cfg.audience:
        raise CredentialRefused("wrong audience")
    if session_key is None:
        raise CredentialRefused("no session key; grants are not bearer tokens")
    if not hmac.compare_digest(session_hash(session_key), g.session):
        raise CredentialRefused("session does not match grant")
    return g


def _verify_state(g: Grant, st: Mapping, now: float) -> None:
    """Time, nonce, kill switch, and lineage against one loaded store state."""
    if now >= g.not_after:
        raise CredentialRefused("expired")
    if g.issued_at > now + NBF_SKEW_SECONDS:
        # H4: not-before. A ticket from a clock set ahead is refused.
        raise CredentialRefused("not yet valid (issued after the gate clock)")
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
        if (
            cur in st["revoked_grants"]
            or rec["principal_id"] in st["revoked_principals"]
        ):
            raise CredentialRefused(
                "revoked" if cur == g.grant_id else "ancestor revoked"
            )
        if now >= rec["not_after"]:
            raise CredentialRefused("ancestor expired")
        hops += 1
        if hops > MAX_LINEAGE:
            raise CredentialRefused("lineage too deep")
        cur = rec["parent_grant_id"]


def verify(cfg: GrantConfig, ticket, session_key) -> Grant:
    raw = cfg.clock()
    g = _verify_ticket(cfg, ticket, session_key)
    try:
        st, now = GrantStore(cfg.store_path).advance_clock(
            raw, cfg.clock_backward_slack
        )
    except StoreError as exc:
        raise CredentialRefused(str(exc)) from exc
    _verify_state(g, st, now)
    return g


def refused_ids(cfg: GrantConfig, ticket) -> tuple[str | None, str | None]:
    """grant_id and parent_grant_id of a refused ticket, only when its MAC is
    good. A forged ticket names nothing on the row."""
    try:
        g = decode_verified(ticket, cfg.key)
    except Exception:
        return None, None
    return g.grant_id, g.parent_grant_id


def refresh(
    cfg: GrantConfig,
    ticket: str,
    session_key: str,
    ttl: int,
    *,
    renewal: str | None = None,
) -> str:
    """New nonce and life. Never past the parent's not_after; never wider.

    D3: only a named human renews. ``renewal`` is a receipt from
    ``mint_renewal`` for this grant and this ttl, signed with the approval
    key by someone outside the grant's lineage. Its nonce is spent once."""
    old = verify(cfg, ticket, session_key)
    _ttl_ok(ttl, old.risk)
    why, nonce = renewal_reason(cfg, renewal, grant=old, ttl=ttl, now=cfg.clock())
    if why is not None:
        raise CredentialRefused(why)
    _spend_receipt_nonce(cfg, nonce)
    now = _issue_now(cfg)
    new_after = int(now) + ttl
    if old.parent_grant_id is not None:
        parent_after = GrantStore(cfg.store_path).load()["lineage"][
            old.parent_grant_id
        ]["not_after"]
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
    now = _issue_now(cfg)
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
    and loop checks. ``seq`` only grows. The grant store keeps a seal: the
    highest ledger seq ever written. A ledger whose seq is below the seal, or
    one that is missing after the seal was set, is a DENY in every process,
    so delete or rollback then restart does not reset budgets (H3).

    Lock order everywhere: ledger, then grant store, then approval nonce file.
    """

    def __init__(self, path: str, store_path: str | None = None):
        self.path = os.path.abspath(str(path))
        self.store_path = os.path.abspath(str(store_path)) if store_path else None
        self._seen_seq = -1

    def _store(self) -> GrantStore:
        if self.store_path is None:
            raise StoreError("ledger has no grant store seal")
        return GrantStore(self.store_path)

    def ensure(self) -> None:
        """Create the ledger once, the first time the store has no seal for it.
        After that a missing ledger is tamper and is never re-created."""
        store = self._store()
        with _locked(self.path), _locked(store.path):
            st = store.load()
            seal = st["seals"]["ledger"]
            if not os.path.lexists(self.path):
                if seal is not None:
                    return  # evaluate denies: "ledger missing after first use"
                _write_state(self.path, {"seq": 0, "used": {}, "history": []})
                st["seals"]["ledger"] = 0
                _write_state(store.path, st)
                seal = 0
            try:
                led = self._load(seal or 0)
            except StoreError:
                return  # evaluate denies with the reason
            if seal is None:
                st["seals"]["ledger"] = led["seq"]
                _write_state(store.path, st)
            self._seen_seq = max(self._seen_seq, led["seq"])

    def _load(self, floor: int = -1) -> dict:
        st = _read_state(self.path, "ledger")
        if set(st) != {"seq", "used", "history"} or not isinstance(st["seq"], int):
            raise StoreError("ledger malformed")
        if st["seq"] < max(self._seen_seq, floor):
            raise StoreError("ledger stale (rolled back or replaced)")
        return st

    @staticmethod
    def key(principal_id, grant_id, tool, unit) -> str:
        return f"{principal_id}|{grant_id}|{tool}|{unit}"

    def admit_and_charge(
        self,
        *,
        cfg: GrantConfig,
        ticket,
        session_key,
        tool: str,
        manifest: str,
        charge: Mapping[str, int],
        approval_nonce: str | None = None,
    ) -> str | None:
        """One critical section for the last admission check and the charge (H5).

        Under the ledger, store, and (if a receipt is used) approval locks: the
        ticket is re-verified against the store as it is now, so a revoke that
        lands after Gate 1 wins; then rate, loop and budget; then the receipt
        nonce is spent only if the call will be charged (H5b); then every file
        and its seal are written. Returns a deny reason, or None after charging.
        """
        store = self._store()
        nonce_path = cfg.approval_nonce_path if approval_nonce is not None else None
        if approval_nonce is not None and nonce_path is None:
            return "approval receipts not configured"
        with _locked(self.path), _locked(store.path):
            try:
                sst = store.load()
            except StoreError as exc:
                return f"ledger unreadable, failing closed: {exc}"
            raw = cfg.clock()
            now = effective_now(raw, sst)
            try:
                # I4 again under the ledger lock: a step back between
                # admission and charge is refused here too.
                _check_clock(raw, sst, cfg.clock_backward_slack)
                g = _verify_ticket(cfg, ticket, session_key)
                _verify_state(g, sst, now)
            except CredentialRefused as exc:
                return str(exc)
            chain = []
            cur = g.grant_id
            while cur is not None:
                rec = sst["lineage"][cur]
                chain.append((rec["principal_id"], cur, rec["budget"]))
                cur = rec["parent_grant_id"]
            try:
                st = self._load(sst["seals"]["ledger"] or 0)
            except StoreError as exc:
                return f"ledger unreadable, failing closed: {exc}"
            why = self._limits(st, chain, tool, manifest, cfg, now, charge)
            if why is not None:
                return why
            if nonce_path is not None:
                with _locked(nonce_path):
                    try:
                        ast_ = _load_approvals(nonce_path, sst["seals"]["approvals"])
                    except StoreError as exc:
                        return f"approval check failed: {exc}"
                    if approval_nonce in ast_["spent"]:
                        return "approval receipt replay"
                    ast_["spent"].append(approval_nonce)
                    ast_["seq"] += 1
                    self._commit(st, chain, tool, manifest, now, charge, cfg)
                    _write_state(nonce_path, ast_)
                    sst["seals"]["approvals"] = ast_["seq"]
            else:
                self._commit(st, chain, tool, manifest, now, charge, cfg)
            sst["seals"]["ledger"] = st["seq"]
            if sst["clock_high"] is None or raw > sst["clock_high"]:
                sst["clock_high"] = raw
            _write_state(store.path, sst)
            return None

    @staticmethod
    def _limits(st, chain, tool, manifest, cfg, now, charge) -> str | None:
        principal = chain[0][0]
        if cfg.rate_limit is not None:
            max_calls, window = cfg.rate_limit
            recent = [h for h in st["history"] if now - h["ts"] < window]
            same_tool = [h for h in recent if h["p"] == principal and h["tool"] == tool]
            if len(same_tool) >= max_calls:
                return f"rate limit: {max_calls} calls of '{tool}' per {window}s for this principal"
            if cfg.loop_limit is not None:
                loops = [
                    h for h in recent if h["p"] == principal and h["m"] == manifest
                ]
                if len(loops) >= cfg.loop_limit:
                    return "loop guard: identical action repeated"
        for _p, gid, budget in chain:
            for unit, cap in budget.items():
                have = sum(
                    v
                    for k, v in st["used"].items()
                    if k.split("|")[1] == gid and k.split("|")[3] == unit
                )
                # Children charge their ancestors, so each level's keys hold
                # its own spend plus every descendant's. A unit this call
                # does not charge is denied once it is already spent.
                want = charge.get(unit, 0)
                if (want and have + want > cap) or (not want and have >= cap):
                    return f"budget: {unit} cap {cap} reached for grant {gid}"
        return None

    def _commit(self, st, chain, tool, manifest, now, charge, cfg) -> None:
        principal = chain[0][0]
        for p, gid, _budget in chain:
            for unit, amount in charge.items():
                k = self.key(p, gid, tool, unit)
                st["used"][k] = st["used"].get(k, 0) + amount
        st["history"].append({"ts": now, "p": principal, "tool": tool, "m": manifest})
        # H7: prune by time, never by count. Every row inside the rate window
        # is kept, so other principals' traffic cannot push this principal's
        # rows out. Rows are only added on a charged call, so the window holds
        # at most max_calls rows per principal and tool.
        if cfg.rate_limit is not None:
            window = cfg.rate_limit[1]
            st["history"] = [h for h in st["history"] if now - h["ts"] < window]
        else:
            st["history"] = []
        st["seq"] += 1
        _write_state(self.path, st)
        self._seen_seq = st["seq"]

    def charge_usage(self, chain, tool: str, usage: Mapping[str, int]) -> None:
        """Post-call usage (tokens, wall seconds, egress bytes) reported by the host.
        Counts against the next pre-call check; it is not itself a control."""
        for unit in usage:
            if unit not in UNITS:
                raise StoreError(f"unknown unit {unit}")
        store = self._store()
        with _locked(self.path), _locked(store.path):
            sst = store.load()
            st = self._load(sst["seals"]["ledger"] or 0)
            for p, gid, _b in chain:
                for unit, amount in usage.items():
                    k = self.key(p, gid, tool, unit)
                    st["used"][k] = st["used"].get(k, 0) + int(amount)
            st["seq"] += 1
            _write_state(self.path, st)
            self._seen_seq = st["seq"]
            sst["seals"]["ledger"] = st["seq"]
            _write_state(store.path, sst)


# --- approval receipts (D4) -----------------------------------------------------


def _load_approvals(path: str, seal: int | None) -> dict:
    """Approval nonce file. Made the first time (no seal yet); after that a
    missing file, or one whose seq is below the store seal, is a DENY (H3b)."""
    if not os.path.lexists(path):
        if seal is not None:
            raise StoreError("approval nonce file missing after first use")
        return {"seq": 0, "spent": []}
    st = _read_state(path, "approval nonce file")
    if (
        set(st) != {"seq", "spent"}
        or not isinstance(st["seq"], int)
        or not isinstance(st["spent"], list)
    ):
        raise StoreError("approval nonce file malformed")
    if seal is not None and st["seq"] < seal:
        raise StoreError("approval nonce file stale (rolled back or replaced)")
    return st


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
    """Made by the out-of-band approval path, never by the agent. ``key`` is the
    approval key (``GrantConfig.approval_key``), not the grant key."""
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


def approval_reason(
    cfg: GrantConfig,
    receipt,
    *,
    manifest: str,
    principal_id: str,
    pol_hash: str,
    now: float,
) -> tuple[str | None, str | None]:
    """(None, nonce) when the receipt is good; (reason, None) otherwise.
    Spends nothing: the nonce is spent in ``Ledger.admit_and_charge`` only when
    the call is charged (H5b)."""
    try:
        if cfg.approval_nonce_path is None:
            return "approval receipts not configured", None
        if cfg.approval_key is None:
            return "approval key not configured", None
        _check_key(cfg.approval_key)
        if (
            not isinstance(receipt, str)
            or receipt.count(".") != 1
            or len(receipt) > 8192
        ):
            return "no bound approval receipt", None
        p64, m64 = receipt.split(".")
        payload, mac = _b64d(p64), _b64d(m64)
        if not hmac.compare_digest(
            mac, _mac(cfg.approval_key, payload, _RECEIPT_DOMAIN)
        ):
            return "approval receipt bad mac", None
        body = json.loads(payload)
        want = {
            "manifest",
            "principal_id",
            "approver",
            "tool",
            "policy_hash",
            "not_after",
            "nonce",
        }
        if not isinstance(body, dict) or set(body) != want:
            return "approval receipt malformed", None
        if body["policy_hash"] != pol_hash:
            return "approval receipt minted under another policy", None
        if body["manifest"] != manifest:
            return "approval receipt bound to another action", None
        if body["principal_id"] != principal_id:
            return "approval receipt for another principal", None
        st = GrantStore(cfg.store_path).load()
        if effective_now(now, st) >= body["not_after"]:
            return "approval receipt expired", None
        approver = body["approver"]
        if approver == principal_id:
            return "approver is the requesting principal", None
        if approver not in cfg.approvers:
            return "approver not a named human approver", None
        if approver in {rec["principal_id"] for rec in st["lineage"].values()}:
            return "approver is an agent principal", None
        nonce = body["nonce"]
        if not isinstance(nonce, str) or not nonce:
            return "approval receipt malformed", None
        return None, nonce
    except CredentialRefused as exc:
        return f"approval receipt refused: {exc}", None
    except Exception as exc:  # fail closed
        return f"approval check failed: {type(exc).__name__}", None


# --- renewal receipts (D3) ------------------------------------------------------


def mint_renewal(
    key: bytes,
    *,
    grant_id: str,
    principal_id: str,
    approver: str,
    ttl: int,
    not_after: int,
    nonce: str | None = None,
) -> str:
    """Made by the out-of-band human path, never by the agent. ``key`` is the
    approval key. Its own domain, so an approval receipt cannot renew."""
    _check_key(key)
    body = {
        "grant_id": grant_id,
        "principal_id": principal_id,
        "approver": approver,
        "ttl": int(ttl),
        "not_after": int(not_after),
        "nonce": nonce or secrets.token_hex(16),
    }
    payload = _canon(body)
    return f"{_b64e(payload)}.{_b64e(_mac(key, payload, _RENEWAL_DOMAIN))}"


def renewal_reason(
    cfg: GrantConfig, receipt, *, grant: Grant, ttl: int, now: float
) -> tuple[str | None, str | None]:
    """(None, nonce) when the renewal receipt is good; (reason, None)
    otherwise. Same approver checks as ``approval_reason``. Spends nothing."""
    try:
        if receipt is None:
            return "renewal needs a human renewal receipt", None
        if cfg.approval_nonce_path is None:
            return "renewal receipts not configured", None
        if cfg.approval_key is None:
            return "approval key not configured", None
        _check_key(cfg.approval_key)
        if (
            not isinstance(receipt, str)
            or receipt.count(".") != 1
            or len(receipt) > 8192
        ):
            return "renewal receipt malformed", None
        p64, m64 = receipt.split(".")
        payload, mac = _b64d(p64), _b64d(m64)
        if not hmac.compare_digest(
            mac, _mac(cfg.approval_key, payload, _RENEWAL_DOMAIN)
        ):
            return "renewal receipt bad mac", None
        body = json.loads(payload)
        want = {"grant_id", "principal_id", "approver", "ttl", "not_after", "nonce"}
        if not isinstance(body, dict) or set(body) != want:
            return "renewal receipt malformed", None
        if body["grant_id"] != grant.grant_id:
            return "renewal receipt for another grant", None
        if body["principal_id"] != grant.principal_id:
            return "renewal receipt for another principal", None
        if body["ttl"] != ttl:
            return "renewal receipt approved another lifetime", None
        st = GrantStore(cfg.store_path).load()
        if effective_now(now, st) >= body["not_after"]:
            return "renewal receipt expired", None
        approver = body["approver"]
        if approver == grant.principal_id:
            return "approver is the requesting principal", None
        if approver not in cfg.approvers:
            return "approver not a named human approver", None
        if approver in {rec["principal_id"] for rec in st["lineage"].values()}:
            return "approver is an agent principal", None
        nonce = body["nonce"]
        if not isinstance(nonce, str) or not nonce:
            return "renewal receipt malformed", None
        return None, nonce
    except CredentialRefused as exc:
        return f"renewal receipt refused: {exc}", None
    except Exception as exc:  # fail closed
        return f"renewal check failed: {type(exc).__name__}", None


def _spend_receipt_nonce(cfg: GrantConfig, nonce: str) -> None:
    """Spend a renewal nonce once, in the approval nonce file, and move the
    store seal with it (H3b). Same lock order as ``Ledger.admit_and_charge``."""
    store = GrantStore(cfg.store_path)
    path = cfg.approval_nonce_path
    with _locked(store.path), _locked(path):
        try:
            sst = store.load()
            ast_ = _load_approvals(path, sst["seals"]["approvals"])
        except StoreError as exc:
            raise CredentialRefused(f"renewal check failed: {exc}") from exc
        if nonce in ast_["spent"]:
            raise CredentialRefused("renewal receipt replay")
        ast_["spent"].append(nonce)
        ast_["seq"] += 1
        _write_state(path, ast_)
        sst["seals"]["approvals"] = ast_["seq"]
        _write_state(store.path, sst)
