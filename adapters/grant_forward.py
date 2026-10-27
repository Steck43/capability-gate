"""Host-owned grant/session/approval forwarding for harness hooks.

Reads GrantConfig and per-call session fields from host-controlled files only.
Never trust model- or tool-supplied principal_id / grant / session_key / approval.
"""

from __future__ import annotations

import json
import os
from typing import Any

import capability_gate_grants as gr


class GrantForwardError(Exception):
    """Host grant config or session is present but unusable (fail closed)."""


def _read_json_object(path: str) -> dict[str, Any]:
    if not os.path.lexists(path):
        raise GrantForwardError(f"missing grant file: {path}")
    # No symlink follow: open after rejecting links.
    if os.path.islink(path):
        raise GrantForwardError(f"grant file must not be a symlink: {path}")
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        # Present-but-unreadable (bad JSON, bad UTF-8, directory, etc.).
        raise GrantForwardError(f"grant file unreadable: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise GrantForwardError(f"grant file root must be an object: {path}")
    return data


def _read_key_file(path: str) -> bytes:
    if not os.path.lexists(path) or os.path.islink(path):
        raise GrantForwardError(f"key file missing or symlink: {path}")
    try:
        with open(path, "rb") as fh:
            key = fh.read()
    except OSError as exc:
        raise GrantForwardError(f"key file unreadable: {path}: {exc}") from exc
    if len(key) < 32:
        raise GrantForwardError("key file must be at least 32 bytes")
    return key


def load_grant_config(
    path: str | None, *, required: bool = False
) -> gr.GrantConfig | None:
    """Load GrantConfig from a host JSON file, or None when path is unset/empty.

    When required=True (caller opted in via env), a missing path or file is
    refuse (GF-L1). When required=False, missing stays legacy None (Hermes
    fixed-path shape).
    """
    if not path:
        if required:
            raise GrantForwardError("grant config path required but unset")
        return None
    path = os.path.abspath(path)
    if not os.path.lexists(path):
        if required:
            raise GrantForwardError(f"missing grant file: {path}")
        return None
    data = _read_json_object(path)
    key_file = data.get("key_file")
    if not isinstance(key_file, str) or not key_file:
        raise GrantForwardError("grant config needs string key_file")
    audience = data.get("audience")
    if not isinstance(audience, str) or not audience:
        raise GrantForwardError("grant config needs string audience")
    store_path = data.get("store_path")
    ledger_path = data.get("ledger_path")
    if not isinstance(store_path, str) or not isinstance(ledger_path, str):
        raise GrantForwardError("grant config needs store_path and ledger_path strings")
    approval_nonce_path = data.get("approval_nonce_path")
    if approval_nonce_path is not None and not isinstance(approval_nonce_path, str):
        raise GrantForwardError("approval_nonce_path must be a string or null")
    approvers_raw = data.get("approvers") or []
    if not isinstance(approvers_raw, list):
        raise GrantForwardError("approvers must be a list")
    approval_key_file = data.get("approval_key_file")
    approval_key = None
    if isinstance(approval_key_file, str) and approval_key_file:
        approval_key = _read_key_file(approval_key_file)
    key = _read_key_file(key_file)
    return gr.GrantConfig(
        key=key,
        audience=audience,
        store_path=os.path.abspath(store_path),
        ledger_path=os.path.abspath(ledger_path),
        approval_nonce_path=(
            os.path.abspath(approval_nonce_path) if approval_nonce_path else None
        ),
        approvers=frozenset(str(a) for a in approvers_raw),
        key_paths=tuple(
            os.path.abspath(p)
            for p in (key_file, approval_key_file)
            if isinstance(p, str) and p
        ),
        approval_key=approval_key,
    )


def load_call_kwargs(path: str | None, *, required: bool = False) -> dict[str, Any]:
    """Return evaluate kwargs from a host session file.

    Empty dict when path unset or file missing (legacy call shape).
    When required=True (caller opted in via env), missing path/file refuses
    (GF-L1). Raises GrantForwardError when the file exists but is invalid.
    """
    if not path:
        if required:
            raise GrantForwardError("grant session path required but unset")
        return {}
    path = os.path.abspath(path)
    if not os.path.lexists(path):
        if required:
            raise GrantForwardError(f"missing session file: {path}")
        return {}
    data = _read_json_object(path)
    out: dict[str, Any] = {}
    for key in ("principal_id", "grant", "session_key"):
        val = data.get(key)
        if val is None:
            continue
        if not isinstance(val, str) or not val:
            raise GrantForwardError(f"session.{key} must be a non-empty string")
        out[key] = val
    approval = data.get("approval")
    if approval is not None:
        if not isinstance(approval, str) or not approval:
            raise GrantForwardError("session.approval must be a non-empty string")
        out["approval"] = approval
    if out and not {"principal_id", "grant", "session_key"} <= set(out):
        raise GrantForwardError(
            "session needs principal_id, grant, and session_key together"
        )
    return out


def hermes_paths(hermes_home: str) -> tuple[str, str]:
    """Default host paths under HERMES_HOME (no new env reads)."""
    base = os.path.join(hermes_home, "capability-gate")
    return (
        os.path.join(base, "grants.json"),
        os.path.join(base, "session.json"),
    )
