"""Offline helpers for paper-facing composition contracts.

These helpers recompute values from source objects. They do not attest that a
live Hermes, atoms, or box path used them.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from typing import Any


def _field(value: Any, name: str) -> Any:
    if isinstance(value, Mapping):
        return value.get(name)
    return getattr(value, name, None)


def _verdict_value(decision: Any) -> Any:
    verdict = _field(decision, "verdict")
    return getattr(verdict, "value", verdict)


def decision_digest(decision: Any) -> str:
    """Recompute the digest shape used by the gate-to-atoms contract."""
    body = json.dumps(
        [
            _verdict_value(decision),
            _field(decision, "skill"),
            _field(decision, "tool"),
            list(_field(decision, "paths") or ()),
            _field(decision, "reason"),
        ]
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def atoms_result_digest(atoms_result: Any) -> str:
    """Recompute the digest shape used by the atoms-to-box contract."""
    body = json.dumps(
        [
            _field(atoms_result, "block_message"),
            _field(atoms_result, "winning_effect"),
            _field(atoms_result, "decision_digest"),
            _field(atoms_result, "box_ticket"),
        ]
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def receipt_digests_match(
    receipt: Mapping[str, Any],
    expected_gate_digest: str,
    expected_atoms_digest: str,
) -> bool:
    """Require receipt digests to equal caller-recomputed values."""
    gate = receipt.get("gate_decision_sha256")
    atoms = receipt.get("atoms_result_sha256")
    if not all(isinstance(value, str) and len(value) == 64 for value in (gate, atoms)):
        return False
    return hmac.compare_digest(gate, expected_gate_digest) and hmac.compare_digest(
        atoms, expected_atoms_digest
    )


def accept_bound_receipt(
    receipt: Mapping[str, Any],
    decision: Any,
    atoms_result: Any,
) -> bool:
    """Accept only digests recomputed from the source decision and atoms result."""
    return receipt_digests_match(
        receipt,
        decision_digest(decision),
        atoms_result_digest(atoms_result),
    )
