#!/usr/bin/env python3
"""Per-recipient token/credit ledger: who spent what, caps, step-back. Fail-closed.

Rules:
* Only a recipient with a cap can spend. Unknown recipient: refused.
* Amount must be a positive int (bool refused). Over cap: refused, nothing written.
* A spend is accepted only for a gate Decision that may_run (enforce ALLOW).
* step_back(ref) reverses one accepted spend, once. Unknown or repeated ref: refused.
* Every accepted row is appended to a sha256 hash chain; verify() recomputes it.
  If the row cannot be written, the spend is refused (no silent credit).
Box-only stub. Not a billing system; no currency, no multi-writer locking.
"""

import hashlib
import json
import os
import sys

GENESIS = "0" * 64


class Refused(Exception):
    pass


class Ledger:
    def __init__(self, path, caps, may_run):
        if not isinstance(caps, dict) or not caps:
            raise Refused("no caps, no ledger")
        for r, c in caps.items():
            if type(c) is not int or c < 0:
                raise Refused(f"bad cap for {r!r}")
        self._path, self._caps, self._may_run = path, dict(caps), may_run
        self._spent = {r: 0 for r in caps}
        self._open = {}  # ref -> (recipient, amount) still reversible
        self._used = set()  # every ref ever spent; refs are single-use
        self._head = GENESIS
        if os.path.exists(path):
            self._replay()

    def _row(self, body):
        body = dict(body, prev=self._head)
        raw = json.dumps(body, sort_keys=True)
        h = hashlib.sha256(raw.encode()).hexdigest()
        try:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"row": body, "hash": h}, sort_keys=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            raise Refused(f"ledger write failed, refusing: {exc!r}") from exc
        self._head = h

    def spend(self, recipient, amount, ref, decision):
        if recipient not in self._caps:
            raise Refused(f"unknown recipient {recipient!r}")
        if type(amount) is not int or amount <= 0:
            raise Refused("amount must be a positive int")
        if (
            not isinstance(ref, str)
            or not ref
            or ref in self._open
            or ref in self._used
        ):
            raise Refused("ref missing or reused")
        if not self._may_run(decision):
            raise Refused("gate did not allow this call; no spend")
        if self._spent[recipient] + amount > self._caps[recipient]:
            raise Refused(f"cap {self._caps[recipient]} exceeded for {recipient!r}")
        self._row({"op": "spend", "recipient": recipient, "amount": amount, "ref": ref})
        self._spent[recipient] += amount
        self._open[ref] = (recipient, amount)
        self._used.add(ref)

    def step_back(self, ref):
        if ref not in self._open:
            raise Refused("nothing to step back for this ref")
        recipient, amount = self._open[ref]
        self._row(
            {"op": "step_back", "recipient": recipient, "amount": amount, "ref": ref}
        )
        self._spent[recipient] -= amount
        self._open.pop(ref)

    def spent(self, recipient):
        return self._spent[recipient]

    def _replay(self):
        for row in self.verify(return_rows=True):
            r = row["recipient"]
            if row["op"] == "spend":
                self._spent[r] += row["amount"]
                self._open[row["ref"]] = (r, row["amount"])
                self._used.add(row["ref"])
            else:
                self._spent[r] -= row["amount"]
                self._open.pop(row["ref"], None)

    def verify(self, return_rows=False):
        head, rows = GENESIS, []
        with open(self._path, encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                rec = json.loads(line)
                body = rec["row"]
                if body.get("prev") != head:
                    raise Refused(f"chain broken at row {n}")
                h = hashlib.sha256(
                    json.dumps(body, sort_keys=True).encode()
                ).hexdigest()
                if h != rec["hash"]:
                    raise Refused(f"row {n} edited")
                head = h
                rows.append(body)
        return rows if return_rows else head


def demo():
    from _cg import SKILL, make_client, sdk

    c, root, work = make_client()
    led = Ledger(
        str(root / "ledger.jsonl"), {"alice-agent": 100, "bob-agent": 10}, sdk.may_run
    )
    ok = c.check(SKILL, "read_file", [f"{work}/a.txt"])
    bad = c.check(SKILL, "shell", [])
    out = []

    def tryit(name, fn):
        try:
            fn()
            out.append((name, "ACCEPTED"))
        except Refused as e:
            out.append((name, f"REFUSED ({str(e)[:50]})"))

    tryit(
        "alice spends 60 on allowed call",
        lambda: led.spend("alice-agent", 60, "r1", ok),
    )
    tryit(
        "alice spends 50 more (cap 100)", lambda: led.spend("alice-agent", 50, "r2", ok)
    )
    tryit("bob spends 5 on denied call", lambda: led.spend("bob-agent", 5, "r3", bad))
    tryit("mallory spends 1 (no cap)", lambda: led.spend("mallory", 1, "r4", ok))
    tryit("alice steps back r1", lambda: led.step_back("r1"))
    tryit("alice steps back r1 again", lambda: led.step_back("r1"))
    tryit(
        "alice spends 50 after step-back",
        lambda: led.spend("alice-agent", 50, "r5", ok),
    )
    for n, r in out:
        print(f"  {r:<60} {n}")
    head = led.verify()
    print(
        f"spent alice={led.spent('alice-agent')} bob={led.spent('bob-agent')} head={head[:16]}"
    )
    want = [
        "ACCEPTED",
        "REFUSED",
        "REFUSED",
        "REFUSED",
        "ACCEPTED",
        "REFUSED",
        "ACCEPTED",
    ]
    good = [r.split()[0] for _, r in out] == want and led.spent("alice-agent") == 50
    print("LEDGER " + ("PASS" if good else "FAIL"))
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(demo())
