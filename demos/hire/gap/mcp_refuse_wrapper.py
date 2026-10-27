#!/usr/bin/env python3
"""MCP-shaped refuse-before-model wrapper (box simulation of the RT-B pattern).

A JSON-RPC 2.0 ``tools/call`` request goes through the gate first. If may_run
is False, the backend tool is never invoked and the model gets an
``isError: true`` result that says refused. Malformed requests, a gate error,
or a backend exception all return isError (fail-closed); none returns success.
Honest limit: simulated JSON-RPC in one process, not a live MCP server or a
live harness; says nothing about a host that skips the wrapper.
"""

import json
import sys

from _cg import SKILL, make_client, sdk


class Wrapper:
    def __init__(self, client, backend, skill=SKILL):
        self.client, self.backend, self.skill = client, backend, skill
        self.backend_calls = 0

    def _err(self, rid, text):
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "result": {"isError": True, "content": [{"type": "text", "text": text}]},
        }

    def handle(self, raw):
        try:
            req = json.loads(raw)
            rid = req.get("id")
            if req.get("jsonrpc") != "2.0" or req.get("method") != "tools/call":
                return self._err(rid, "refused: not a tools/call request")
            params = req["params"]
            name, args = params["name"], params.get("arguments") or {}
            if not isinstance(name, str) or not isinstance(args, dict):
                return self._err(rid, "refused: malformed call")
            paths = [args["path"]] if isinstance(args.get("path"), str) else []
        except Exception:
            return self._err(None, "refused: unparseable request")
        try:
            d = self.client.check(self.skill, name, paths, args=args)
        except Exception as exc:  # contract: treat as deny
            return self._err(rid, f"refused: gate error {exc!r}")
        if not sdk.may_run(d):
            return self._err(
                rid, f"refused by gate: {d.verdict.value}: {d.reason[:80]}"
            )
        try:
            self.backend_calls += 1
            out = self.backend(name, args)
        except Exception as exc:
            return self._err(rid, f"tool failed: {exc!r}")
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "result": {
                "isError": False,
                "content": [{"type": "text", "text": str(out)}],
            },
        }


def demo():
    c, _root, work = make_client()
    (work / "a.txt").write_text("hello")
    effects = []

    def backend(name, args):
        # Records the effect only; never touches a real path, so a mutant run is harmless.
        effects.append((name, args.get("path")))
        return "hello" if name == "read_file" else "ran " + name

    w = Wrapper(c, backend)

    def call(i, name, args):
        return json.dumps(
            {
                "jsonrpc": "2.0",
                "id": i,
                "method": "tools/call",
                "params": {"name": name, "arguments": args},
            }
        )

    cases = [
        ("allowed read", call(1, "read_file", {"path": str(work / "a.txt")}), False),
        (
            "write /etc/passwd",
            call(2, "write_file", {"path": "/etc/passwd", "text": "x"}),
            True,
        ),
        ("unlisted shell", call(3, "shell", {"cmd": "id"}), True),
        ("garbage json", "{not json", True),
        (
            "wrong method",
            json.dumps({"jsonrpc": "2.0", "id": 5, "method": "tools/list"}),
            True,
        ),
    ]
    ok = True
    for label, raw, want_err in cases:
        before = w.backend_calls
        resp = w.handle(raw)
        is_err = resp["result"]["isError"]
        invoked = w.backend_calls - before
        good = is_err == want_err and (invoked == 0 if want_err else invoked == 1)
        ok &= good
        print(
            f"  {'PASS' if good else 'FAIL'}  {label:<20} isError={is_err} backend_invoked={invoked} :: {resp['result']['content'][0]['text'][:60]}"
        )
    c.throw("mcp drill")
    resp = w.handle(call(6, "read_file", {"path": str(work / "a.txt")}))
    good = resp["result"]["isError"] and w.backend_calls == 1
    ok &= good
    print(
        f"  {'PASS' if good else 'FAIL'}  after kill switch      isError={resp['result']['isError']} backend_calls_total={w.backend_calls}"
    )
    print("MCP-REFUSE " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(demo())
