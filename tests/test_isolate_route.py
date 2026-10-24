"""Isolate verdict and the route to the box door (P0 item 5, T1 to T11).

Each test names the failure class it guards. The door here is a small script
written into the test's own folder: it reads one task on stdin and prints one
receipt, so every route error can be planted without a VM. The stub door in
isolation-layer (sandbox-demo route) speaks the same task and receipt shapes;
the S14 demo runs that door end to end.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import json
import os
import shutil
import signal
import stat
import sys
import textwrap
import time
from pathlib import Path

import pytest
import yaml

import capability_gate as cg

ROOT = Path(__file__).resolve().parents[1]

PLUGIN_FILES = ("__init__.py", "capability_gate.py", "adapters/isolate_route.py")


def _policy(extra: dict | None = None) -> dict:
    body = {
        "skills": {
            # The plugin judges a call with no skill field as UNLABELED.
            "UNLABELED": {
                "tools": ["read_file", "write_file", "execute_code", "terminal"],
                "paths": ["$HERMES_HOME/work/**"],
            }
        },
        "isolate": ["execute_code"],
    }
    body.update(extra or {})
    return body


# --- T1, T2: the decider ----------------------------------------------------


def test_isolate_verdict_for_listed_tool(tmp_path, monkeypatch):
    """Class: a tool the policy lists for isolation is allowed to run on the host."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    policy = cg.load_policy(_policy())
    d = cg._decide(policy, "UNLABELED", "execute_code", [])
    assert d.verdict.value == "isolate", d
    # A tool outside the list keeps its old verdict.
    assert cg._decide(policy, "UNLABELED", "terminal", []).verdict.value == "allow"


def test_isolate_and_approval_lists_must_not_overlap(tmp_path, monkeypatch):
    """Class: one tool in both lists gets whichever branch happens to run ahead."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    with pytest.raises(cg.PolicyError):
        cg.load_policy(_policy({"require_approval": ["execute_code"]}))
    with pytest.raises(cg.PolicyError):
        cg.load_policy(_policy({"isolate": "execute_code"}))


@pytest.mark.parametrize(
    "rel",
    ["work/.env", "work/.aegis/key", "outside/x.txt", "work/../outside/x.txt"],
)
def test_path_deny_beats_isolate(tmp_path, monkeypatch, rel):
    """Class: an isolate tool skips the path deny checks and a bad path reaches the box."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    (tmp_path / "work").mkdir()
    policy = cg.load_policy(_policy({"isolate": ["write_file"]}))
    d = cg._decide(policy, "UNLABELED", "write_file", [str(tmp_path / rel)])
    assert d.verdict.value == "deny", d
    ok = cg._decide(
        policy, "UNLABELED", "write_file", [str(tmp_path / "work" / "a.txt")]
    )
    assert ok.verdict.value == "isolate", ok


def test_isolate_row_carries_a_route_ticket(tmp_path, monkeypatch):
    """Class: a routed call has no ticket on the record, so a receipt cannot be tied to it."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    log = tmp_path / "logs" / "g.jsonl"
    gate = cg.Gate(cg.load_policy(_policy()), log_path=str(log), mode="enforce")
    d = gate.evaluate("UNLABELED", "execute_code", [])
    assert d.verdict.value == "isolate"
    assert isinstance(d.route_ticket, str) and len(d.route_ticket) == 32
    row = json.loads(log.read_text().splitlines()[-1])
    assert row["verdict"] == "isolate" and row["route_ticket"] == d.route_ticket
    d2 = gate.evaluate("UNLABELED", "execute_code", [])
    assert d2.route_ticket != d.route_ticket
    # Rows for other verdicts keep their old shape.
    gate.evaluate("UNLABELED", "terminal", [])
    assert "route_ticket" not in json.loads(log.read_text().splitlines()[-1])


# --- plugin sandbox ---------------------------------------------------------


GOOD_DOOR = r"""
import hashlib, json, sys
task = json.loads(sys.stdin.read())
fields = {k: task[k] for k in ("schema", "route_ticket", "tool_call_id", "tool", "skill", "args", "gate_decision_sha256")}
canon = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
receipt = {
    "schema": "isolate-route-receipt/1",
    "route_ticket": task["route_ticket"],
    "tool_call_id": task["tool_call_id"],
    "task_sha256": hashlib.sha256(canon.encode()).hexdigest(),
    "gate_decision_sha256": task["gate_decision_sha256"],
    "jail_id": "stub-test-1",
    "disposition": "advance",
    "reason": "clear",
    "result_sha256": hashlib.sha256(b"box result").hexdigest(),
    "teardown_clean": True,
    "hygiene_ok": True,
    "chain_tip": "0" * 64,
    "real": False,
    "mode": "STUBBED",
}
PATCH
print(json.dumps(receipt))
"""


class Sandbox:
    def __init__(
        self,
        tmp: Path,
        monkeypatch,
        *,
        mode="enforce",
        door_patch="",
        route=True,
        policy=None,
    ):
        self.tmp = tmp
        self.home = tmp / "hermes"
        (self.home / "logs").mkdir(parents=True)
        (self.home / "work").mkdir()
        monkeypatch.setenv("HERMES_HOME", str(self.home))
        self.plugin = tmp / "plugins" / "capability_gate"
        (self.plugin / "adapters").mkdir(parents=True)
        for rel in PLUGIN_FILES:
            src = ROOT / rel
            if src.is_file():
                shutil.copyfile(src, self.plugin / rel)
        (self.plugin / "allowlist.yaml").write_text(yaml.safe_dump(policy or _policy()))
        self.calls = tmp / "door-calls.jsonl"
        self.door = tmp / "bin" / "door"
        self.door.parent.mkdir()
        self.write_door(door_patch)
        if route:
            self.write_route({"door": [str(self.door)], "real": False})
        self.set_mode(mode)
        self.mod = self._load()
        self.hook = self._hook()

    def write_door(self, patch: str, body: str | None = None):
        record = f"open({str(self.calls)!r}, 'a').write(json.dumps(task) + '\\n')\n"
        text = (
            body
            if body is not None
            else GOOD_DOOR.replace("PATCH", textwrap.dedent(patch))
        )
        if "task = json.loads" in text:
            text = text.replace(
                "task = json.loads(sys.stdin.read())\n",
                "task = json.loads(sys.stdin.read())\n" + record,
                1,
            )
        self.door.write_text(f"#!{sys.executable}\n{text}")
        self.door.chmod(0o700)

    def write_route(self, body: dict):
        (self.plugin / "isolate_route.yaml").write_text(yaml.safe_dump(body))

    def set_mode(self, mode: str):
        cfg = {
            "plugins": {
                "enabled": ["capability-gate"],
                "entries": {"capability-gate": {"mode": mode}},
            }
        }
        (self.home / "config.yaml").write_text(yaml.safe_dump(cfg))

    def _load(self):
        name = f"cg_iso_{abs(hash(str(self.plugin)))}"
        spec = importlib.util.spec_from_file_location(
            name,
            self.plugin / "__init__.py",
            submodule_search_locations=[str(self.plugin)],
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        return mod

    def _hook(self):
        hooks = {}

        class Ctx:
            def register_hook(self, n, fn):
                hooks[n] = fn

        self.mod.register(Ctx())
        return hooks["pre_tool_call"]

    def call(self, tool="execute_code", args=None, call_id="call-1"):
        return self.hook(
            tool,
            args if args is not None else {"code": "print(1)"},
            "task-1",
            tool_call_id=call_id,
        )

    def door_calls(self):
        if not self.calls.exists():
            return []
        return [json.loads(x) for x in self.calls.read_text().splitlines() if x.strip()]

    def rows(self):
        p = self.home / "logs" / "capability-gate.jsonl"
        return (
            [json.loads(x) for x in p.read_text().splitlines() if x.strip()]
            if p.exists()
            else []
        )


def _blocked(res) -> str:
    assert isinstance(res, dict) and res.get("action") == "block", res
    return res["message"]


# --- T3, T4: enforce blocks the host and routes ------------------------------


def test_isolate_blocks_host_in_enforce(tmp_path, monkeypatch):
    """Class: an isolate verdict lets the host executor run the call."""
    sb = Sandbox(tmp_path, monkeypatch)
    host_runs = 0
    for i in range(3):
        res = sb.call(call_id=f"c{i}")
        if res is None:
            host_runs += 1
        else:
            _blocked(res)
    assert host_runs == 0
    assert (
        sb.call(tool="terminal", args={"command": "true"}) is None
    )  # others unchanged


def test_isolate_routes_to_door(tmp_path, monkeypatch):
    """Class: the call is blocked but never reaches the box, so its work is lost silently."""
    sb = Sandbox(tmp_path, monkeypatch)
    msg = _blocked(sb.call(call_id="call-77"))
    calls = sb.door_calls()
    assert len(calls) == 1
    task = calls[0]
    assert task["tool_call_id"] == "call-77" and task["tool"] == "execute_code"
    assert task["args"] == {"code": "print(1)"}
    rows = sb.rows()
    iso = [r for r in rows if r["verdict"] == "isolate"]
    assert len(iso) == 1 and iso[0]["route_ticket"] == task["route_ticket"]
    canon = json.dumps(
        {
            k: v
            for k, v in iso[0].items()
            if k
            in (
                "verdict",
                "reason",
                "skill",
                "tool",
                "paths",
                "enforced",
                "route_ticket",
            )
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    assert task["gate_decision_sha256"] == hashlib.sha256(canon.encode()).hexdigest()
    result = hashlib.sha256(b"box result").hexdigest()
    assert msg == f"isolated: advance {result}"
    assert rows[-1]["verdict"] == "deny" and rows[-1]["reason"] == msg
    assert rows[-1]["route_ticket"] == task["route_ticket"]


# --- T5: every route error blocks --------------------------------------------

ERRORS = {
    "no_route_config": ("isolate route unavailable", None),
    "door_missing": ("isolate route unavailable", None),
    "door_group_writable": ("isolate route unavailable", None),
    "door_symlink": ("isolate route unavailable", None),
    "door_not_executable": ("isolate route unreachable", None),
    "timeout": ("isolate route timed out", "import time; time.sleep(30)"),
    "exit_nonzero": ("isolate route failed: exit 3", "sys.exit(3)"),
    "no_json": ("isolate route failed: no receipt", "print('hello'); sys.exit(0)"),
    "bad_schema": ("isolate receipt rejected", "receipt['schema'] = 'other/1'"),
    "wrong_call_id": (
        "isolate receipt rejected",
        "receipt['tool_call_id'] = 'call-other'",
    ),
    "wrong_gate_digest": (
        "isolate receipt rejected",
        "receipt['gate_decision_sha256'] = 'a' * 64",
    ),
    "wrong_task_digest": (
        "isolate receipt rejected",
        "receipt['task_sha256'] = 'b' * 64",
    ),
    "wrong_ticket": ("isolate receipt rejected", "receipt['route_ticket'] = 'c' * 32"),
    "real_flag_lie": ("isolate receipt rejected", "receipt['real'] = True"),
    "vestibule_rejected": (
        "isolate result rejected by vestibule",
        "receipt['disposition'] = 'rejected'; receipt['reason'] = 'body exceeds MAX_BODY_BYTES'",
    ),
    "held": ("isolate result held", "receipt['disposition'] = 'hold'"),
    "dropped": ("isolate result dropped", "receipt['disposition'] = 'drop'"),
    "unknown_disposition": (
        "isolate receipt rejected",
        "receipt['disposition'] = 'clear'",
    ),
    "teardown_not_clean": (
        "isolate teardown not clean",
        "receipt['teardown_clean'] = False",
    ),
    "hygiene_not_clean": (
        "isolate teardown not clean",
        "receipt['hygiene_ok'] = False",
    ),
}


@pytest.mark.parametrize("case", sorted(ERRORS))
def test_each_route_error_blocks(tmp_path, monkeypatch, case):
    """Class: a route error is mapped to a pass, and the call runs on the host or reports success."""
    want, patch = ERRORS[case]
    sb = Sandbox(
        tmp_path, monkeypatch, door_patch=patch or "", route=case != "no_route_config"
    )
    if case == "door_missing":
        sb.door.unlink()
    elif case == "door_group_writable":
        sb.door.chmod(0o770)
    elif case == "door_symlink":
        real = sb.door.with_name("door-real")
        sb.door.rename(real)
        sb.door.symlink_to(real)
    elif case == "door_not_executable":
        sb.door.chmod(0o600)
    if case == "timeout":
        sb.write_route({"door": [str(sb.door)], "real": False, "deadline_s": 1})
    msg = _blocked(sb.call())
    assert msg.startswith(want), (case, msg)
    assert not msg.startswith("isolated: advance")
    last = sb.rows()[-1]
    assert last["verdict"] == "deny" and last["reason"] == msg


def test_task_over_the_cap_is_refused_before_launch(tmp_path, monkeypatch):
    """Class: an oversized task is handed to the door, which is then the one bound left."""
    sb = Sandbox(tmp_path, monkeypatch)
    msg = _blocked(sb.call(args={"code": "x" * (70 * 1024)}))
    assert msg.startswith("isolate route refused: task over")
    assert sb.door_calls() == []


def test_route_module_import_failure_blocks(tmp_path, monkeypatch):
    """Class: a broken route module turns the isolate branch into a host run."""
    sb = Sandbox(tmp_path, monkeypatch)
    (sb.plugin / "adapters" / "isolate_route.py").write_text(
        "raise ImportError('planted')\n"
    )
    msg = _blocked(sb.call())
    assert "failing closed" in msg
    sb.set_mode("observe")
    msg = _blocked(sb.call())
    assert "failing closed" in msg or msg.startswith("isolate route")


# --- T6: single use across calls -----------------------------------------------


def test_receipt_single_use_across_calls(tmp_path, monkeypatch):
    """Class: a receipt accepted once is accepted again on a later call, because the
    replay set lives for one call and no longer (box_entry.py:274 pattern)."""
    sb = Sandbox(tmp_path, monkeypatch)
    _blocked(sb.call(call_id="c1"))
    task = sb.door_calls()[0]
    earlier = sb.door.parent / "earlier-receipt.json"
    # A door that answers every later call with the receipt it saved from the
    # earlier one, rebound to the new call id and digests except the ticket.
    sb.write_door(
        f"""
        import pathlib
        saved = pathlib.Path({str(earlier)!r})
        if not saved.exists():
            saved.write_text(json.dumps(receipt))
        else:
            old = json.loads(saved.read_text())
            receipt['route_ticket'] = old['route_ticket']
        """
    )
    router = sb.mod._isolate_route()
    store = router.TicketStore(sb.mod._log_path())
    # The ticket from the earlier call is already spent in the persisted store.
    assert store.consume(task["route_ticket"]) is False
    # A fresh store object over the same file still refuses it.
    assert router.TicketStore(sb.mod._log_path()).consume(task["route_ticket"]) is False
    assert router.TicketStore(sb.mod._log_path()).consume("f" * 32) is True
    # A later call fed an old ticket is refused.
    _blocked(sb.call(call_id="c2"))
    msg = _blocked(sb.call(call_id="c3"))
    assert msg.startswith("isolate receipt rejected"), msg


def test_verify_refuses_a_replayed_receipt(tmp_path, monkeypatch):
    """Class: the receipt check accepts the same bound receipt twice."""
    sb = Sandbox(tmp_path, monkeypatch)
    _blocked(sb.call(call_id="c1"))
    router = sb.mod._isolate_route()
    calls = sb.door_calls()
    task = calls[0]
    import subprocess

    out = subprocess.run(
        [str(sb.door)],
        input=json.dumps(task),
        capture_output=True,
        text=True,
        check=True,
    )
    receipt = json.loads(out.stdout.strip().splitlines()[-1])
    store = router.TicketStore(str(tmp_path / "fresh.jsonl"))
    cfg = router.RouteConfig(door=(str(sb.door),), real=False, deadline_s=30.0)
    earlier = router.verify_receipt(task, receipt, cfg, store)
    second = router.verify_receipt(
        task, receipt, cfg, router.TicketStore(str(tmp_path / "fresh.jsonl"))
    )
    assert earlier.ok, earlier
    assert not second.ok and second.message.startswith("isolate receipt replayed"), (
        second
    )


def test_forged_contract_receipt_is_refused(tmp_path, monkeypatch):
    """Class: a receipt with every flag true but no binding to this call passes (RT8)."""
    sb = Sandbox(
        tmp_path,
        monkeypatch,
        door_patch="""
        receipt = {"receipt_id": "r1", "jail_id": "mgr-contract-1", "mode": "jailed-via-helper",
                   "vsock_roundtrip_ok": True, "vestibule_framed_ok": True, "dropbox_handoff_ok": True,
                   "inspector_stage_ok": True, "inspector_vm_ok": True, "inspector_verdict_ok": True,
                   "dropbox_hash": "e" * 64, "tool_call_id": task["tool_call_id"]}
        """,
    )
    msg = _blocked(sb.call())
    assert msg.startswith("isolate receipt rejected"), msg


# --- T7: kill switch during the route ---------------------------------------


def test_kill_switch_during_route_discards_result(tmp_path, monkeypatch):
    """Class: a result that comes back after the kill switch was thrown is still delivered."""
    sb = Sandbox(tmp_path, monkeypatch)
    halt = Path(cg.halt_marker_path(sb.mod._log_path()))
    sb.write_door(f"""
        import pathlib
        p = pathlib.Path({str(halt)!r})
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('halt')
        """)
    msg = _blocked(sb.call())
    assert msg.startswith("kill switch thrown during isolate"), msg
    assert "advance" not in msg
    halt.unlink()


def test_log_folder_removed_during_route_blocks(tmp_path, monkeypatch):
    """Class: the gate's own record disappears mid route and the result is still delivered (RT18)."""
    sb = Sandbox(tmp_path, monkeypatch)
    sb.write_door(f"""
        import shutil
        shutil.rmtree({str(sb.home / "logs")!r})
        """)
    msg = _blocked(sb.call())
    assert not msg.startswith("isolated: advance"), msg


def test_mode_flip_during_route_still_blocks(tmp_path, monkeypatch):
    """Class: config flipped to observe while the task is in the box lets the host run it (RT2)."""
    sb = Sandbox(tmp_path, monkeypatch)
    cfg = sb.home / "config.yaml"
    body = {
        "plugins": {
            "enabled": ["capability-gate"],
            "entries": {"capability-gate": {"mode": "observe"}},
        }
    }
    sb.write_door(f"""
        import pathlib
        pathlib.Path({str(cfg)!r}).write_text({json.dumps(yaml.safe_dump(body))})
        """)
    msg = _blocked(sb.call())
    assert "mode changed during isolate" in msg, msg


# --- T8, T9: observe semantics and load failure ------------------------------


def test_observe_isolate_semantics(tmp_path, monkeypatch):
    """Class: observe mode routes to the box, or blocks, where S12 says it just records (D4)."""
    sb = Sandbox(tmp_path, monkeypatch, mode="observe")
    assert sb.call() is None  # runs on the host
    assert sb.door_calls() == []
    rows = sb.rows()
    assert rows[-1]["verdict"] == "isolate" and rows[-1]["enforced"] is False
    assert "route_ticket" not in rows[-1]


D5_ALLOWLISTS = {
    "route_yaml_only": (
        True,
        "skills: {'*': {tools: [execute_code], paths: []}}\nbroken: [\n",
    ),
    "allowlist_block": (
        False,
        (
            "skills: {'*': {tools: [execute_code], paths: []}}\n"
            "isolate: [execute_code]\nbroken: [\n"
        ),
    ),
    "allowlist_flow": (
        False,
        (
            '{"isolate": ["execute_code"], '
            '"skills": {"*": {"tools": ["execute_code"], "paths": 7}}}\n'
        ),
    ),
    "allowlist_bom": (False, "\ufeffisolate: [execute_code]\nskills: 7\n"),
}


@pytest.mark.parametrize("signal", sorted(D5_ALLOWLISTS))
@pytest.mark.parametrize("mode", ["enforce", "observe"])
def test_gate_load_failure_with_isolate_configured(tmp_path, monkeypatch, mode, signal):
    """Class: a gate that fails to load lets an isolate tool run on the host in observe (D5).

    Each signal is set alone, so dropping either half of the detector fails a case.
    """
    route, text = D5_ALLOWLISTS[signal]
    sb = Sandbox(tmp_path, monkeypatch, mode=mode, route=route)
    (sb.plugin / "allowlist.yaml").write_text(text, encoding="utf-8")
    hook = sb._hook()
    res = hook("execute_code", {"code": "1"}, "t", tool_call_id="c")
    assert _blocked(res)
    res = hook("terminal", {"command": "true"}, "t", tool_call_id="c")
    assert _blocked(res)


def test_gate_load_failure_without_isolate_keeps_observe_passthrough(
    tmp_path, monkeypatch
):
    """Control: D5 changes just the isolate case; observe passthrough on load failure stays."""
    sb = Sandbox(tmp_path, monkeypatch, mode="observe", route=False)
    (sb.plugin / "allowlist.yaml").write_text(
        "skills: {'*': {tools: [terminal]}}\nbroken: [\n"
    )
    hook = sb._hook()
    assert hook("terminal", {"command": "true"}, "t", tool_call_id="c") is None


@pytest.mark.parametrize("mode", ["enforce", "observe"])
def test_misspelled_isolate_key_blocks(tmp_path, monkeypatch, mode):
    """Class: a misspelled isolate key loads as no isolate list, so the tool runs on the host (N7)."""
    policy = _policy()
    policy["isloate"] = policy.pop("isolate")
    sb = Sandbox(tmp_path, monkeypatch, mode=mode, policy=policy)
    msg = _blocked(sb.call())
    assert "unknown top-level allowlist keys: isloate" in msg, msg
    assert sb.door_calls() == []


def test_unknown_policy_keys_are_refused():
    """Class: the loader ignores a top-level key it does not know (N7)."""
    with pytest.raises(
        cg.PolicyError, match="unknown top-level allowlist keys: isloate"
    ):
        cg.load_policy({"skills": {}, "isloate": ["execute_code"]})
    # Control: the top-level keys the shipped examples use are all known.
    for rel in (
        "allowlist.example.yaml",
        "adapters/claude_code_allowlist.example.yaml",
    ):
        keys = set(cg.load_yaml_mapping((ROOT / rel).read_text()))
        assert keys and keys <= cg.POLICY_KEYS, (rel, keys)
    cg.load_policy({"version": 1, "skills": {}, "require_approval": [], "isolate": []})


# --- RT14, RT17: door path and flood -----------------------------------------


def test_door_in_a_writable_folder_is_refused(tmp_path, monkeypatch):
    """Class: a door reached through a folder others can write is swappable (RT14)."""
    sb = Sandbox(tmp_path, monkeypatch)
    sb.door.parent.chmod(0o777)
    try:
        msg = _blocked(sb.call())
    finally:
        sb.door.parent.chmod(0o755)
    assert msg.startswith("isolate route unavailable"), msg
    assert sb.door_calls() == []


def _reap(pid: int) -> None:
    """Kill a leftover door child so a failed run does not leave it sleeping."""
    with contextlib.suppress(OSError):
        os.kill(pid, signal.SIGKILL)


def _gone(pid: int, wait_s: float = 2.0) -> bool:
    """Whether pid has exited (a zombie waiting for its reaper counts)."""
    end = time.monotonic() + wait_s
    while True:
        try:
            state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        except (OSError, IndexError):
            return True
        if state == "Z":
            return True
        if time.monotonic() > end:
            return False
        time.sleep(0.05)


@pytest.mark.skipif(not Path("/proc/self/stat").exists(), reason="reads /proc")
def test_timed_out_door_takes_its_children_with_it(tmp_path, monkeypatch):
    """Class: a door that times out leaves a child running after the route returns (gate N3)."""
    pidfile = tmp_path / "grandchild.pid"
    sb = Sandbox(tmp_path, monkeypatch)
    sb.write_door(
        "",
        body=(
            "import subprocess, sys, time\n"
            "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            f"open({str(pidfile)!r}, 'w').write(str(p.pid))\n"
            "time.sleep(60)\n"
        ),
    )
    sb.write_route({"door": [str(sb.door)], "real": False, "deadline_s": 1})
    t0 = time.monotonic()
    msg = _blocked(sb.call())
    took = time.monotonic() - t0
    assert msg.startswith("isolate route timed out"), msg
    pid = int(pidfile.read_text())
    try:
        assert _gone(pid), f"door child {pid} still running after the timeout"
    finally:
        _reap(pid)
    assert took < 4, took


def test_door_script_in_a_writable_folder_is_refused(tmp_path, monkeypatch):
    """Class: an interpreter door runs a script from a folder others can write (gate N4)."""
    sb = Sandbox(tmp_path, monkeypatch)
    folder = tmp_path / "scripts"
    folder.mkdir()
    script = folder / "door.py"
    script.write_text(sb.door.read_text())
    script.chmod(0o600)
    interpreter = os.path.realpath(sys.executable)
    sb.write_route({"door": [interpreter, str(script)], "real": False})
    folder.chmod(0o777)
    try:
        msg = _blocked(sb.call())
    finally:
        folder.chmod(0o755)
    assert msg.startswith("isolate route unavailable: door argument 1 folder"), msg
    assert sb.door_calls() == []
    # Control: the same script from a folder only this user can write runs.
    ok = _blocked(sb.call(call_id="call-2"))
    assert ok.startswith("isolated: advance"), ok
    for arg in ("rel/door.py", "--script=/tmp/door.py"):
        sb.write_route({"door": [interpreter, arg], "real": False})
        msg = _blocked(sb.call(call_id=f"call-{arg}"))
        assert msg.startswith("isolate route unavailable: door argument 1"), msg


def test_one_route_at_a_time(tmp_path, monkeypatch):
    """Class: a flood of isolate calls runs routes in parallel or spills onto the host (RT17)."""
    sb = Sandbox(tmp_path, monkeypatch)
    router = sb.mod._isolate_route()
    with router.route_slot(sb.mod._log_path()) as held:
        assert held
        msg = _blocked(sb.call())
    assert msg.startswith("isolate route busy"), msg
    assert sb.door_calls() == []
    assert _blocked(sb.call()).startswith("isolated: advance")


# --- D8: Claude Code queue and deny -------------------------------------------


def _cc(event: dict, env: dict):
    import subprocess

    return subprocess.run(
        [sys.executable, str(ROOT / "adapters" / "claude_code_hook.py")],
        input=json.dumps(event),
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        check=False,
    )


def test_claude_code_isolate_queues_and_denies(tmp_path):
    """Class: the Claude Code hook waits on a VM past its deadline, or lets the call run (D8)."""
    work = tmp_path / "work"
    work.mkdir()
    allow = tmp_path / "cc.yaml"
    allow.write_text(
        yaml.safe_dump(
            {
                "skills": {
                    "UNLABELED": {"tools": ["Write"], "paths": [str(work / "**")]}
                },
                "isolate": ["Write"],
            }
        )
    )
    spool = tmp_path / "spool"
    spool.mkdir(mode=0o700)
    env = {k: v for k, v in os.environ.items() if not k.startswith("CG_CC_")}
    env.update(
        CG_CC_ALLOWLIST=str(allow),
        CG_CC_LOG=str(tmp_path / "logs" / "cc.jsonl"),
        CG_CC_ISOLATE_SPOOL=str(spool),
    )
    event = {
        "tool_name": "Write",
        "tool_input": {"file_path": str(work / "a.txt"), "content": "x"},
        "tool_use_id": "tu-1",
        "session_id": "s",
        "cwd": str(work),
    }
    p = _cc(event, env)
    assert p.returncode == 2, (p.returncode, p.stderr)
    msg = p.stderr.strip().removeprefix("capability-gate: ")
    assert msg.startswith("isolated: queued "), p.stderr
    ticket = msg.split()[-1]
    queued = list(spool.iterdir())
    assert [q.name for q in queued] == [f"{ticket}.json"]
    assert stat.S_IMODE(queued[0].stat().st_mode) == 0o600
    task = json.loads(queued[0].read_text())
    assert task["route_ticket"] == ticket and task["tool_call_id"] == "tu-1"
    assert not (work / "a.txt").exists()
    # No spool configured: still a denial, never a host run.
    del env["CG_CC_ISOLATE_SPOOL"]
    p = _cc({**event, "tool_use_id": "tu-2"}, env)
    assert p.returncode == 2 and "isolate route unavailable" in p.stderr, p.stderr
    # A spool others can read is refused.
    spool.chmod(0o755)
    env["CG_CC_ISOLATE_SPOOL"] = str(spool)
    p = _cc({**event, "tool_use_id": "tu-3"}, env)
    assert p.returncode == 2 and "isolate route unavailable" in p.stderr, p.stderr
    assert len(list(spool.iterdir())) == 1


# --- T10: the route module is the sole box caller -----------------------------

_BOX_WORDS = (
    "firecracker",
    "jailer",
    "isolation_layer",
    "isolation-layer",
    "microvm",
    "vsock",
    "sandbox-demo",
    "isolation-manager",
    "subprocess",
)


def _shipped_python():
    skip = {
        "tests",
        "demos",
        "scripts",
        "harness",
        "design",
        "tools",
        ".tmp",
        "out",
        "dist",
    }
    for p in sorted(ROOT.rglob("*.py")):
        rel = p.relative_to(ROOT)
        if (
            rel.parts[0] in skip
            or rel.parts[0].startswith(".")
            or rel.name.startswith("test_")
        ):
            continue
        yield rel


def test_route_is_the_sole_box_caller():
    """Class: a second module starts a door process, so the checks in the route module can be skipped."""
    route = Path("adapters/isolate_route.py")
    assert (ROOT / route).is_file()
    assert "def _run_door" in (ROOT / route).read_text()
    callers = {}
    for rel in _shipped_python():
        text = (ROOT / rel).read_text(encoding="utf-8")
        if "_run_door" in text or "subprocess" in text:
            callers[str(rel)] = sorted(
                w for w in ("_run_door", "subprocess") if w in text
            )
    assert set(callers) == {str(route)}, callers
    for rel in ("__init__.py", "capability_gate.py", "adapters/claude_code_hook.py"):
        text = (ROOT / rel).read_text(encoding="utf-8").lower()
        assert not [w for w in _BOX_WORDS if w in text], rel


# --- B2, B3: ticket store across processes, row tickets under threads ---------

_BARRIER = None


def _child_init(barrier):
    global _BARRIER
    _BARRIER = barrier


def _consume_in_child(args):
    path, log, ticket = args
    spec = importlib.util.spec_from_file_location("isolate_route_child", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    _BARRIER.wait()
    return mod.TicketStore(log).consume(ticket)


@pytest.mark.skipif(sys.platform == "win32", reason="fork and fcntl")
def test_ticket_single_use_across_processes(tmp_path):
    """Class: a ticket is accepted twice when processes race the store, or each keeps its own."""
    import multiprocessing as mp

    ctx = mp.get_context("fork")
    n = 16
    log = str(tmp_path / "capability-gate.jsonl")
    path = str(ROOT / "adapters" / "isolate_route.py")
    for _ in range(20):
        ticket = os.urandom(16).hex()
        with ctx.Pool(n, initializer=_child_init, initargs=(ctx.Barrier(n),)) as pool:
            got = pool.map(_consume_in_child, [(path, log, ticket)] * n, chunksize=1)
        assert sum(got) == 1, got


def test_parallel_isolate_rows_keep_their_own_ticket(tmp_path, monkeypatch):
    """Class: under parallel calls a denial row records another call's route ticket."""
    from concurrent.futures import ThreadPoolExecutor

    sb = Sandbox(tmp_path, monkeypatch)
    with ThreadPoolExecutor(8) as ex:
        list(ex.map(lambda i: sb.call(call_id=f"c{i}"), range(64)))
    rows = sb.rows()
    iso = {
        r["tool_call_id"]: r["route_ticket"] for r in rows if r["verdict"] == "isolate"
    }
    deny = {
        r["tool_call_id"]: r.get("route_ticket") for r in rows if r["verdict"] == "deny"
    }
    assert len(iso) == 64 and deny == iso


def test_route_module_first_load_is_safe_across_threads(tmp_path, monkeypatch):
    """Class: a thread uses the route module before it has finished loading."""
    import threading

    sb = Sandbox(tmp_path, monkeypatch)
    path = os.path.join(sb.mod._HERE, "adapters", "isolate_route.py")
    name = (
        "capability_gate_isolate_route_"
        + hashlib.sha256(path.encode()).hexdigest()[:16]
    )
    try:
        for n in range(30):
            sys.modules.pop(name, None)
            barrier = threading.Barrier(16)
            got = []

            def go(barrier=barrier, got=got):
                barrier.wait()
                try:
                    got.append(
                        callable(
                            getattr(sb.mod._isolate_route(), "route_isolate", None)
                        )
                    )
                except Exception as exc:
                    got.append(repr(exc))

            threads = [threading.Thread(target=go) for _ in range(16)]
            for th in threads:
                th.start()
            for th in threads:
                th.join()
            assert got == [True] * 16, (n, got)
    finally:
        sys.modules.pop(name, None)
