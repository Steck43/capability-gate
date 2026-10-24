"""The route from an ISOLATE verdict to the box door.

The gate decides; this module carries the decided call to the door and checks
what comes back. It is the one shipped module that starts a process, so the
decider and the host entry points stay free of box code. Every outcome is a
block on the host: a call with an ISOLATE verdict never runs on the host, and
the message says what the box did with it.

The door is a program named in ``isolate_route.yaml`` beside the plugin. It
reads one task (``isolate-route-task/1``) on stdin and prints one receipt
(``isolate-route-receipt/1``) on stdout. The receipt must answer this task:
the route ticket the gate issued, the tool call id, the gate decision digest
and the task digest all have to match, and each ticket is accepted once
across calls (a persisted store beside the decision log).

The Claude Code hook cannot wait on a VM inside its deadline, so it queues
the task in a spool folder and denies the call (``queue_only``).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import signal
import stat
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

try:
    import fcntl
except ImportError:  # Windows: no route slot, so every route reports busy
    fcntl = None

TASK_SCHEMA = "isolate-route-task/1"
RECEIPT_SCHEMA = "isolate-route-receipt/1"
TASK_FIELDS = (
    "schema",
    "route_ticket",
    "tool_call_id",
    "tool",
    "skill",
    "args",
    "gate_decision_sha256",
)
MAX_TASK_BYTES = 64 * 1024
MAX_RECEIPT_BYTES = 64 * 1024
STUB_DEADLINE_S = 30.0
REAL_DEADLINE_S = 120.0
MAX_DEADLINE_S = 120.0
DISPOSITIONS = ("advance", "hold", "drop", "rejected")
_DOOR_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}


class RouteConfigError(ValueError):
    """The route config is missing a field or names one it should not."""


@dataclass(frozen=True)
class RouteConfig:
    door: tuple[str, ...]
    real: bool
    deadline_s: float


@dataclass(frozen=True)
class Outcome:
    message: str
    ticket: str | None = None
    disposition: str | None = None


@dataclass(frozen=True)
class Verified:
    ok: bool
    message: str
    disposition: str | None = None


def load_config(mapping: Any) -> RouteConfig:
    if not isinstance(mapping, Mapping):
        raise RouteConfigError("route config must be a mapping")
    extra = sorted(set(mapping) - {"door", "real", "deadline_s"})
    if extra:
        raise RouteConfigError("unknown route config keys: " + ", ".join(extra))
    door = mapping.get("door")
    if (
        not isinstance(door, list)
        or not door
        or not all(isinstance(a, str) and a for a in door)
    ):
        raise RouteConfigError("'door' must be a non-empty list of strings")
    real = mapping.get("real")
    if not isinstance(real, bool):
        raise RouteConfigError("'real' must be true or false")
    default = REAL_DEADLINE_S if real else STUB_DEADLINE_S
    deadline = mapping.get("deadline_s", default)
    if isinstance(deadline, bool) or not isinstance(deadline, (int, float)):
        raise RouteConfigError("'deadline_s' must be a number")
    if not 0 < float(deadline) <= MAX_DEADLINE_S:
        raise RouteConfigError(
            f"'deadline_s' must be above 0 and at most {MAX_DEADLINE_S:g}"
        )
    return RouteConfig(door=tuple(door), real=real, deadline_s=float(deadline))


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_hex(value: Any, n: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == n
        and all(c in "0123456789abcdef" for c in value)
    )


def build_task(decision: Any, tool_call_id: str, args: Any) -> dict:
    return {
        "schema": TASK_SCHEMA,
        "route_ticket": decision.route_ticket,
        "tool_call_id": tool_call_id,
        "tool": decision.tool,
        "skill": decision.skill,
        "args": args,
        "gate_decision_sha256": _sha256(canonical(decision.as_dict())),
    }


def task_sha256(task: Mapping) -> str:
    return _sha256(canonical({k: task[k] for k in TASK_FIELDS}))


# --- single-use tickets and the route slot ------------------------------------


class TicketStore:
    """Route tickets already answered, kept beside the decision log.

    A ticket is accepted once across calls and processes: the check and the
    append run under one lock, and the file is read fresh each time.
    """

    def __init__(self, log_path: str):
        self.path = log_path + ".route-tickets"
        self.lock = log_path + ".route-tickets.lock"

    def consume(self, ticket: str) -> bool:
        if not _is_hex(ticket, 32) or fcntl is None:
            return False
        lfd = os.open(self.lock, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(lfd, fcntl.LOCK_EX)
            seen = set()
            with (
                contextlib.suppress(FileNotFoundError),
                open(self.path, encoding="utf-8") as f,
            ):
                for line in f:
                    seen.add(line.strip())
            if ticket in seen:
                return False
            fd = os.open(
                self.path,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
                0o600,
            )
            try:
                os.write(fd, (ticket + "\n").encode("ascii"))
                os.fsync(fd)
            finally:
                os.close(fd)
            return True
        finally:
            os.close(lfd)


@contextlib.contextmanager
def route_slot(log_path: str):
    """One route at a time per decision log. Yields False when the slot is taken."""
    if fcntl is None:
        yield False
        return
    fd = os.open(
        log_path + ".route.lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600
    )
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


# --- the door -----------------------------------------------------------------


def _not_swappable(path: str, what: str, want_dir: bool) -> str | None:
    """Why someone other than this user could swap the file, or None."""
    if not os.path.isabs(path):
        return f"{what} {path!r} is not an absolute path"
    try:
        st = os.lstat(path)
    except OSError as exc:
        return f"{what} {path!r} is missing ({exc.strerror})"
    if stat.S_ISLNK(st.st_mode):
        return f"{what} {path!r} is a symlink"
    if want_dir and not stat.S_ISDIR(st.st_mode):
        return f"{what} {path!r} is not a folder"
    if not want_dir and not stat.S_ISREG(st.st_mode):
        return f"{what} {path!r} is not a regular file"
    if st.st_uid not in (os.geteuid(), 0):
        return f"{what} {path!r} is not owned by this user or root"
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return f"{what} {path!r} is writable by group or others"
    return None


def _door_problem(door: str) -> str | None:
    problem = _not_swappable(door, "door", want_dir=False)
    if problem is None:
        problem = _not_swappable(os.path.dirname(door), "door folder", want_dir=True)
    return problem


def _run_door(cfg: RouteConfig, task_bytes: bytes) -> tuple[str | None, bytes]:
    """Run the door once. Returns (error message or None, stdout)."""
    try:
        proc = subprocess.Popen(
            list(cfg.door),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=dict(_DOOR_ENV),
            start_new_session=True,
            close_fds=True,
        )
    except OSError as exc:
        return f"isolate route unreachable: {exc.strerror or exc}", b""
    try:
        out, _ = proc.communicate(task_bytes, timeout=cfg.deadline_s)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(OSError):
            os.killpg(proc.pid, signal.SIGKILL)
        with contextlib.suppress(Exception):
            proc.communicate(timeout=5)
        return f"isolate route timed out after {cfg.deadline_s:g} s", b""
    if proc.returncode != 0:
        return f"isolate route failed: exit {proc.returncode}", b""
    if len(out) > MAX_RECEIPT_BYTES:
        return "isolate route failed: receipt over the size cap", b""
    return None, out


def _last_json_line(out: bytes) -> Any:
    for line in reversed(out.decode("utf-8", "replace").splitlines()):
        if line.strip():
            try:
                return json.loads(line)
            except ValueError:
                return None
    return None


# --- the receipt ----------------------------------------------------------------


def verify_receipt(
    task: Mapping, receipt: Any, cfg: RouteConfig, store: TicketStore
) -> Verified:
    """Check the receipt answers this task, then spend the ticket once."""

    def no(why: str) -> Verified:
        return Verified(False, f"isolate receipt rejected: {why}")

    if not isinstance(receipt, dict):
        return no("not a JSON object")
    if receipt.get("schema") != RECEIPT_SCHEMA:
        return no("schema is not isolate-route-receipt/1")
    for key in ("route_ticket", "tool_call_id", "gate_decision_sha256"):
        if receipt.get(key) != task.get(key):
            return no(f"{key} does not match this call")
    if receipt.get("task_sha256") != task_sha256(task):
        return no("task_sha256 does not match this call")
    if receipt.get("real") is not cfg.real:
        return no("real flag does not match the route config")
    if receipt.get("mode") != ("REAL" if cfg.real else "STUBBED"):
        return no("mode does not match the route config")
    disposition = receipt.get("disposition")
    if disposition not in DISPOSITIONS:
        return no(f"unknown disposition {disposition!r}")
    if not _is_hex(receipt.get("result_sha256"), 64):
        return no("result_sha256 is not 64 hex")
    for key in ("teardown_clean", "hygiene_ok"):
        if not isinstance(receipt.get(key), bool):
            return no(f"{key} is not true or false")
    if not isinstance(receipt.get("jail_id"), str) or not receipt["jail_id"]:
        return no("no jail_id")
    try:
        fresh = store.consume(task["route_ticket"])
    except OSError as exc:
        return no(f"ticket store unavailable ({exc.strerror or exc})")
    if not fresh:
        return Verified(
            False, "isolate receipt replayed: route ticket already answered"
        )
    if not (receipt["teardown_clean"] and receipt["hygiene_ok"]):
        return Verified(
            False,
            f"isolate teardown not clean (jail {receipt['jail_id']})",
            disposition,
        )
    digest = receipt["result_sha256"]
    if disposition == "advance":
        return Verified(True, f"isolated: advance {digest}", disposition)
    if disposition == "hold":
        return Verified(False, f"isolate result held {digest}", disposition)
    if disposition == "drop":
        return Verified(False, f"isolate result dropped {digest}", disposition)
    reason = str(receipt.get("reason", ""))[:200]
    return Verified(
        False, f"isolate result rejected by vestibule: {reason}", disposition
    )


# --- the route ------------------------------------------------------------------


def _folder_token(log_path: str) -> str | None:
    try:
        with open(
            os.path.join(os.path.dirname(log_path), ".capability-gate-folder"),
            encoding="ascii",
        ) as f:
            return f.read().strip() or None
    except (OSError, UnicodeError):
        return None


def _queue(spool: str | None, task: dict, task_bytes: bytes) -> Outcome:
    ticket = task["route_ticket"]
    if not spool:
        return Outcome("isolate route unavailable: no spool folder configured", ticket)
    problem = _not_swappable(spool, "spool", want_dir=True)
    if problem is None and stat.S_IMODE(os.lstat(spool).st_mode) & 0o077:
        problem = f"spool {spool!r} is open to group or others"
    if problem is not None:
        return Outcome(f"isolate route unavailable: {problem}", ticket)
    path = os.path.join(spool, f"{ticket}.json")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        return Outcome(
            f"isolate route unavailable: spool write failed ({exc.strerror or exc})",
            ticket,
        )
    try:
        os.write(fd, task_bytes)
        os.fsync(fd)
    finally:
        os.close(fd)
    return Outcome(f"isolated: queued {ticket}", ticket)


def route_isolate(
    decision: Any,
    *,
    tool_call_id: str,
    args: Any,
    log_path: str,
    config: Mapping | None = None,
    halted: Callable[[], str | None] | None = None,
    queue_only: bool = False,
    spool: str | None = None,
) -> Outcome:
    """Carry one enforced ISOLATE decision to the box. The call is blocked on
    the host whatever comes back; the message says what the box did."""
    ticket = decision.route_ticket
    if not _is_hex(ticket, 32):
        return Outcome("isolate route refused: the decision carries no route ticket")
    if not isinstance(tool_call_id, str) or not tool_call_id:
        return Outcome("isolate route refused: the call has no tool_call_id", ticket)
    if not isinstance(args, dict):
        return Outcome("isolate route refused: args are not an object", ticket)
    task = build_task(decision, tool_call_id, args)
    try:
        task_bytes = canonical(task)
    except (TypeError, ValueError):
        return Outcome("isolate route refused: args are not JSON", ticket)
    if len(task_bytes) > MAX_TASK_BYTES:
        return Outcome(
            f"isolate route refused: task over {MAX_TASK_BYTES} bytes", ticket
        )
    if queue_only:
        return _queue(spool, task, task_bytes)
    if config is None:
        return Outcome("isolate route unavailable: no route config", ticket)
    try:
        cfg = load_config(config)
    except RouteConfigError as exc:
        return Outcome(f"isolate route unavailable: {exc}", ticket)
    problem = _door_problem(cfg.door[0])
    if problem is not None:
        return Outcome(f"isolate route unavailable: {problem}", ticket)
    token = _folder_token(log_path)
    with route_slot(log_path) as held:
        if not held:
            return Outcome(
                "isolate route busy: another isolate route is running", ticket
            )
        error, out = _run_door(cfg, task_bytes)
        stop = halted() if halted is not None else None
        if stop is not None:
            return Outcome(
                f"kill switch thrown during isolate: {stop}; box result discarded",
                ticket,
            )
        if token is None or _folder_token(log_path) != token:
            return Outcome(
                "isolate record lost during route: the decision log folder changed",
                ticket,
            )
        if error is not None:
            return Outcome(error, ticket)
        receipt = _last_json_line(out)
        if receipt is None:
            return Outcome("isolate route failed: no receipt", ticket)
        verified = verify_receipt(task, receipt, cfg, TicketStore(log_path))
        stop = halted() if halted is not None else None
        if stop is not None:
            return Outcome(
                f"kill switch thrown during isolate: {stop}; box result discarded",
                ticket,
            )
        return Outcome(verified.message, ticket, verified.disposition)
