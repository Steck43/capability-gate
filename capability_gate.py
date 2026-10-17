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
import time
from collections.abc import Iterable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from enum import Enum

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
    data = yaml.load(text, Loader=_StrictLoader)
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


def _read_anchor(anchor_path: str) -> dict | None:
    if not os.path.lexists(anchor_path):
        return None
    try:
        return _read_witness(anchor_path)
    except (OSError, ValueError) as exc:
        raise ValueError(
            f"audit log anchor unreadable, failing closed: {exc!r}"
        ) from exc


def _verify_log(log_path: str, anchor_path: str | None = None) -> tuple[str, int]:
    """Return (head hash, record count). Check parent links, witness, and anchor.

    The anchor holds the same head and count as the witness, written on every
    append. Once it exists, a missing log, a missing witness, or a chain that
    does not reach the anchored head and count is tamper, not a first run.
    """
    witness_path = _witness_path(log_path)
    witness = _read_witness(witness_path) if os.path.exists(witness_path) else None
    anchor = _read_anchor(anchor_path or _anchor_path(log_path))

    prev = _GENESIS
    count = 0
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

    if witness is None and anchor is not None and count > 0:
        raise ValueError(f"audit log witness missing; {_REANCHOR}")
    if witness is not None and (witness["count"] != count or witness["head"] != prev):
        raise ValueError("audit log witness mismatch")
    if anchor is not None and (anchor["count"] != count or anchor["head"] != prev):
        raise ValueError(
            "audit log does not match its anchor (shortened, rewritten, or "
            f"replaced); {_REANCHOR}"
        )
    return prev, count


def verify_hash_chain(log_path: str, anchor_path: str | None = None) -> str:
    """Return the hash of the last JSONL line, or genesis if none exist.

    Each record's parent is the hash of the previous line. A sibling witness
    file and an anchor (beside the log unless an operator sets another
    location) store the head hash and record count, so truncation, deletion,
    and a recomputed witness fail closed the same way a rewrite does. Fail
    closed instead of appending onto a broken chain.
    """
    head, _count = _verify_log(log_path, anchor_path)
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

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "reason": self.reason,
            "skill": self.skill,
            "tool": self.tool,
            "paths": list(self.paths),
            "enforced": self.enforced,
        }


@dataclass(frozen=True)
class SkillRule:
    tools: frozenset[str]
    path_globs: tuple[str, ...]


@dataclass(frozen=True)
class Policy:
    skills: Mapping[str, SkillRule]
    require_approval: frozenset[str] = field(default_factory=frozenset)


class PolicyError(ValueError):
    """Raised only at load time. A malformed policy fails loudly here, never
    silently at decision time where the failure would be a security gap."""


# --- policy loading -------------------------------------------------------


def load_policy(mapping: Mapping) -> Policy:
    if not isinstance(mapping, Mapping):
        raise PolicyError("policy root must be a mapping")
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
    return Policy(skills=skills, require_approval=frozenset(str(t) for t in approval))


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
    out.append("$")
    return re.compile("".join(out))


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


def _canary_secret(path: str) -> bool:
    return os.path.basename(os.path.normpath(_expand(path))) in _CANARY_BASENAMES


def _protected_segment(name: str) -> bool:
    """True for .env / .aegis / .env.* / .envrc (case-insensitive)."""
    if not name:
        return False
    lower = name.casefold()
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
    ):
        if mode not in (ENFORCE, OBSERVE):
            raise ValueError(f"mode must be '{ENFORCE}' or '{OBSERVE}', got {mode!r}")
        self._policy = policy
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
        record_decision(self._log_path, self._mode, decision)
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
        own = (log, log + ".lock", log + ".witness", token)
        if any(_same_file_name(a, f) for f in own):
            return f"path '{p}' is the gate's own decision log file"
        folders = {os.path.dirname(h) for h in self._halt_paths}
        folders.add(os.path.dirname(log))
        for folder in folders:
            if _is_same_or_ancestor(a, folder):
                return f"path '{p}' holds the kill switch or decision log folder"
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
            else:
                decision = _decide(
                    self._policy,
                    str(skill),
                    str(tool),
                    path_list,
                    base_dir,
                )
            # observe mode records the true verdict but does not act on it
            decision = replace(decision, enforced=(self._mode == ENFORCE))
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
        )


def record_decision(
    log_path: str,
    mode: str,
    decision: Decision,
    *,
    trace: Mapping[str, str] | None = None,
    arg_summary: Mapping | None = None,
    anchor_path: str | None = None,
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
            head, count = _verify_log(log_path, anchor_path)
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
    args = parser.parse_args(argv)
    retired = reanchor_audit_log(args.log, anchor_path=args.anchor)
    if retired:
        print("retired: " + ", ".join(retired))
    else:
        print("nothing to retire")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
