# Diagram traces

Line numbers are for commit `a979de5`.

### Trace: `capability-gate` (L0)

| Element | Code |
|---|---|
| Agent proposes a tool call | Hook inputs: `__init__.py:608-613` (`tool_name, args, task_id`), `adapters/claude_code_hook.py:289-290` (`tool_name`, `tool_input`) |
| Host hook: plugin `pre_tool_call` | `__init__.py:608`, registered `:720` (load-failure path `:570-605` also blocks) |
| Host hook: Claude Code `PreToolUse` | `adapters/claude_code_hook.py:1-4`, `_pre` `:286-309` |
| Hook to `Gate.evaluate()` | `__init__.py:637-645`; `adapters/claude_code_hook.py:304` |
| `Gate.evaluate()`: kill switch, then policy. In enforce an error is a deny; observe blocks nothing | `capability_gate.py:1432-1499` (`_kill_switch` `:1458`, `_decide` `:1470`, `except` `:1482-1499`, `enforced` `:1478` and `:1490`) |
| `record_decision()` | `capability_gate.py:1597-1660`; called through `Gate._log` `:1501-1516` |
| Decision returned to the hook when the write succeeds. A tamper or a failed write in enforce re-raises, writes no row, and the hook blocks | `_log` before `return decision` when the write works (`capability_gate.py:1479-1481`). Re-raise `:1657-1660` and `:1493-1498`. Hook block `__init__.py:706-718` |
| allow: tool runs | `__init__.py:646-682` (returns `None`); `adapters/claude_code_hook.py:309` (exit 0, no output) |
| deny or ask: blocked | `__init__.py:700-705` (`ask` becomes a block); `adapters/claude_code_hook.py:305-306` (any non-ALLOW exits 2) |
| Blocked reasons shown | `capability_gate.py:1200`, `:1204`, `:1234` |
| Kill switch: halt marker beside the log, `Gate.throw()`, unreadable means deny | `halt_marker_path` `:821`; `throw` `:1312-1358`; `_halt_state` `:1360-1390` |
| Signed checkpoint, not wired (dashed) | `_cp_check` `:636`, called from `_verify_log` `:296-299`, `:323-326`. The hooks build `Gate` without `checkpoint=`: `__init__.py:485`, `adapters/claude_code_hook.py:297`. `SECURITY.md:25`: "Neither hook sets one yet" |
| Observe mode note | `enforced=(self._mode == ENFORCE)` `:1478`; observe passthrough `__init__.py:683-699`; grant-gap report `report.py:4` |

### Trace: `capability-gate-L1-evaluate`

| Element | Code |
|---|---|
| `evaluate(skill, tool, paths, refuse=, base_dir=)` | `capability_gate.py:1432-1442` |
| `_kill_switch()` region | `:1415-1430` |
| `_halt_state()`: marker present or unreadable; log folder removed or replaced; no writable halt spot | `:1360-1390` (`:1374-1376`, `:1378-1384`, `:1385-1389`) |
| `_guarded_name()`: path names the switch, log, witness, anchor, checkpoint folder | `:1392-1413` |
| `refuse=` set by the hook | `:1461-1468`. Set at `__init__.py:626-636` (`ArgsRefused`, `_gate_file_hit`) and `adapters/claude_code_hook.py:301-303` (`_grant_reaches_own_files`, `_own_file_hit`) |
| `_decide()` region | `:1176-1247` |
| `_absolute()`: relative path with no base folder | `:1184-1194`, `_absolute` `:1158` |
| `policy.skills[skill]`, `rule.tools` | `:1197-1205` |
| Path hazards: `_canary_secret`, `_protected_path`, `_shared_hardlink` | `:1206-1230` (defs `:1099`, `:1131`, `:1018`) |
| `_path_allowed()`, `_tree_escape()` | `:1231-1242` (defs `:1071`, `:1039`) |
| `policy.require_approval` gives ASK | `:1243-1246` |
| ASK: both hooks block it today | `__init__.py:700-704`; `adapters/claude_code_hook.py:305-306` |
| ALLOW: "allowed by policy" | `:1247` |
| `replace(decision, enforced = mode == 'enforce')` | `:1478` |
| `self._log()` to `record_decision()` | `:1479-1480`, `:1501-1516` |
| `except Exception` to DENY "gate error, failing closed" | `:1482-1499` |
| A denial row is written only when the log write succeeds. A tamper or a failed write in enforce re-raises and writes no row. A removed log folder denies without a row | `record_decision` `:1657-1660`; `evaluate` `:1491-1498`; removed folder `:1379-1384` |

### Trace: `capability-gate-L2-audit-log`

| Element | Code |
|---|---|
| `with _audit_lock(log)`: flock on `<log>.lock` | `capability_gate.py:139-162`, used at `:1625` |
| `_verify_log()`: parent equals sha256 of previous line | `:302-312` (`_hash_log_line` `:203`) |
| Witness and anchor must match head and count | `:314-322` |
| If configured: `_cp_check()` | `:323-326` (and `:296-299` for an empty log) |
| Tamper or failed write in enforce: re-raise, no row, hook blocks. Observe does not block a normal decision | `ValueError` in `:290-322`; `record_decision` re-raises `:1657-1660`; enforce re-raises `:1497-1498`. Observe passthrough `__init__.py:683-699` |
| `checked_log_record()`: unknown keys fail closed | `:194-200`, used `:1630` |
| `os.write(O_APPEND)`, `os.fsync()`, short write rolled back | `:1633-1646` |
| `<log>.jsonl` rows with `parent` | `record["parent"] = head` `:1629` |
| `_write_witness()` x2: `.witness` and `.anchor` hold `{head, count + 1}` | `:1647-1656`; paths `:207`, `:235` |
| `.anchor` can sit outside the agent tree | `Gate.__init__` `:1288-1290` (operator-set `anchor_path`) |
| `checkpoint-request`: hashes only plus consistency proof | `checkpoint_request` `:662-688`; CLI `:1676-1688` |
| `checkpoint-sign (CI only)`, `sign_extending()` | CLI `:1689-1696`, `:1711-1733`; `sign_extending` `:689` |
| Signed notes folder `<size>.note`, C2SP, RFC 9162 root, Ed25519 | `_CP_NOTE` `:387`; section comment `:369-384`; `sign_checkpoint` `:584` |
| Notes checked by `_verify_log` | `_cp_check` `:636-653` |
| "Not wired yet" | No `checkpoint=` at `__init__.py:485` or `adapters/claude_code_hook.py:297`. `.github/workflows/` holds only `floor.yml`, `plugin-bundle.yml` and `scorecard.yml` |
| Same-OS-user note | `SECURITY.md:15-17` |

---
