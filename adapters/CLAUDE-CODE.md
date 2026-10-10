# capability-gate for Claude Code

Controls that contain what an agent can do at the level of each tool call.

The decider in `capability_gate.py` runs as a Claude Code `PreToolUse` hook. Every tool call Claude Code is about to make is checked against an allowlist of tools and paths. A call the allowlist does not grant is blocked before it runs, and every decision is written to a hash-chained log before the hook answers.

Windows only. Measured on Claude Code 2.1.290 and Windows 10.0.26300.9457, with the adapter at commit `f4aae96`.

## Install

1. Copy `adapters/claude_code_allowlist.example.yaml` to `adapters/claude_code_allowlist.yaml` and edit the grants.
2. Add the hook to `.claude/settings.local.json` in your project. Use the full path to `python.exe`. Exec form (`args`) runs the interpreter directly, with no shell in between.

```json
{
  "hooks": {
    "PreToolUse": [
      {"matcher": "*", "hooks": [{"type": "command",
        "command": "C:\\path\\to\\python.exe",
        "args": ["C:\\path\\to\\capability-gate\\adapters\\claude_code_hook.py"],
        "timeout": 15}]}
    ],
    "PostToolUse": [
      {"matcher": "*", "hooks": [{"type": "command",
        "command": "C:\\path\\to\\python.exe",
        "args": ["C:\\path\\to\\capability-gate\\adapters\\claude_code_hook.py", "--post"],
        "timeout": 15}]}
    ]
  }
}
```

The allowlist path can be set with `CG_CC_ALLOWLIST`. Decisions go to `%USERPROFILE%\.capability-gate\claude-code.jsonl`, or to `CG_CC_LOG`.

## How it decides

- **Allow** is exit 0 with no output. Claude Code reads that as "no decision", so its own permission rules still apply. The hook can take access away; it cannot grant it.
- **Deny** is exit 2 with the reason on stderr. Claude Code shows the reason to the model.
- **Every error is a deny.** Bad input, a missing or unreadable allowlist, a grant that does not load, and a log that cannot be written all end in exit 2. This matters because Claude Code does not block on a hook that crashes or times out. Only exit 2 or a JSON deny blocks.
- **Deadline.** The hook denies after 5 s by default (`CG_CC_DEADLINE_S`), clamped to at most 14 s and rejecting non-finite values, so a stalled check blocks inside Claude Code's ~15 s hook timeout instead of timing out as allow.
- **No skill label.** Claude Code sends none, so every call is judged as the skill `UNLABELED`. The allowlist must grant `UNLABELED` by name. A `"*"` entry never applies.
- **Paths.** Only tools in the closed adapter schema are checked: `Read`, `Write`, `Edit`, `MultiEdit` and `NotebookEdit` on the file they name; `Glob` and `Grep` on their search path, or the working directory when none is given. Any other tool name (including `LS`, `NotebookRead`, and `mcp__*`) is denied even if the allowlist grants it. Relative paths resolve against the working directory. Links are resolved and case is folded before matching. A path with an unexpanded `$` or a leading `~` is denied. A `Glob` pattern that is absolute or climbs is denied, including `[.][.]/*`, `[\.][\.]/*`, nested braces such as `{a,{..,b}}/*`, `..*`, and absolute brace alts. That is a denylist over climb shapes, not a full Glob semantic model.
- **Shell tools.** `Bash` and `PowerShell` are outside the path schema, so the adapter denies them. The example allowlist also lists them under `require_approval`.
- **Grants.** A grant is either a file or `<root>/**`, which covers the root and everything below it. A single `*` or `?` makes the allowlist refuse to load, which denies every call.
- **It never rewrites a call.** The hook prints no JSON on `PreToolUse`, so it never returns `updatedInput`.

## What it looked like

A Claude Code session with the hook loaded. The model was asked for one read inside the project and one write outside it. User paths are shortened to `<project>` and `<home>`.

```
TOOL_USE    Read  {"file_path": "<project>\\notes\\a.txt"}
TOOL_RESULT 1  hello from inside the project
TOOL_USE    Write {"file_path": "<home>\\cg_p5_outside.txt", "content": "p5."}
TOOL_RESULT PreToolUse:Write hook error: [...python.exe ...\adapters\claude_code_hook.py]:
            capability-gate: deny: tool 'Write' not granted to 'UNLABELED'
```

The decision log for that session:

```
allow UNLABELED Read  ['<project>\\notes\\a.txt']   | allowed by policy
deny  UNLABELED Write ['<home>\\cg_p5_outside.txt']  | tool 'Write' not granted to 'UNLABELED'
```

The file outside the project was not created. In this run the hook was loaded with `claude --settings <file>` rather than from `.claude/settings.local.json`.

## Behavior measured on Claude Code 2.1.290

| Question | What happened |
|---|---|
| One hook exits 2, another returns JSON allow, same call | Blocked. The file was not written. |
| One hook returns JSON deny, another returns JSON allow | Blocked. |
| Two hooks return different `updatedInput` | The hook that finished last won. A 3 s delay decided which rewrite ran, in both orders. |
| What a third, read-only hook saw on that call | The original input, not either rewrite |
| What `PostToolUse` saw on that call | The rewritten input that actually ran |
| `Write`, `Read`, `Edit`, `Glob`, `Grep` with no rewrite | The same `tool_input` in `PreToolUse` and `PostToolUse` |

## Input changed after the check

Hooks run in parallel, so a check sees the input as it was before any other hook rewrote it, and the last rewrite to finish is the one that runs. A `PreToolUse` hook cannot tie the run to the input it checked. So the adapter detects instead. `PreToolUse` records a digest of each input it allows. `PostToolUse` (`--post`) compares the input that ran. On a mismatch, or when there is no record, it returns `{"decision": "block", ...}` with the reason, so Claude is told and stops.

This happens after the call has run. It is detection, not prevention.

## What this hook does not see

- **The interpreter failing to start.** If `python.exe` is missing or moved, Claude Code treats the hook as a non-blocking error and the call runs. Nothing inside the hook can close this. (From the Claude Code documentation; not measured here.)
- **A broken settings file.** If the settings file that holds the hook is invalid JSON, Claude Code skips it. In an interactive session it asks first; with `-p` it skips silently. The hook is then not loaded. (From the Claude Code documentation; not measured here.)
- **Other hooks.** Another hook's `updatedInput` can change a call after this hook allowed it (see the table above). The `PostToolUse` check reports it after the fact.
- **What an allowed tool does next.** The hook sees the call, not its effects. What a shell command does once it is allowed, what an MCP server does on its side, and the files Claude Code reads on its own (project instructions, settings, `@` mentions) are outside the hook path.
- **Hardlinks and races.** Resolving links catches a symlink or junction to an off-grant file. A regular file with more than one hard link is denied. A file swapped between the check and the open stays open until the host opens by fd.

Managed settings change some of this. With the hook in managed settings and `allowManagedHooksOnly` set, user, project, local and plugin hooks do not run, apart from plugins that managed settings force-enable. That removes other hooks' rewrites and a broken user or project settings file. A user `disableAllHooks` cannot turn off a managed hook. The interpreter failing to start, and what an allowed tool does next, are not changed by managed settings. These managed-settings effects come from the Claude Code documentation and were not measured here.

## Tests

`tests/test_cc_adapter.py` runs the hook as a subprocess, the way Claude Code does. Each guarded branch was removed, and the tests that turned red are listed below. Every restore came back green.

| Branch removed | Tests that go red |
|---|---|
| The top-level handler that turns any error into exit 2 | `test_adapter_raise_blocks`, `test_unreadable_allowlist_denies_all` (missing, directory, invalid YAML, bad policy), `test_ungranted_tool_denied`, `test_unexpanded_or_escaping_paths_denied`, `test_single_star_grant_refused_on_windows_style` |
| The deadline watchdog | `test_deadline_denies` |
| The literal `UNLABELED` skill (swapped for `*`) | `test_unlabeled_not_star`, `test_read_inside_allowed`, `test_relative_path_resolves_against_cwd`, `test_windows_spellings_match`, `test_glob_and_grep_in_project_allowed`, `test_input_changed_after_check_flagged` |
| The `PostToolUse` digest comparison | `test_input_changed_after_check_flagged`, `test_post_with_no_pre_record_flagged` |
| Link resolution and case folding | `test_windows_spellings_match` |
| Refusing a single `*` or `?` in a grant | `test_single_star_grant_refused_on_windows_style` |
| Refusing an absolute or `..` `Glob` pattern | `test_unexpanded_or_escaping_paths_denied` |
| Refusing obfuscated Glob climbs (incl. residuals) | `test_glob_obfuscated_climb_denied`, `test_glob_climb_residuals_denied` |
| Refusing `$` and leading `~` | `test_unexpanded_or_escaping_paths_denied` |

`test_never_emits_updated_input` guards the rule that the hook prints nothing on `PreToolUse`. It goes red if any branch starts printing.

Run: `python -m pytest -q tests/test_cc_adapter.py`
