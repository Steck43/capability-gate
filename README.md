# capability-gate

A deny-by-default capability gate for agent tool calls. A Hermes plugin.

An agent thinks and it acts. Thinking is text and it is harmless. Acting is a tool call, and every real consequence runs through one. In most setups the line from thought to action is unbroken. This closes it. The agent does not run the tool. It asks the gate, and the gate answers allow, deny, or ask. The model proposes. The gate disposes.

The decision is deterministic code you can read, not the probabilistic model you cannot fully trust, because the model is the thing being guarded against. If the guard were also the model, a clever prompt could talk it into opening the door. A small amount of deterministic code cannot be argued with. Safety becomes a property of what a skill can reach, not of what the model can be talked into.

## What it does

The gate sits on the Hermes `pre_tool_call` hook and enforces one file: an allowlist. Each skill may touch only the tools and paths its entry grants. Everything else is denied.

- **Deny by default.** An unlisted skill, tool, or path is denied.
- **Complete mediation.** Every call and every path it touches is checked.
- **Least privilege.** A skill does only what its entry grants.
- **Fail closed.** Any error in the decision path is a denial. The Hermes hook framework catches hook errors and lets the agent continue, so it fails open. A gate cannot lean on the thing it guards. It stops itself.
- **Log before act.** The decision is flushed to durable storage before it returns, so the record survives a crash mid-action and the audit trail is real from the first call.

Two modes make rollout safe. Observe decides and logs exactly as it would, and blocks nothing, so a new allowlist can be built against real behavior without breaking the skills already running. Read the log, write the grants to match, then flip to enforce.

## Install

```
# from your Hermes plugins directory
git clone https://github.com/Steck43/capability-gate.git ~/.hermes/plugins/capability-gate
cd ~/.hermes/plugins/capability-gate
cp allowlist.example.yaml allowlist.yaml   # then edit allowlist.yaml for your skills
python -m pytest -q                        # confirm the decider passes
```

Enable the plugin under `plugins.enabled` in your Hermes `config.yaml`. Start in observe, read `~/.hermes/logs/capability-gate.jsonl`, tune the allowlist, then set the mode to enforce.

## Status

Honest about what runs versus what is planned.

- **Working, tested.** Stage 1, the decider: deny-by-default allowlist enforcement over tool and path, fail-closed, log-before-act, observe and enforce modes. The decision core is runtime-agnostic and covered by tests.
- **Planned.** Human-in-the-loop approval for heavy actions (the `ask` verdict is already modeled). Real isolation, so that deny means a skill physically cannot reach a resource rather than being asked not to.

This is a capability gate for one agent, not an operating system. The isolation idea it is built on is the same one that runs underneath every OS: let untrusted programs run on a machine without letting them wreck it or each other.

## License

MIT. See LICENSE.

## Requirements
- The decider (`capability_gate.py`) has zero third-party dependencies. Standard library only, by design, so the decision logic is testable without any runtime.
- Tooling and tests require the packages in `requirements-dev.txt` (PyYAML for policy loading and reporting, pytest for the suite).
- The Hermes adapter and its tests require a Hermes install; on a standalone clone those tests skip.
- Tested on Python 3.12.

To run the tests:
    python3 -m venv .venv && . .venv/bin/activate
    pip install -r requirements-dev.txt
    pytest -q
