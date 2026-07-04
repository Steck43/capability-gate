# capability-gate

A deny-by-default capability gate for agent tool calls. A Hermes plugin.

An agent thinks and it acts. Thinking is text and it is harmless. Acting is a tool call, and every real consequence runs through one. In most setups the line from thought to action is unbroken. The model decides to read a file, write a file, run a command, and the runtime obeys. This closes that line. The agent does not run the tool. It asks the gate, and the gate answers allow, deny, or ask. The model proposes. The gate disposes.

## Why

An agent wired into real systems is a non-human identity with standing access. It holds the tools and paths its task needs, and usually far more, because permissions are granted broad and rarely pulled back. A prompt injection, a poisoned document, or a confused plan then acts with everything that identity can reach, not just what the task required. Most controls watch for that after the fact and alert on it. This one enforces least privilege at the point of action. A call outside what the skill was granted does not run.

The decision is deterministic code you can read, not the probabilistic model you cannot fully trust, because the model is the thing being guarded against. If the guard were also the model, a clever prompt could talk it into opening the door. A small amount of deterministic code cannot be argued with. Safety becomes a property of what a skill can reach, not of what the model can be talked into.

## What it does

The gate sits on the Hermes `pre_tool_call` hook and enforces one file: an allowlist. Each skill may touch only the tools and paths its entry grants. Everything else is denied.

- **Deny by default.** An unlisted skill, tool, or path is denied.
- **Complete mediation.** Every call and every path it touches is checked.
- **Least privilege.** A skill does only what its entry grants.
- **Fail closed.** Any error in the decision path is a denial. The Hermes hook framework catches hook errors and lets the agent continue, so it fails open. A gate cannot lean on the thing it guards. It stops itself.
- **Fail loud.** A policy that cannot resolve, an unset path variable, a malformed grant, is rejected at load, not silently ignored at decision time where the failure would be a security gap.
- **Log before act.** The decision is flushed to durable storage before it returns, so the record survives a crash mid-action and the audit trail is real from the first call.

## Rollout

Two modes make rollout safe. Observe decides and logs exactly as it would, and blocks nothing. Enforce acts on the decision.

The intended rollout is observe first. Run observe continuously for two weeks. Read the log. Write the grants to match what the agent actually does. Then flip to enforce. `report.py` reads the decision log and surfaces the grant gap, the tools and paths used but not yet granted, so the enforce allowlist is distilled from real behavior instead of guessed. Observe protects nothing by design. Protection is an enforce-mode property. Do not lean on observe.

## Install

    # from your Hermes plugins directory
    git clone https://github.com/Steck43/capability-gate.git ~/.hermes/plugins/capability-gate
    cd ~/.hermes/plugins/capability-gate
    cp allowlist.example.yaml allowlist.yaml   # then edit allowlist.yaml for your skills
    python -m pytest -q                         # confirm the decider passes

Enable the plugin under `plugins.enabled` in your Hermes `config.yaml`. Start in observe, read `~/.hermes/logs/capability-gate.jsonl`, tune the allowlist, then set the mode to enforce.

## Status

Honest about what runs versus what is planned.

- **Working, tested.** Stage 1, the decider: deny-by-default allowlist enforcement over tool and path, fail-closed, fail-loud on unresolved policy, log-before-act, observe and enforce modes. The decision core is runtime-agnostic and covered by tests.
- **In rollout.** The gate runs in observe on a live Hermes agent, logging every decision and blocking nothing, across a two-week window. The enforce allowlist is built from that behavior, then enforce is turned on.
- **Planned.** Human-in-the-loop approval for heavy actions (the `ask` verdict is already modeled). Real isolation, so that deny means a skill physically cannot reach a resource rather than being asked not to.

This is a capability gate for one agent, not an operating system. The isolation idea it is built on is the same one that runs underneath every OS: let untrusted programs run on a machine without letting them wreck it or each other.

## Requirements

- The decider (`capability_gate.py`) has zero third-party dependencies. Standard library only, by design, so the decision logic is testable without any runtime.
- Tooling and tests require the packages in `requirements-dev.txt` (PyYAML for policy loading and reporting, pytest for the suite).
- The Hermes adapter and its tests require a Hermes install. On a standalone clone those tests skip.
- Tested on Python 3.12.

To run the tests:

    python3 -m venv .venv && . .venv/bin/activate
    pip install -r requirements-dev.txt
    pytest -q

## License

MIT. See LICENSE.
