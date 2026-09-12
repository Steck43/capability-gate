"""D15: Stage-1 cases through the live pre_tool_call hook, not Gate.evaluate.

The mounted adapter resolves skill as ``*`` (Hermes 0.16.0 has no skill on
that dispatch). This harness grades transfer vs non-transfer. It does not
install Hermes. Public CI stays green without the host agent.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

ROOF = Path(__file__).resolve().parents[1]
if str(ROOF) not in sys.path:
    sys.path.insert(0, str(ROOF))
if str(ROOF / "harness") not in sys.path:
    sys.path.insert(0, str(ROOF / "harness"))

from lab_insufficiency_harness import (  # noqa: E402
    ENFORCE,
    POLICY,
    Gate,
    load_policy,
    run_cases,
)


def load_adapter():
    cg_spec = importlib.util.spec_from_file_location(
        "capability_gate", ROOF / "capability_gate.py"
    )
    cg = importlib.util.module_from_spec(cg_spec)
    sys.modules["capability_gate"] = cg
    cg_spec.loader.exec_module(cg)
    src = (ROOF / "__init__.py").read_text(encoding="utf-8")
    src = src.replace("from .capability_gate import", "from capability_gate import")
    mod = types.ModuleType("d15_adapter")
    mod.__file__ = str(ROOF / "__init__.py")
    exec(compile(src, str(ROOF / "__init__.py"), "exec"), mod.__dict__)
    return mod, cg


def hook_verdict(hook_fn, tool: str, paths: list[str]):
    args = {"path": paths[0]} if paths else {}
    result = hook_fn(tool, args, "d15")
    if result is None:
        return "allow"
    if isinstance(result, dict) and result.get("action") == "block":
        return "deny"
    return "unknown"


def run_d15(tmp: Path) -> dict:
    """Compare Gate.evaluate(named skill) to pre_tool_call on the same policy."""
    import copy

    import yaml

    home = tmp / "hermes"
    (home / "logs").mkdir(parents=True)
    cfg = home / "config.yaml"
    cfg.write_text(
        yaml.dump({"plugins": {"entries": {"capability-gate": {"mode": "enforce"}}}}),
        encoding="utf-8",
    )
    os.environ["HERMES_HOME"] = str(home)

    adapter, _cg = load_adapter()
    policy_raw = copy.deepcopy(POLICY)
    grant = tmp / "s1-in-grant"
    grant.mkdir(parents=True, exist_ok=True)
    policy_raw["skills"]["lab-helper"]["paths"].append(str(grant.resolve() / "**"))
    policy = load_policy(policy_raw)

    def _build_gate(mode: str):
        return Gate(policy, log_path=str(home / "logs" / "d15.jsonl"), mode=ENFORCE)

    adapter._build_gate = _build_gate
    ctx = MagicMock()
    adapter.register(ctx)
    hook_fn = ctx.register_hook.call_args[0][1]

    gate_results = run_cases(tmp / "gate.jsonl", work=tmp)
    rows = []
    transfer = 0
    for r in gate_results:
        hv = hook_verdict(hook_fn, r.tool, r.paths)
        match = hv == ("allow" if r.gate_verdict == "allow" else "deny")
        transfer += int(match)
        rows.append(
            {
                "id": r.case_id,
                "skill": r.skill,
                "gate": r.gate_verdict,
                "hook": hv,
                "transfer": match,
            }
        )
    grade = "TRANSFER" if transfer == len(rows) else "NON-TRANSFER"
    return {
        "grade": grade,
        "n": len(rows),
        "transfer": transfer,
        "hook_skill": adapter._resolve_skill({}),
        "rows": rows,
    }
