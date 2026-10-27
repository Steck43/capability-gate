"""Shared setup: import capability-gate from CG_ROOT and build a client on a temp tree."""

import importlib
import os
import sys
import tempfile
from pathlib import Path

# Default: the capability-gate checkout this file lives in (demos/hire/gap -> repo root).
CG_ROOT = os.environ.get("CG_ROOT") or str(Path(__file__).resolve().parents[3])
if not (Path(CG_ROOT) / "capability_gate.py").is_file():
    raise SystemExit(
        f"CG_ROOT {CG_ROOT} has no capability_gate.py; set CG_ROOT to a capability-gate checkout"
    )
sys.path.insert(0, CG_ROOT)
cg = importlib.import_module("capability_gate")
sdk = importlib.import_module("capability_gate_sdk")

SKILL = "agent"


def make_client(mode=cg.ENFORCE, root=None):
    root = Path(root or tempfile.mkdtemp(prefix="hire-gap-"))
    work = root / "work"
    work.mkdir(parents=True, exist_ok=True)
    pol = root / "policy.yaml"
    pol.write_text(
        "version: 1\n"
        "require_approval:\n  - terminal\n"
        "skills:\n"
        f"  {SKILL}:\n"
        "    tools: [read_file, write_file, web_search]\n"
        f'    paths: ["{work}/**"]\n',
        encoding="utf-8",
    )
    client = sdk.Client.from_files(pol, root / "log" / "gate.jsonl", mode=mode)
    return client, root, work
