# Author: Landen Stecker
# Created: 2026-09-12
# Updated: 2026-09-12
# Version: 0.1.0
# Summary: Stage-1 receipt paths stay portable.

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOF = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOF))
sys.path.insert(0, str(ROOF / "harness"))

from lab_insufficiency_harness import run_cases, write_receipt  # noqa: E402


def test_committed_receipt_matches_gate_file_and_names_a_visible_commit() -> None:
    # Replacing gate_sha256 / git_head with 99eaf7e / 53f35f0 stayed green.
    # The digest must be this tree's capability_gate.py, and the named
    # revision must be a commit HEAD can see.
    receipt = json.loads(
        (ROOF / "harness" / "evidence_receipt.json").read_text(encoding="utf-8")
    )
    digest = hashlib.sha256((ROOF / "capability_gate.py").read_bytes()).hexdigest()
    assert receipt["gate_sha256"] == digest
    sha = str(receipt["git_head"])
    exists = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", f"{sha}^{{commit}}"],
        cwd=ROOF,
    )
    visible = subprocess.run(
        ["git", "merge-base", "--is-ancestor", sha, "HEAD"],
        cwd=ROOF,
    )
    assert exists.returncode == 0 and visible.returncode == 0


def test_write_receipt_has_no_host_home(tmp_path: Path) -> None:
    results = run_cases(tmp_path / "decisions.jsonl")
    path = write_receipt(results, tmp_path)
    text = path.read_text(encoding="utf-8")
    assert "C:\\Users\\" not in text
    assert "C:/Users/" not in text
    payload = json.loads(text)
    assert payload["gate_module"] == "capability_gate.py"
    a2 = next(r for r in payload["results"] if r["case_id"] == "A2")
    assert a2["paths"] == ["~/.ssh/id_rsa"]
