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
    # Digest must match this tree. git_head must be an ancestor when the
    # object is present. A depth-1 checkout cannot see ancestors; that is
    # the only skip.
    receipt = json.loads(
        (ROOF / "harness" / "evidence_receipt.json").read_text(encoding="utf-8")
    )
    digest = hashlib.sha256((ROOF / "capability_gate.py").read_bytes()).hexdigest()
    assert receipt["gate_sha256"] == digest
    sha = str(receipt["git_head"])
    exists = subprocess.run(
        ["git", "rev-parse", "--verify", f"{sha}^{{commit}}"],
        cwd=ROOF,
        capture_output=True,
        text=True,
    )
    if exists.returncode != 0:
        shallow = subprocess.run(
            ["git", "rev-parse", "--is-shallow-repository"],
            cwd=ROOF,
            capture_output=True,
            text=True,
            check=True,
        )
        if shallow.stdout.strip() == "true":
            return
        raise AssertionError(
            f"git_head {sha} is not a commit in this repo"
        )
    visible = subprocess.run(
        ["git", "merge-base", "--is-ancestor", sha, "HEAD"],
        cwd=ROOF,
    )
    assert visible.returncode == 0


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
