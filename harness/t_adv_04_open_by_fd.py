"""T-ADV-04: repeat the check-open swap against the descriptor-bound read."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from capability_gate import (  # noqa: E402
    ENFORCE,
    Gate,
    Verdict,
    load_policy,
    open_authorized_read,
)

DEFAULT_ITERATIONS = 100
FULL_CAMPAIGN_ITERATIONS = 10_000


def run(iterations: int) -> dict[str, int | str]:
    if iterations < 1:
        raise ValueError("iterations must be positive")
    caught = 0
    with tempfile.TemporaryDirectory(prefix="cg-t-adv-04-") as raw:
        root = Path(raw)
        grant = root / "grant"
        outside = root / "outside"
        grant.mkdir()
        outside.mkdir()
        target = grant / "notes.md"
        secret = outside / "id_rsa"
        secret.write_text("secret", encoding="utf-8")
        gate = Gate(
            load_policy(
                {
                    "skills": {
                        "harness": {
                            "tools": ["read_file"],
                            "paths": [str(grant / "**")],
                        }
                    }
                }
            ),
            log_path=str(root / "decisions.jsonl"),
            mode=ENFORCE,
        )

        for _ in range(iterations):
            target.write_text("allowed", encoding="utf-8")
            with open_authorized_read(gate, "harness", str(target)) as opened:
                if opened.decision.verdict is not Verdict.ALLOW:
                    raise AssertionError(opened.decision.reason)
                if opened.stream is None:
                    raise AssertionError("allow returned no descriptor-bound stream")
                target.unlink()
                os.symlink(secret, target)
                if opened.stream.read() != "allowed":
                    raise AssertionError("descriptor followed the swapped path")
                caught += 1
            target.unlink()

    return {
        "case": "T-ADV-04",
        "iterations": iterations,
        "caught": caught,
        "false_allows": iterations - caught,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    args = parser.parse_args()
    print(json.dumps(run(args.iterations), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
