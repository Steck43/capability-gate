"""A second path argument cannot hide behind an in-grant first one.

Main and A5 read every path-like argument. The ``keep/2026-10-05`` snapshot
read only the tool's primary key, so ``{path: <in-grant>, target: <off-grant>}``
was allowed there. This pins the branch against sliding back to that extractor.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from grind01_util import blocked, hermes_home, load_adapter, register  # noqa: E402


def test_secondary_path_key_mediated(tmp_path, monkeypatch) -> None:
    home = hermes_home(tmp_path, monkeypatch)
    grant = (tmp_path / "grant").resolve()
    grant.mkdir()
    outside = (tmp_path / "outside").resolve()
    outside.mkdir()
    adapter = load_adapter("p0")
    pre = register(
        adapter,
        home,
        {"UNLABELED": {"tools": ["write_file"], "paths": [str(grant / "**")]}},
    )
    out = pre(
        "write_file",
        {"path": str(grant / "ok.txt"), "target": str(outside / "x.txt")},
        "p0",
    )
    assert blocked(out), out
