"""Every known-answer test fails against a deliberately naive gate.

A KAT that still passes when the gate allows everything is not testing the
gate. Each KAT file is run in a fresh interpreter with a pytest plugin that
replaces the decision with "allow" and switches off the kill switch, and must
fail there while passing against the real gate.
"""

from __future__ import annotations

import io
import os
import re
import subprocess
import sys
import tokenize
from pathlib import Path

import pytest

ROOF = Path(__file__).resolve().parents[1]

_NAIVE_PLUGIN = """
def pytest_configure(config):
    import capability_gate as cg

    def _allow_everything(policy, skill, tool, paths, base_dir=None):
        return cg.Decision(
            cg.Verdict.ALLOW, "naive gate: allows everything", skill, tool, tuple(paths)
        )

    cg._decide = _allow_everything
    cg.Gate._kill_switch = lambda self, *a, **k: None
"""

_MARKER = re.compile(r"^#\s*KAT\b")


def _has_marker(path: Path) -> bool:
    src = path.read_text(encoding="utf-8", errors="replace")
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(src).readline))
    except (tokenize.TokenError, SyntaxError):
        return False
    return any(t.type == tokenize.COMMENT and _MARKER.match(t.string) for t in tokens)


def _kat_files() -> list[Path]:
    tests = ROOF / "tests"
    found = {*tests.glob("test_k*.py"), *tests.glob("test_*kat*.py")}
    found |= {p for p in tests.glob("test_*.py") if _has_marker(p)}
    return sorted(p for p in found if p.name != Path(__file__).name)


KATS = _kat_files()


def _run(path: Path, plugin_dir: Path | None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    args = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(path)]
    if plugin_dir is not None:
        env["PYTHONPATH"] = os.pathsep.join(
            [str(plugin_dir), str(ROOF), env.get("PYTHONPATH", "")]
        )
        args[3:3] = ["-p", "naive_gate_plugin"]
    return subprocess.run(
        args, cwd=ROOF, env=env, capture_output=True, text=True, check=False
    )


def test_there_are_known_answer_tests_to_check() -> None:
    assert KATS, "no KAT files found; the naive-gate run would check nothing"


@pytest.mark.parametrize("kat", KATS, ids=[p.name for p in KATS])
def test_kat_fails_against_a_naive_gate(tmp_path: Path, kat: Path) -> None:
    (tmp_path / "naive_gate_plugin.py").write_text(_NAIVE_PLUGIN, encoding="utf-8")
    real = _run(kat, None)
    assert real.returncode == 0, real.stdout[-2000:]
    naive = _run(kat, tmp_path)
    assert naive.returncode != 0, (
        f"{kat.name} passed against a gate that allows everything:\n"
        + naive.stdout[-2000:]
    )
    assert "failed" in naive.stdout


def test_naive_run_would_catch_a_kat_that_ignores_the_gate(tmp_path: Path) -> None:
    # The check above relies on a KAT failing under the naive gate. A test that
    # never consults the gate passes there, which is exactly what it flags.
    (tmp_path / "naive_gate_plugin.py").write_text(_NAIVE_PLUGIN, encoding="utf-8")
    hollow = tmp_path / "test_k99_hollow.py"
    hollow.write_text(
        "# KAT\n\n\ndef test_hollow():\n    assert True\n", encoding="utf-8"
    )
    assert _run(hollow, tmp_path).returncode == 0
