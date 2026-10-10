#!/usr/bin/env python3
"""Run the capability-gate pytest suite against the sibling pins in tests.

CI sets AEGIS_ATOMS_ROOT and ISOLATION_LAYER_ROOT to checkouts of those pins.
A local `pytest -q` without those env vars uses ../aegis-atoms and
../isolation-layer at whatever HEAD they happen to be, so test_siblings_pinned
goes red. This runner creates detached worktrees at the pinned SHAs, sets the
env, and runs pytest. It does not move the operator's sibling checkouts.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOF = Path(__file__).resolve().parents[1]
# Keep equal to tests/test_gate_boundary.py _PINS / _ENV. test_run_full_suite_pins
# fails if they drift.
_ATOMS = "aegis-atoms"
_ISOLATION = "isolation-layer"
_ENV = {
    _ATOMS: "AEGIS_ATOMS_ROOT",
    _ISOLATION: "ISOLATION_LAYER_ROOT",
}
_PINS = {
    _ATOMS: "41b6e8396b998d7f2a7bb95fb6f3ced186e28ee1",
    _ISOLATION: "a27c8ee424d96a18a9147bab5689a78e819b7184",
}
_DEFAULT_SRC = {
    _ATOMS: (
        "AEGIS_ATOMS_SRC",
        ("aegis-atoms-public", "aegis-atoms"),
    ),
    _ISOLATION: (
        "ISOLATION_LAYER_SRC",
        ("isolation-layer",),
    ),
}


def _git(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def _src_repo(name: str) -> Path:
    env_key, defaults = _DEFAULT_SRC[name]
    raw = os.environ.get(env_key, "").strip()
    candidates = [Path(raw)] if raw else []
    candidates.extend(ROOF.parent / folder for folder in defaults)
    pin = _PINS[name]
    for root in candidates:
        if not (root / ".git").exists() and not (root / ".git").is_file():
            continue
        got = _git(["cat-file", "-t", pin], cwd=root)
        if got.returncode != 0:
            _git(["fetch", "--all", "--tags"], cwd=root)
            got = _git(["cat-file", "-t", pin], cwd=root)
        if got.returncode == 0 and got.stdout.strip() == "commit":
            return root.resolve()
    raise SystemExit(
        f"no sibling git repo contains pin {name}={pin}; "
        f"set {env_key} to a clone that has that commit"
    )


def _worktree(name: str, src: Path, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        _git(["worktree", "remove", "--force", str(dest)], cwd=src)
        shutil.rmtree(dest, ignore_errors=True)
    added = _git(["worktree", "add", "--detach", str(dest), _PINS[name]], cwd=src)
    if added.returncode != 0:
        raise SystemExit(f"git worktree add failed for {name}: {added.stderr.strip()}")
    head = _git(["rev-parse", "HEAD"], cwd=dest)
    if head.stdout.strip() != _PINS[name]:
        raise SystemExit(
            f"{name} worktree HEAD {head.stdout.strip()} != pin {_PINS[name]}"
        )
    return dest.resolve()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    pytest_args = args.pytest_args
    if pytest_args and pytest_args[0] == "--":
        pytest_args = pytest_args[1:]
    if not pytest_args:
        pytest_args = ["-q"]

    tmp = ROOF / ".tmp" / "pinned-siblings"
    atoms_src = _src_repo(_ATOMS)
    isolation_src = _src_repo(_ISOLATION)
    atoms_root = None
    isolation_root = None
    try:
        atoms_root = _worktree(_ATOMS, atoms_src, tmp / "aegis-atoms")
        isolation_root = _worktree(_ISOLATION, isolation_src, tmp / "isolation-layer")
        env = os.environ.copy()
        env[_ENV[_ATOMS]] = str(atoms_root)
        env[_ENV[_ISOLATION]] = str(isolation_root)
        print(
            f"AEGIS_ATOMS_ROOT={atoms_root} ({_PINS[_ATOMS][:12]})\n"
            f"ISOLATION_LAYER_ROOT={isolation_root} ({_PINS[_ISOLATION][:12]})",
            file=sys.stderr,
        )
        run = subprocess.run(
            [sys.executable, "-m", "pytest", *pytest_args],
            cwd=ROOF,
            env=env,
        )
        return int(run.returncode)
    finally:
        for src, dest in (
            (atoms_src, atoms_root),
            (isolation_src, isolation_root),
        ):
            if dest is not None and dest.exists():
                _git(["worktree", "remove", "--force", str(dest)], cwd=src)
                shutil.rmtree(dest, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
