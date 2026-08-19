"""Build the versioned Hermes plugin zip. Not a wheel. Not GitHub's source archive.

Author: Landen Stecker
Date: 2026-08-19
Version: 0.1.0
Summary: Zip capability_gate.py, plugin.yaml, allowlist.example.yaml, and SHA256SUMS of those bytes.
"""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MEMBERS = (
    "capability_gate.py",
    "plugin.yaml",
    "allowlist.example.yaml",
)
VERSION = "0.1.0"


def main() -> int:
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    lines: list[str] = []
    for name in MEMBERS:
        path = ROOT / name
        if not path.is_file():
            raise SystemExit(f"missing bundle member: {name}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {name}")
    sums = dist / "SHA256SUMS"
    sums.write_text("\n".join(lines) + "\n", encoding="utf-8")
    zip_path = dist / f"capability-gate-plugin-{VERSION}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name in MEMBERS:
            zf.write(ROOT / name, arcname=name)
        zf.write(sums, arcname="SHA256SUMS")
    print(zip_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
