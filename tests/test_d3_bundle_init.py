"""D-3: the release zip must include __init__.py with register."""

from __future__ import annotations

import hashlib
import importlib.util
import zipfile
from pathlib import Path

ROOF = Path(__file__).resolve().parents[1]


def _load_bundle_mod():
    path = ROOF / "scripts" / "build_plugin_bundle.py"
    spec = importlib.util.spec_from_file_location("build_plugin_bundle", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_members_list_includes_init() -> None:
    mod = _load_bundle_mod()
    assert "__init__.py" in mod.MEMBERS
    assert (ROOF / "__init__.py").is_file()


def test_built_zip_has_register(tmp_path) -> None:
    mod = _load_bundle_mod()
    lines: list[str] = []
    for name in mod.MEMBERS:
        path = ROOF / name
        assert path.is_file(), name
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {name}")
    sums = tmp_path / "SHA256SUMS"
    sums.write_text("\n".join(lines) + "\n", encoding="utf-8")
    zip_path = tmp_path / f"capability-gate-plugin-{mod.VERSION}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name in mod.MEMBERS:
            zf.write(ROOF / name, arcname=name)
        zf.write(sums, arcname="SHA256SUMS")
    names = zipfile.ZipFile(zip_path).namelist()
    assert "__init__.py" in names
    src = zipfile.ZipFile(zip_path).read("__init__.py").decode("utf-8")
    assert "def register(" in src
