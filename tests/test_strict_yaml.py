"""Permissive YAML: duplicate keys and merge keys must fail closed."""

from __future__ import annotations

import pytest
import yaml
from yaml.constructor import ConstructorError

from capability_gate import load_yaml_mapping


def test_plain_mapping_loads() -> None:
    data = load_yaml_mapping("skills:\n  s:\n    tools: [read_file]\n")
    assert data["skills"]["s"]["tools"] == ["read_file"]


def test_duplicate_key_refused() -> None:
    text = "mode: enforce\nmode: observe\n"
    # PyYAML safe_load keeps the last value; strict load must raise.
    assert yaml.safe_load(text)["mode"] == "observe"
    with pytest.raises(ConstructorError, match="duplicate YAML key"):
        load_yaml_mapping(text)


def test_merge_key_refused() -> None:
    text = "defaults: &d\n  mode: observe\nentry:\n  <<: *d\n  tools: [read_file]\n"
    with pytest.raises(ConstructorError, match="merge keys"):
        load_yaml_mapping(text)


def test_duplicate_skill_key_refused() -> None:
    text = (
        "skills:\n"
        "  UNLABELED:\n"
        "    tools: [read_file]\n"
        "  UNLABELED:\n"
        "    tools: [write_file]\n"
    )
    with pytest.raises(ConstructorError, match="duplicate YAML key"):
        load_yaml_mapping(text)


def test_non_mapping_root_refused() -> None:
    with pytest.raises(ValueError, match="mapping"):
        load_yaml_mapping("- just a list\n")
