"""Property tests for the path checks.

The known-answer files pin named attacks. These tests let Hypothesis build
the inputs instead: paths of random segments through a fixed link layout,
random glob segments, and protected names in random case and position.

The main property needs no model of path rules. It opens the generated path
and reads which file the operating system actually returns, then requires the
gate to deny exactly when that file is outside the grant.

CI runs a fixed set of examples (derandomized), so a red run cannot come from
new random inputs on an unrelated change. Local runs draw fresh examples.
"""

from __future__ import annotations

import os
import types

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from capability_gate import (
    Gate,
    Verdict,
    _glob_to_regex,
    _path_allowed,
    _path_has_protected_segment,
    load_policy,
)

PROPERTY = settings(
    max_examples=300,
    deadline=None,
    database=None,
    derandomize=os.environ.get("CI") == "true",
)


@pytest.fixture(scope="module")
def layout(tmp_path_factory):
    """A grant with links that point out, links that point back in, and decoys.

    granted/            the grant is granted/**
      a/f.txt
      b.txt
      secret.txt        decoy, same name as the outside secret
      sl  -> outside/inner      folder link out
      fl  -> outside/secret.txt file link out
      dl  -> granted/a          folder link that stays in
    outside/
      inner/g.txt
      secret.txt
      back -> granted           folder link from outside back into the grant

    Every file holds IN or OUT and its own name, so a read says where it was.
    """
    root = tmp_path_factory.mktemp("props").resolve()
    granted, outside = root / "granted", root / "outside"
    (granted / "a").mkdir(parents=True)
    (outside / "inner").mkdir(parents=True)
    for path, side in (
        (granted / "a" / "f.txt", "IN"),
        (granted / "b.txt", "IN"),
        (granted / "secret.txt", "IN"),
        (outside / "inner" / "g.txt", "OUT"),
        (outside / "secret.txt", "OUT"),
    ):
        path.write_text(f"{side} {path.relative_to(root).as_posix()}", encoding="utf-8")
    links = (
        (granted / "sl", outside / "inner", True),
        (granted / "fl", outside / "secret.txt", False),
        (granted / "dl", granted / "a", True),
        (outside / "back", granted, True),
    )
    try:
        for link, target, is_dir in links:
            os.symlink(target, link, target_is_directory=is_dir)
    except OSError as exc:
        pytest.skip(f"this account cannot create symlinks: {exc}")
    policy = load_policy(
        {"skills": {"s": {"tools": ["read_file"], "paths": [str(granted / "**")]}}}
    )
    gate = Gate(policy, log_path=str(root / "logs" / "decisions.jsonl"))
    return types.SimpleNamespace(root=root, granted=granted, gate=gate)


_SEGMENTS = st.sampled_from(
    [
        "a",
        "b.txt",
        "secret.txt",
        "sl",
        "fl",
        "dl",
        "inner",
        "g.txt",
        "f.txt",
        "back",
        "granted",
        "outside",
        "..",
        ".",
        "",
    ]
)
_LEAVES = st.sampled_from(["b.txt", "secret.txt", "g.txt", "f.txt", "fl"])
# On Windows both separators name the same path, so mix them there.
_SEPARATORS = st.sampled_from(sorted({"/", os.sep}))


@st.composite
def _relative_paths(draw) -> str:
    segments = [*draw(st.lists(_SEGMENTS, max_size=6)), draw(_LEAVES)]
    out = segments[0]
    for seg in segments[1:]:
        out += draw(_SEPARATORS) + seg
    return out


def _opened_side(full: str) -> str | None:
    """IN or OUT for the file the OS opens at this path, or None if none opens."""
    try:
        with open(full, encoding="utf-8") as fh:
            return fh.read().split()[0]
    except OSError:
        return None


def _check(layout, path: str, base_dir: str | None) -> None:
    side = _opened_side(os.path.join(base_dir, path) if base_dir else path)
    if side is None:
        return
    d = layout.gate.evaluate("s", "read_file", [path], base_dir=base_dir)
    expected = Verdict.ALLOW if side == "IN" else Verdict.DENY
    assert d.verdict is expected, f"{path!r} opens a file {side} the grant: {d.reason}"


@PROPERTY
@given(rel=_relative_paths())
def test_relative_path_denied_exactly_when_the_os_opens_outside(layout, rel) -> None:
    _check(layout, rel, str(layout.granted))


@PROPERTY
@given(rel=_relative_paths())
def test_absolute_path_denied_exactly_when_the_os_opens_outside(layout, rel) -> None:
    _check(layout, str(layout.granted) + os.sep + rel, None)


_NAME = st.text(
    st.characters(blacklist_categories=("Cs",), blacklist_characters="/\\*?"),
    min_size=1,
    max_size=12,
)


@PROPERTY
@given(name=_NAME)
def test_star_and_question_mark_match_within_one_segment(name) -> None:
    star = _glob_to_regex("/w/*")
    assert star.match("/w/" + name)
    assert not star.match("/w/" + name + "/x")
    assert not star.match("/w/" + name + "\\x")
    assert bool(_glob_to_regex("/w/?").match("/w/" + name)) == (len(name) == 1)


@PROPERTY
@given(
    glob=_NAME,
    other=_NAME,
    suffix=st.sampled_from(["", "\n", "\r", "x", "/", "\\"]),
)
def test_glob_without_wildcards_matches_only_itself(glob, other, suffix) -> None:
    literal = _glob_to_regex(glob)
    assert bool(literal.match(glob + suffix)) == (suffix == "")
    assert bool(literal.match(other)) == (other == glob)


@PROPERTY
@given(names=st.lists(_NAME, min_size=1, max_size=4))
def test_double_star_matches_every_name_below(names) -> None:
    assert _glob_to_regex("/w/**").match("/w/" + "/".join(names))


_PROTECTED = st.sampled_from([".env", ".aegis", ".envrc", ".env.local", ".env.x"])


@st.composite
def _any_case(draw, name: str) -> str:
    flips = draw(st.lists(st.booleans(), min_size=len(name), max_size=len(name)))
    return "".join(c.upper() if f else c for c, f in zip(name, flips))


_PLAIN = st.text(
    st.characters(whitelist_categories=("Ll", "Lu", "Nd")), min_size=1, max_size=8
)


@PROPERTY
@given(
    before=st.lists(_PLAIN, max_size=4),
    after=st.lists(_PLAIN, max_size=4),
    protected=_PROTECTED.flatmap(_any_case),
    sep=st.sampled_from(["/", "\\"]),
)
def test_protected_name_anywhere_in_any_case_is_protected(
    before, after, protected, sep
) -> None:
    assert _path_has_protected_segment(sep.join([*before, protected, *after]))


@PROPERTY
@given(segments=st.lists(_PLAIN, min_size=1, max_size=6))
def test_path_of_plain_names_is_not_protected(segments) -> None:
    assert not _path_has_protected_segment("/".join(segments))


@PROPERTY
@given(head=_PLAIN, tail=_PLAIN)
def test_path_needing_expansion_is_never_allowed(layout, head, tail) -> None:
    grant = [str(layout.granted / "**")]
    assert not _path_allowed(str(layout.granted / f"{head}${tail}"), grant)
    assert not _path_allowed(f"~{head}{os.sep}{tail}", grant)
