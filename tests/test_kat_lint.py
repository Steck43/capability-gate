"""KAT linter: reject tests that are red by fiat or never reach the gate."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "kat_lint.py"

HARD_CODED_FAIL = '''
import pytest


def test_k9_escape_denied():
    """Failing-first until the fix lands."""
    pytest.fail("not yet measured")
'''

RECEIPT_ONLY = """
from pathlib import Path


def test_k9_receipt_exists():
    assert (Path(__file__).parent / "K9.md").is_file()
"""

REAL_GATE_CALL = """
import sys
from pathlib import Path

sys.path.insert(0, {root!r})

import pytest

from capability_gate import Gate, Verdict, load_policy


@pytest.fixture()
def gate(tmp_path):
    policy = load_policy(
        {{"skills": {{"writer": {{"tools": ["read_file"], "paths": [str(tmp_path) + "/work/**"]}}}}}}
    )
    return Gate(policy, log_path=str(tmp_path / "decisions.jsonl"))


def _attempt(gate, tmp_path):
    return gate.evaluate("writer", "read_file", [str(tmp_path / "outside.txt")])


def test_k9_off_grant_read_denied(gate, tmp_path):
    assert _attempt(gate, tmp_path).verdict is Verdict.DENY
"""

# Placeholder shapes from independent review, each a one-line edit away from
# the original hard-coded fail. Every one must be rejected.
REJECTED = {
    "dead_gate_call_then_fail": """
import pytest


def test_k91():
    if False:
        pre_tool_call()
    pytest.fail("red by fiat")
""",
    "fail_second_gate_call_unreachable": """
import pytest


def test_k92(gate):
    x = 1
    pytest.fail("red by fiat")
    gate.evaluate("s", "read_file", ["x"])
""",
    "aliased_fail_gate_call_in_uncalled_lambda": """
from pytest import fail as boom


def test_k93(gate):
    _later = lambda: gate.evaluate("s", "read_file", ["x"])
    boom("red by fiat")
""",
    "module_alias_fail": """
import pytest as pt


def test_k95(gate):
    gate.evaluate("s", "read_file", ["x"])
    pt.fail("red by fiat")
""",
    "skip_marked_receipt_placeholder": """
import pytest
from pathlib import Path


@pytest.mark.skip(reason="later")
def test_k94():
    assert (Path(__file__).parent / "receipts" / "K94.md").is_file()
""",
    "raise_assertion_error": """
def test_k96(gate):
    gate.evaluate("s", "read_file", ["x"])
    raise AssertionError("todo")
""",
    "constant_true_guarded_fail": """
import pytest


def test_k97(gate):
    if True:
        pytest.fail("red by fiat")
    gate.evaluate("s", "read_file", ["x"])
""",
    "returns_before_gate": """
def test_k98(gate):
    return
    gate.evaluate("s", "read_file", ["x"])
""",
    "gate_call_only_in_constant_false_expression": """
def test_k99(gate):
    assert (gate.evaluate("s", "read_file", ["x"]) if False else True)
""",
}

# Known gap, kept visible: the call's receiver is not type-checked, so a local
# class with an evaluate method passes.
LOCAL_EVALUATE = """
class D:
    def evaluate(self, *a):
        return None


def test_k90():
    D().evaluate("x")
    assert True
"""


def _lint(*args: str | Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *map(str, args)],
        capture_output=True,
        text=True,
        check=False,
    )


def _write(tmp_path: Path, name: str, src: str) -> Path:
    p = tmp_path / "tests" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(src, encoding="utf-8")
    return p


def test_hard_coded_fail_is_rejected(tmp_path: Path) -> None:
    r = _lint(_write(tmp_path, "test_k9_fail.py", HARD_CODED_FAIL))
    assert r.returncode == 1
    assert "pytest.fail in a KAT file fails by fiat" in r.stdout


def test_receipt_only_is_rejected(tmp_path: Path) -> None:
    r = _lint(_write(tmp_path, "test_k9_receipt.py", RECEIPT_ONLY))
    assert r.returncode == 1
    assert "never reaches the gate" in r.stdout


@pytest.mark.parametrize("shape", sorted(REJECTED))
def test_placeholder_shape_is_rejected(tmp_path: Path, shape: str) -> None:
    r = _lint(_write(tmp_path, f"test_k_{shape}.py", REJECTED[shape]))
    assert r.returncode == 1, r.stdout


def test_real_gate_call_asserting_deny_is_accepted(tmp_path: Path) -> None:
    path = _write(tmp_path, "test_k9_real.py", REAL_GATE_CALL.format(root=str(ROOT)))
    r = _lint(path)
    assert r.returncode == 0, r.stdout
    # The accepted fixture is a working test, not only a lint-shaped one.
    run = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(path)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0, run.stdout + run.stderr


def test_local_gate_class_is_not_the_real_receiver(tmp_path: Path) -> None:
    src = (
        "class Gate:\n"
        "    def evaluate(self, *args):\n"
        "        return 'DENY'\n\n\n"
        "def test_k_local_class():\n"
        "    assert Gate().evaluate('s', 'read_file', ['x']) == 'DENY'\n"
    )
    r = _lint(_write(tmp_path, "test_k_local_class.py", src))
    assert r.returncode == 1, r.stdout
    assert "never reaches the gate" in r.stdout


def test_local_evaluate_method_is_rejected(tmp_path: Path) -> None:
    r = _lint(_write(tmp_path, "test_k90_local.py", LOCAL_EVALUATE))
    assert r.returncode == 1
    assert "never reaches the gate" in r.stdout


def test_discovery_is_recursive_case_insensitive_and_reads_receipt_paths(
    tmp_path: Path,
) -> None:
    _write(tmp_path, "test_k9_fail.py", HARD_CODED_FAIL)
    _write(tmp_path, "test_scaffold_kat.py", RECEIPT_ONLY)
    _write(tmp_path, "test_marked.py", "# KAT\n" + RECEIPT_ONLY)
    _write(tmp_path, "sub/test_k3_nested.py", RECEIPT_ONLY)
    _write(tmp_path, "test_K5_upper.py", RECEIPT_ONLY)
    # Shape of an open PR that escaped name-based discovery: no K in the name,
    # no marker, but it checks a receipts/ path.
    _write(
        tmp_path,
        "test_windows_grant_acl.py",
        "from pathlib import Path\n\n\n"
        "def test_receipt_exists():\n"
        '    assert (Path(__file__).parents[1] / "receipts" / "X.md").is_file()\n',
    )
    _write(tmp_path, "test_unrelated.py", RECEIPT_ONLY)
    r = _lint("--root", tmp_path)
    assert r.returncode == 1
    assert "in 6 KAT file(s)" in r.stdout
    for name in ("test_k3_nested.py", "test_K5_upper.py", "test_windows_grant_acl.py"):
        assert name in r.stdout
    assert "test_unrelated.py" not in r.stdout


def test_this_repo_kats_pass() -> None:
    r = _lint()
    assert r.returncode == 0, r.stdout


# A real gate fixture, so each fiat form below is the only problem in its file.
GATE_HEADER = """
import sys

import pytest

from capability_gate import Gate, load_policy


@pytest.fixture()
def gate(tmp_path):
    return Gate(load_policy({"skills": {}}), log_path=str(tmp_path / "d.jsonl"))

"""

FIAT_FORMS = {
    "assert_false_after_gate": (
        "assert False",
        """
def test_k_af(gate):
    gate.evaluate("s", "read_file", ["x"])
    assert False, "fiat"
""",
    ),
    "assert_constant_zero": (
        "assert False",
        """
def test_k_az(gate):
    gate.evaluate("s", "read_file", ["x"])
    assert 0
""",
    ),
    "getattr_pytest_fail": (
        "pytest.fail",
        """
def test_k_ga(gate):
    getattr(pytest, "fail")("fiat")
    gate.evaluate("s", "read_file", ["x"])
""",
    ),
    "skip_after_gate": (
        "pytest.skip",
        """
def test_k_sk(gate):
    gate.evaluate("s", "read_file", ["x"])
    pytest.skip("later")
""",
    ),
    "xfail_after_gate": (
        "pytest.xfail",
        """
def test_k_xf(gate):
    gate.evaluate("s", "read_file", ["x"])
    pytest.xfail("later")
""",
    ),
    "unconditional_skip_mark": (
        "unconditional skip mark",
        """
@pytest.mark.skip(reason="later")
def test_k_sm(gate):
    assert gate.evaluate("s", "read_file", ["x"]) is not None
""",
    ),
    "generator_throw": (
        "never reaches the gate",
        """
def test_k_gt():
    def gen():
        yield 1

    g = gen()
    next(g)
    g.throw(ValueError("x"))
""",
    ),
    "constant_comparison": (
        "constant comparison",
        """
def test_k_cmp(gate):
    gate.evaluate("s", "read_file", ["x"])
    assert 1 == 2
""",
    ),
    "bound_constant": (
        "constant comparison",
        """
def test_k_bound(gate):
    left = 1
    right = 2
    gate.evaluate("s", "read_file", ["x"])
    assert left == right
""",
    ),
    "forced_raise": (
        "forced failure",
        """
def test_k_raise(gate):
    gate.evaluate("s", "read_file", ["x"])
    raise RuntimeError("fiat")
""",
    ),
    "forced_exit": (
        "forced exit",
        """
def test_k_exit(gate):
    gate.evaluate("s", "read_file", ["x"])
    sys.exit(1)
""",
    ),
    "importorskip": (
        "pytest.importorskip",
        """
def test_k_imp(gate):
    pytest.importorskip("not_a_real_module")
    gate.evaluate("s", "read_file", ["x"])
""",
    ),
    "constant_skipif": (
        "skipif on a constant",
        """
@pytest.mark.skipif(True, reason="fiat")
def test_k_skipif(gate):
    gate.evaluate("s", "read_file", ["x"])
""",
    ),
    "xfail_raises": (
        "xfail(raises=)",
        """
@pytest.mark.xfail(raises=RuntimeError)
def test_k_xr():
    raise RuntimeError("fiat")
""",
    ),
    "dynamic_code": (
        "dynamic code",
        """
def test_k_dyn(gate):
    gate.evaluate("s", "read_file", ["x"])
    eval("1")
""",
    ),
}


@pytest.mark.parametrize("shape", sorted(FIAT_FORMS))
def test_fiat_form_is_rejected(tmp_path: Path, shape: str) -> None:
    reason, body = FIAT_FORMS[shape]
    r = _lint(_write(tmp_path, f"test_k_{shape}.py", GATE_HEADER + body))
    assert r.returncode == 1, r.stdout
    assert reason in r.stdout, r.stdout


def test_platform_conditional_skip_with_gate_call_is_accepted(tmp_path: Path) -> None:
    body = """
def test_k_pl(gate):
    if sys.platform == "win32":
        pytest.skip("no symlinks without privilege")
    assert gate.evaluate("s", "read_file", ["x"]) is not None
"""
    r = _lint(_write(tmp_path, "test_k_platform.py", GATE_HEADER + body))
    assert r.returncode == 0, r.stdout


@pytest.mark.parametrize(
    "src, reason",
    [
        (
            "import pytest\n\n\n@pytest.mark.xfail(strict=False, reason='x')\n"
            "def test_a():\n    assert 1\n",
            "strict=False",
        ),
        (
            "import pytest\n\n\n"
            "@pytest.mark.parametrize('v', [pytest.param(1, marks=pytest.mark.xfail(strict=False))])\n"
            "def test_b(v):\n    assert v\n",
            "strict=False",
        ),
        (
            "import pytest\n\n\ndef test_c():\n    pytest.xfail('later')\n",
            "imperative pytest.xfail",
        ),
        (
            "import pytest\n\n\n@pytest.mark.skipif(True, reason='x')\n"
            "def test_d():\n    assert 1\n",
            "skipif on a constant",
        ),
        (
            "import sys\n\n\ndef test_e():\n    sys.exit(0)\n",
            "forced exit",
        ),
        (
            "def test_f():\n    eval('1')\n",
            "dynamic code",
        ),
    ],
    ids=[
        "mark-strict-false",
        "param-strict-false",
        "imperative-xfail",
        "constant-skipif",
        "forced-exit",
        "dynamic-code",
    ],
)
def test_xfail_escape_hatches_rejected_in_any_test_file(
    tmp_path: Path, src: str, reason: str
) -> None:
    # An ordinary test file, not a KAT: these hatches defeat xfail_strict anywhere.
    _write(tmp_path, "test_ordinary.py", src)
    r = _lint("--root", tmp_path)
    assert r.returncode == 1, r.stdout
    assert reason in r.stdout, r.stdout


# ---------------------------------------------------------------------------
# T9 to T14. Each rejected case below is one valid KAT plus one bad form, so the
# bad form is the only thing that can make the lint fail. Fixtures use the fake
# term zqxwvk only.

KAT_HEAD = """
import contextlib
import importlib
import os
import sys

import pytest

from capability_gate import Gate, Verdict, load_policy


@pytest.fixture()
def gate(tmp_path):
    return Gate(load_policy({"skills": {}}), log_path=str(tmp_path / "d.jsonl"))

"""


def _kat(body: str, prelude: str = "", params: str = "gate", deco: str = "") -> str:
    """A valid KAT (gate call plus assert on its result) followed by body."""
    lines = [
        "    d = gate.evaluate('s', 'read_file', ['zqxwvk'])",
        "    assert d.verdict is Verdict.DENY",
        *("    " + x for x in body.splitlines()),
    ]
    return (
        KAT_HEAD
        + prelude
        + "\n\n\n"
        + (deco + "\n" if deco else "")
        + f"def test_k_case({params}):\n"
        + "\n".join(lines)
        + "\n"
    )


def _expect(tmp_path: Path, src: str, reason: str, name: str = "test_k_case.py"):
    r = _lint(_write(tmp_path, name, src))
    assert r.returncode == 1, r.stdout
    assert reason in r.stdout, r.stdout


def test_the_base_kat_is_clean(tmp_path: Path) -> None:
    # Control: every rejected case below differs from this only by its bad form.
    r = _lint(_write(tmp_path, "test_k_case.py", _kat("")))
    assert r.returncode == 0, r.stdout


# T9: every constant form folds, file-wide, in tests, helpers and nested functions.
T9_FORMS = {
    "module_binding": ("assert NO", "NO = False", "assert False"),
    "module_binding_compare": ("assert A == B", "A = 1\nB = 2", "constant comparison"),
    "tuple_binding": ("a, b = 1, 2\nassert a == b", "", "constant comparison"),
    "nested_tuple_binding": (
        "a, (b, c) = 1, (2, 3)\nassert b == c",
        "",
        "constant comparison",
    ),
    "annotated_binding": ("flag: bool = False\nassert flag", "", "assert False"),
    "walrus": ("assert (n := 0)", "", "assert False"),
    "empty_list": ("assert []", "", "assert False"),
    "empty_dict": ("assert {}", "", "assert False"),
    "empty_str": ("assert ''", "", "assert False"),
    "empty_tuple": ("assert ()", "", "assert False"),
    "empty_set_call": ("assert set()", "", "assert False"),
    "ternary": ("assert (1 if False else 0)", "", "assert False"),
    "ternary_both_false": ("assert (0 if d else '')", "", "assert False"),
    "and_false_side": (
        "assert d.verdict is Verdict.DENY and False",
        "",
        "assert False",
    ),
    "or_true_side": ("assert d.verdict is Verdict.DENY or True", "", "constant assert"),
    "not_true": ("assert not True", "", "assert False"),
    "none": ("assert None", "", "assert False"),
    "bool_call": ("assert bool(0)", "", "assert False"),
    "len_call": ("assert len([])", "", "assert False"),
    "int_conversion": ("assert int('0')", "", "assert False"),
    "in_empty": ("assert d.verdict in ()", "", "constant comparison"),
    "in_empty_binding": (
        "allowed = ()\nassert d.verdict in allowed",
        "",
        "constant comparison",
    ),
    "not_in_empty": ("assert d.verdict not in []", "", "constant comparison"),
    "chained_compare": ("assert 1 < 2 < 0", "", "constant comparison"),
    "division_raises": ("assert 1 / 0", "", "always raises"),
    "statement_raises": ("1 // 0", "", "always raises"),
    "conversion_raises": ("int('zqxwvk')", "", "always raises"),
    "index_raises": ("[][0]", "", "always raises"),
    "helper_assert": ("_check(d)", "def _check(x):\n    assert False", "assert False"),
    "helper_raises": ("_check(d)", "def _check(x):\n    return 1 / 0", "always raises"),
    "nested_function": ("def inner():\n    assert 0\n\ninner()", "", "assert False"),
    "folded_string_name": (
        "assert NAME == 'zqx'",
        "NAME = 'zq' + 'xwvk'",
        "constant comparison",
    ),
}


@pytest.mark.parametrize("shape", sorted(T9_FORMS))
def test_t9_constant_forms_are_fiat(tmp_path: Path, shape: str) -> None:
    body, prelude, reason = T9_FORMS[shape]
    _expect(tmp_path, _kat(body, prelude), reason)


def _deco_test(deco: str, prelude: str = "", body: str = "assert 1") -> str:
    return f"{prelude}\n\n\n{deco}\ndef test_a():\n    {body}\n"


# T10: skip and xfail forms that hollow a test. Every test file.
T10_ANY_FILE = {
    "skipif_module_binding": (
        _deco_test("@pytest.mark.skipif(SKIP, reason='x')", "SKIP = True"),
        "skipif on a constant",
    ),
    "skipif_not_false": (
        _deco_test("@pytest.mark.skipif(not False, reason='x')"),
        "skipif on a constant",
    ),
    "skipif_compare": (
        _deco_test("@pytest.mark.skipif(1 == 1, reason='x')"),
        "skipif on a constant",
    ),
    "skipif_string_condition": (
        _deco_test("@pytest.mark.skipif('True', reason='x')"),
        "skipif on a constant",
    ),
    "skipif_lambda": (
        _deco_test("@pytest.mark.skipif(lambda: False, reason='x')"),
        "skipif on a constant",
    ),
    "skipif_no_condition": (
        _deco_test("@pytest.mark.skipif(reason='x')"),
        "skipif with no condition",
    ),
    "skipif_condition_keyword": (
        _deco_test("@pytest.mark.skipif(condition=True, reason='x')"),
        "skipif on a constant",
    ),
    "skipif_string_binding": (
        _deco_test("@pytest.mark.skipif(R, reason='x')", "R = 'zqxwvk'"),
        "skipif on a constant",
    ),
    "module_pytestmark_skipif": (
        "pytestmark = [pytest.mark.skipif(True, reason='x')]\n\n\n"
        "def test_a():\n    assert 1\n",
        "skipif on a constant",
    ),
    "skipif_alias": (
        _deco_test("@sk(True, reason='x')", "sk = pytest.mark.skipif"),
        "skipif on a constant",
    ),
    "platform_mixed": (
        _deco_test(
            "@pytest.mark.skipif(sys.platform == 'win32' or FLAG, reason='x')",
            "import os\nimport sys\n\nFLAG = os.environ.get('ZQXWVK')",
        ),
        "not purely a platform condition",
    ),
    "platform_no_such_value": (
        _deco_test(
            "@pytest.mark.skipif(sys.platform != 'zqxwvk', reason='x')", "import sys"
        ),
        "no platform has",
    ),
    "marker_wrapper_parameter": (
        _deco_test(
            "@when(True)", "def when(c):\n    return pytest.mark.skipif(c, reason='x')"
        ),
        "marker wrapper",
    ),
    "xfail_run_false": (
        _deco_test(
            "@pytest.mark.xfail(run=False, strict=True, reason='x')", "", "assert 0"
        ),
        "xfail(run=False)",
    ),
    "xfail_strict_not_constant": (
        _deco_test(
            "@pytest.mark.xfail(strict=STRICT, reason='x')",
            "import os\n\nSTRICT = os.environ.get('ZQXWVK') == '1'",
            "assert 0",
        ),
        "not provably strict",
    ),
    "xfail_strict_binding_false": (
        _deco_test(
            "@pytest.mark.xfail(strict=LAX, reason='x')", "LAX = False", "assert 0"
        ),
        "strict=False",
    ),
    "xfail_kwargs": (
        _deco_test(
            "@pytest.mark.xfail(**OPTS)", "OPTS = {'strict': False}", "assert 0"
        ),
        "cannot see its arguments",
    ),
    "xfail_alias_strict_false": (
        _deco_test(
            "@lax(strict=False, reason='x')", "lax = pytest.mark.xfail", "assert 0"
        ),
        "strict=False",
    ),
    "xfail_from_mark": (
        _deco_test(
            "@mark.xfail(strict=False, reason='x')",
            "from pytest import mark",
            "assert 0",
        ),
        "strict=False",
    ),
    "xfail_with_args": (
        _deco_test(
            "@pytest.mark.xfail.with_args(strict=False, reason='x')", "", "assert 0"
        ),
        "strict=False",
    ),
    "imperative_xfail_alias": (
        "from pytest import xfail as later\n\n\ndef test_a():\n    later('x')\n",
        "imperative pytest.xfail",
    ),
}


@pytest.mark.parametrize("shape", sorted(T10_ANY_FILE))
def test_t10_skip_and_xfail_forms_rejected_in_any_test_file(
    tmp_path: Path, shape: str
) -> None:
    src, reason = T10_ANY_FILE[shape]
    _write(tmp_path, "test_ordinary.py", "import pytest\n" + src)
    r = _lint("--root", tmp_path)
    assert r.returncode == 1, r.stdout
    assert reason in r.stdout, r.stdout


T10_KAT = {
    "module_pytestmark_skip": (
        "",
        "pytestmark = pytest.mark.skip(reason='x')",
        "",
        "skip mark",
    ),
    "module_level_skip_call": (
        "",
        "pytest.skip('x', allow_module_level=True)",
        "",
        "pytest.skip",
    ),
    "mark_alias": ("", "later = pytest.mark.skip", "@later", "skip mark"),
    "mark_from_import": (
        "",
        "from pytest import mark",
        "@mark.skip(reason='x')",
        "skip mark",
    ),
    "mark_module_alias": ("", "m = pytest.mark", "@m.skip(reason='x')", "skip mark"),
    "getattr_mark": ("", "", "@getattr(pytest.mark, 'skip')", "skip mark"),
    "with_args": ("", "", "@pytest.mark.skip.with_args(reason='x')", "skip mark"),
    "marker_call_wrapper": (
        "",
        "def later(f):\n    return pytest.mark.skip(reason='x')(f)",
        "@later",
        "skip mark",
    ),
    "skipif_not_platform": (
        "",
        "",
        "@pytest.mark.skipif(os.environ.get('ZQXWVK') is None, reason='x')",
        "not a platform check",
    ),
    "imperative_skip_mixed_platform": (
        "if sys.platform == 'win32' or os.environ.get('ZQXWVK'):\n    pytest.skip('x')",
        "",
        "",
        "pytest.skip",
    ),
    "raise_skip_exception": ("raise pytest.skip.Exception('x')", "", "", "pytest.skip"),
    "unittest_skip": ("", "import unittest", "@unittest.skip('x')", "unittest.skip"),
    "unittest_skiptest": (
        "raise unittest.SkipTest('x')",
        "import unittest",
        "",
        "unittest.SkipTest",
    ),
}


@pytest.mark.parametrize("shape", sorted(T10_KAT))
def test_t10_skip_forms_rejected_in_a_kat(tmp_path: Path, shape: str) -> None:
    body, prelude, deco, reason = T10_KAT[shape]
    _expect(tmp_path, _kat(body, prelude, deco=deco), reason)


def test_t10_param_and_marker_added_at_runtime(tmp_path: Path) -> None:
    src = (
        KAT_HEAD
        + "@pytest.mark.parametrize('v', [pytest.param(1, marks=pytest.mark.skip)])\n"
        + "def test_k_param(gate, v):\n"
        + "    assert gate.evaluate('s', 'read_file', ['zqxwvk']).verdict is Verdict.DENY\n"
        + "\n\n"
        + "def test_k_added(gate, request):\n"
        + "    request.node.add_marker(pytest.mark.skip(reason='x'))\n"
        + "    assert gate.evaluate('s', 'read_file', ['zqxwvk']).verdict is Verdict.DENY\n"
    )
    r = _lint(_write(tmp_path, "test_k_param.py", src))
    assert r.returncode == 1, r.stdout
    assert r.stdout.count("skip mark") == 2, r.stdout


def test_t10_class_skip_mark(tmp_path: Path) -> None:
    src = (
        KAT_HEAD
        + "@pytest.mark.skip(reason='x')\nclass TestK:\n"
        + "    def test_k(self, gate):\n"
        + "        d = gate.evaluate('s', 'read_file', ['zqxwvk'])\n"
        + "        assert d.verdict is Verdict.DENY\n"
    )
    _expect(tmp_path, src, "skip mark", "test_k_class.py")


# T11: fail, exit and dynamic code under any spelling, in tests, helpers, nested.
T11_FORMS = {
    "assign_alias": ("boom('x')", "boom = pytest.fail", "pytest.fail"),
    "module_alias_assigned": ("pt.fail('x')", "pt = pytest", "pytest.fail"),
    "alias_chain": ("b('x')", "a = pytest.fail\nb = a", "pytest.fail"),
    "import_module": ("importlib.import_module('pytest').fail('x')", "", "pytest.fail"),
    "dunder_import": ("__import__('pytest').fail('x')", "", "pytest.fail"),
    "dunder_import_sys": ("__import__('sys').exit(1)", "", "forced exit"),
    "getattr_sys_exit": ("getattr(sys, 'exit')(1)", "", "forced exit"),
    "getattr_os_exit": ("getattr(os, '_exit')(0)", "", "forced exit"),
    "getattr_folded_name": (
        "getattr(pytest, NAME)('x')",
        "NAME = 'fa' + 'il'",
        "pytest.fail",
    ),
    "getattr_unknown_name": ("getattr(pytest, d.reason)('x')", "", "dynamic attribute"),
    "vars_lookup": ("vars(pytest)['fail']('x')", "", "pytest.fail"),
    "dict_lookup": ("pytest.__dict__['fail']('x')", "", "pytest.fail"),
    "builtins_eval": ("builtins.eval('1')", "import builtins", "dynamic code"),
    "builtins_getattr_exec": (
        "getattr(builtins, 'exec')('x = 1')",
        "import builtins",
        "dynamic code",
    ),
    "builtins_dict": ("__builtins__['eval']('1')", "", "dynamic code"),
    "builtins_alias_exit": ("b.exit()", "import builtins as b", "forced exit"),
    "bare_exit": ("exit()", "", "forced exit"),
    "bare_quit": ("quit()", "", "forced exit"),
    "compile": ("compile('1', 's', 'eval')", "", "dynamic code"),
    "outcomes_import": (
        "f('x')",
        "from _pytest.outcomes import fail as f",
        "pytest.fail",
    ),
    "outcomes_module": ("o.fail('x')", "import _pytest.outcomes as o", "pytest.fail"),
    "pytest_exit": ("pytest.exit('x')", "", "pytest.exit"),
    "os_abort": ("os.abort()", "", "forced exit"),
    "partial_reference": (
        "functools.partial(pytest.fail, 'x')()",
        "import functools",
        "pytest.fail",
    ),
    "list_reference": ("[pytest][0].fail('x')", "", "pytest.fail"),
    "raise_fail_exception": ("raise pytest.fail.Exception('x')", "", "pytest.fail"),
    "helper_exit": ("_bail()", "def _bail():\n    sys.exit(1)", "forced exit"),
    "helper_raise_systemexit": (
        "_bail()",
        "def _bail():\n    raise SystemExit(1)",
        "forced exit",
    ),
    "nested_eval": (
        "def inner():\n    return eval('1')\n\ninner()",
        "",
        "dynamic code",
    ),
    "import_module_unknown": (
        "importlib.import_module(d.reason)",
        "",
        "dynamic import",
    ),
    "runpy": ("runpy.run_path('zqxwvk.py')", "import runpy", "dynamic code"),
}


@pytest.mark.parametrize("shape", sorted(T11_FORMS))
def test_t11_fail_exit_and_dynamic_code_under_any_spelling(
    tmp_path: Path, shape: str
) -> None:
    body, prelude, reason = T11_FORMS[shape]
    _expect(tmp_path, _kat(body, prelude), reason)


@pytest.mark.parametrize(
    "src, reason",
    [
        ("import sys\n\nex = sys.exit\n\n\ndef test_e():\n    ex(0)\n", "forced exit"),
        ("import sys\n\n\ndef test_e():\n    getattr(sys, 'exit')(0)\n", "forced exit"),
        (
            "import builtins\n\n\ndef test_f():\n    builtins.exec('x = 1')\n",
            "dynamic code",
        ),
    ],
    ids=["alias-exit", "getattr-exit", "builtins-exec"],
)
def test_t11_spellings_rejected_in_any_test_file(
    tmp_path: Path, src: str, reason: str
) -> None:
    _write(tmp_path, "test_ordinary.py", src)
    r = _lint("--root", tmp_path)
    assert r.returncode == 1, r.stdout
    assert reason in r.stdout, r.stdout


# T12: only the real gate counts as the receiver.
REAL_IMPORTS = (
    "import pytest\n\nfrom capability_gate import Gate, Verdict, load_policy\n\n\n"
)
POLICY = "load_policy({'skills': {}}), log_path=str(tmp_path / 'd.jsonl')"
ASSERT_DENY = (
    "    assert g.evaluate('s', 'read_file', ['zqxwvk']).verdict is Verdict.DENY\n"
)
GATE_CALL_ASSERT = (
    "    assert gate.evaluate('s', 'read_file', ['zqxwvk']).verdict is Verdict.DENY\n"
)

T12_NOT_THE_GATE = {
    "getattr_class": (
        "import capability_gate\n"
        + REAL_IMPORTS
        + "def test_k(tmp_path):\n"
        + f"    g = getattr(capability_gate, 'Gate')({POLICY})\n"
        + ASSERT_DENY
    ),
    "import_module_class": (
        "import importlib\n"
        + REAL_IMPORTS
        + "def test_k(tmp_path):\n"
        + f"    g = importlib.import_module('capability_gate').Gate({POLICY})\n"
        + ASSERT_DENY
    ),
    "type_constructed": (
        REAL_IMPORTS
        + "def test_k(tmp_path):\n"
        + f"    g = type('G', (Gate,), {{}})({POLICY})\n"
        + ASSERT_DENY
    ),
    "helper_module_class": (
        "from tests.gate_helpers import Gate\n"
        + "from capability_gate import Verdict, load_policy\n\n\n"
        + "def test_k(tmp_path):\n"
        + f"    g = Gate({POLICY})\n"
        + ASSERT_DENY
    ),
    "conftest_builder": (
        "from conftest import make_gate\nfrom capability_gate import Verdict\n\n\n"
        + "def test_k(tmp_path):\n"
        + "    g = make_gate(tmp_path)\n"
        + ASSERT_DENY
    ),
    "subclass": (
        REAL_IMPORTS
        + "class G(Gate):\n    pass\n\n\n"
        + "def test_k(tmp_path):\n"
        + f"    g = G({POLICY})\n"
        + ASSERT_DENY
    ),
    "annotated_parameter_only": REAL_IMPORTS + "def test_k(g: Gate):\n" + ASSERT_DENY,
    "dead_empty_loop": (
        KAT_HEAD
        + "def test_k(gate):\n"
        + "    for _ in []:\n"
        + "        d = gate.evaluate('s', 'read_file', ['zqxwvk'])\n"
        + "    assert d.verdict is Verdict.DENY\n"
    ),
    "dead_empty_binding_loop": (
        KAT_HEAD
        + "ITEMS = ()\n\n\ndef test_k(gate):\n"
        + "    for p in ITEMS:\n"
        + "        d = gate.evaluate('s', 'read_file', [p])\n"
        + "    assert d.verdict is Verdict.DENY\n"
    ),
    "dead_module_false_branch": (
        KAT_HEAD
        + "RUN = False\n\n\ndef test_k(gate):\n"
        + "    if RUN:\n"
        + "        d = gate.evaluate('s', 'read_file', ['zqxwvk'])\n"
        + "    assert d.verdict is Verdict.DENY\n"
    ),
    "dead_comprehension": (
        KAT_HEAD
        + "def test_k(gate):\n"
        + "    ds = [gate.evaluate('s', 'read_file', [p]) for p in []]\n"
        + "    assert ds[0].verdict is Verdict.DENY\n"
    ),
    "unconsumed_generator": (
        KAT_HEAD
        + "def test_k(gate):\n"
        + "    ds = (gate.evaluate('s', 'read_file', [p]) for p in ['zqxwvk'])\n"
        + "    assert ds is not None\n"
    ),
    "expected_exception": (
        KAT_HEAD
        + "def test_k(gate):\n"
        + "    with pytest.raises(Exception):\n    "
        + GATE_CALL_ASSERT
    ),
    "suppressed": (
        KAT_HEAD
        + "def test_k(gate):\n"
        + "    with contextlib.suppress(Exception):\n    "
        + GATE_CALL_ASSERT
    ),
    "raises_callable_form": (
        KAT_HEAD
        + "def test_k(gate):\n"
        + "    assert pytest.raises(Exception, gate.evaluate, 's', 'read_file', ['zqxwvk'])\n"
    ),
    "local_pre_tool_call": (
        "def pre_tool_call(*a):\n    return {'action': 'block'}\n\n\n"
        + "def test_k():\n    assert pre_tool_call()['action'] == 'block'\n"
    ),
    "local_hook_main": (
        "class hook:\n    main = staticmethod(lambda: 2)\n\n\n"
        + "def test_k():\n    assert hook.main() == 2\n"
    ),
    "fake_hook_script": (
        "import subprocess\nimport sys\n\n\n"
        + "def test_k():\n"
        + "    r = subprocess.run([sys.executable, 'tests/claude_code_hook_fake.py'])\n"
        + "    assert r.returncode == 2\n"
    ),
}


@pytest.mark.parametrize("shape", sorted(T12_NOT_THE_GATE))
def test_t12_only_the_real_gate_counts(tmp_path: Path, shape: str) -> None:
    _expect(
        tmp_path, T12_NOT_THE_GATE[shape], "never reaches the gate", "test_k_recv.py"
    )


def test_t12_a_return_inside_try_ends_the_path(tmp_path: Path) -> None:
    src = (
        KAT_HEAD
        + "def test_k(gate):\n"
        + "    try:\n        return\n    finally:\n        pass\n"
        + GATE_CALL_ASSERT
    )
    _expect(tmp_path, src, "before reaching the gate", "test_k_recv.py")


def test_t12_a_gate_module_beside_the_test_is_not_the_gate(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "capability_gate.py").write_text(
        "class Gate:\n    def evaluate(self, *a):\n        return None\n",
        encoding="utf-8",
    )
    src = (
        REAL_IMPORTS
        + "def test_k(tmp_path):\n"
        + f"    g = Gate({POLICY})\n"
        + ASSERT_DENY
    )
    _expect(tmp_path, src, "never reaches the gate", "test_k_shadow.py")


T12_PATCHED = {
    "monkeypatch_class": (
        "monkeypatch.setattr(Gate, 'evaluate', lambda *a, **k: None)",
        "",
        "gate, monkeypatch",
        "",
    ),
    "monkeypatch_instance": (
        "monkeypatch.setattr(gate, 'evaluate', lambda *a, **k: None)",
        "",
        "gate, monkeypatch",
        "",
    ),
    "assign_method": ("gate.evaluate = lambda *a, **k: None", "", "gate", ""),
    "string_target": (
        "monkeypatch.setattr('capability_gate.Gate.evaluate', lambda *a, **k: None)",
        "",
        "gate, monkeypatch",
        "",
    ),
    "mock_patch_object": (
        "",
        "from unittest import mock",
        "fake, gate",
        "@mock.patch.object(Gate, 'evaluate')",
    ),
    "autouse_fixture": (
        "",
        "@pytest.fixture(autouse=True)\ndef _swap(monkeypatch):\n"
        "    monkeypatch.setattr(Gate, 'evaluate', lambda *a, **k: None)",
        "gate",
        "",
    ),
    "module_level": ("", "Gate.evaluate = lambda self, *a, **k: None", "gate", ""),
}


@pytest.mark.parametrize("shape", sorted(T12_PATCHED))
def test_t12_a_patched_gate_does_not_count(tmp_path: Path, shape: str) -> None:
    body, prelude, params, deco = T12_PATCHED[shape]
    src = _kat("", prelude, params=params, deco=deco)
    if body:
        # The patch goes before the gate call.
        src = src.replace(
            "    d = gate.evaluate", f"    {body}\n    d = gate.evaluate", 1
        )
    _expect(tmp_path, src, "patches the gate")


# T13: every KAT asserts on the gate's result.
CALL = "    gate.evaluate('s', 'read_file', ['zqxwvk'])\n"
BOUND = "    d = gate.evaluate('s', 'read_file', ['zqxwvk'])\n"
OTHER = "    assert tmp_path.exists()\n"
T13_UNUSED = {
    "call_result_dropped": CALL + OTHER,
    "result_unused": BOUND + OTHER,
    "result_printed": BOUND + "    print(d.verdict)\n" + OTHER,
    "assert_in_dead_branch": (
        BOUND + "    if False:\n        assert d.verdict is Verdict.DENY\n" + OTHER
    ),
    "throw_result_dropped": "    gate.throw('drill')\n" + OTHER,
    "no_assert": CALL,
}


@pytest.mark.parametrize("shape", sorted(T13_UNUSED))
def test_t13_a_kat_asserts_on_the_gate_result(tmp_path: Path, shape: str) -> None:
    src = KAT_HEAD + "def test_k(gate, tmp_path):\n" + T13_UNUSED[shape]
    _expect(tmp_path, src, "never asserts on the gate's result", "test_k_unused.py")


# T14: legitimate deny-test shapes stay clean, and each one is a working test.
CORPUS_HEAD = """
import os
import platform
import sys

sys.path.insert(0, {root!r})

import pytest

from capability_gate import Gate, Verdict, load_policy

POSIX = os.name == "posix"


@pytest.fixture()
def gate(tmp_path):
    policy = load_policy(
        {{"skills": {{"writer": {{"tools": ["read_file"], "paths": [str(tmp_path) + "/work/**"]}}}}}}
    )
    return Gate(policy, log_path=str(tmp_path / "decisions.jsonl"))


@pytest.fixture()
def decision(gate, tmp_path):
    return gate.evaluate("writer", "read_file", [str(tmp_path / "outside.txt")])


def _attempt(gate, tmp_path, name="outside.txt"):
    return gate.evaluate("writer", "read_file", [str(tmp_path / name)])


def _assert_denied(d):
    assert d.verdict is Verdict.DENY

"""

CORPUS = {
    "flag_set_in_handler": """
def test_k(gate, tmp_path):
    denied = False
    try:
        d = _attempt(gate, tmp_path)
        if d.verdict is Verdict.DENY:
            raise PermissionError(d.reason)
    except PermissionError:
        denied = True
    assert denied
""",
    "flag_set_in_branch": """
def test_k(gate, tmp_path):
    denied = False
    if _attempt(gate, tmp_path).verdict is Verdict.DENY:
        denied = True
    assert denied
""",
    "counter": """
def test_k(gate, tmp_path):
    denied = 0
    for name in ("a.txt", "b.txt"):
        if gate.evaluate("writer", "read_file", [str(tmp_path / name)]).verdict is Verdict.DENY:
            denied += 1
    assert denied == 2
""",
    "list_append": """
def test_k(gate, tmp_path):
    seen = []
    for name in ("a.txt", "b.txt"):
        seen.append(_attempt(gate, tmp_path, name).verdict)
    assert seen == [Verdict.DENY, Verdict.DENY]
""",
    "platform_only_imperative_skip": """
def test_k(gate, tmp_path):
    if sys.platform == "win32":
        pytest.skip("POSIX path shapes only")
    assert _attempt(gate, tmp_path).verdict is Verdict.DENY
""",
    "platform_only_skipif": """
@pytest.mark.skipif(not POSIX, reason="POSIX only")
def test_k(gate, tmp_path):
    assert _attempt(gate, tmp_path).verdict is Verdict.DENY


@pytest.mark.skipif(platform.system() == "Windows", reason="POSIX only")
def test_k2(gate, tmp_path):
    assert _attempt(gate, tmp_path).verdict is Verdict.DENY


@pytest.mark.skipif("sys.platform == 'win32'", reason="POSIX only")
def test_k3(gate, tmp_path):
    assert _attempt(gate, tmp_path).verdict is Verdict.DENY
""",
    "helper_asserts": """
def test_k(gate, tmp_path):
    _assert_denied(_attempt(gate, tmp_path))


def test_k2(gate, tmp_path):
    d = gate.evaluate("writer", "read_file", [str(tmp_path / "x")])
    _assert_denied(d)
""",
    "fixture_returns_decision": """
def test_k(decision):
    assert decision.verdict is Verdict.DENY
""",
    "expected_exception_elsewhere": """
def test_k(gate, tmp_path):
    with pytest.raises(ValueError):
        int("not a number")
    assert _attempt(gate, tmp_path).verdict is Verdict.DENY
""",
    "all_over_a_generator": """
def test_k(gate, tmp_path):
    assert all(
        gate.evaluate("writer", "read_file", [str(tmp_path / n)]).verdict is Verdict.DENY
        for n in ("a.txt", "b.txt")
    )
""",
    "try_finally": """
def test_k(gate, tmp_path):
    try:
        d = _attempt(gate, tmp_path)
    finally:
        pass
    assert d.verdict is Verdict.DENY
""",
    "strict_xfail_reaching_the_gate": """
@pytest.mark.xfail(strict=True, raises=AssertionError, reason="pinned limit")
def test_k(gate, tmp_path):
    assert _attempt(gate, tmp_path).verdict is Verdict.ALLOW
""",
    "throw_then_evaluate": """
def test_k(gate, tmp_path):
    assert gate.throw("drill") is True
    d = gate.evaluate("writer", "read_file", [str(tmp_path / "work" / "a.txt")])
    assert d.verdict is Verdict.DENY
""",
    "walrus": """
def test_k(gate, tmp_path):
    assert (d := _attempt(gate, tmp_path)).verdict is Verdict.DENY
    assert d.reason
""",
    "comprehension": """
def test_k(gate, tmp_path):
    vs = [_attempt(gate, tmp_path, n).verdict for n in ("a.txt", "b.txt")]
    assert vs == [Verdict.DENY, Verdict.DENY]
""",
    "fault_injection_outside_the_gate": """
def test_k(gate, tmp_path, monkeypatch):
    def boom(_path):
        raise OSError("zqxwvk")

    monkeypatch.setattr(os, "lstat", boom)
    d = _attempt(gate, tmp_path)
    assert d.verdict is Verdict.DENY
""",
}


@pytest.mark.parametrize("shape", sorted(CORPUS))
def test_t14_legitimate_deny_shapes_are_clean_and_work(
    tmp_path: Path, shape: str
) -> None:
    path = _write(
        tmp_path,
        f"test_k_{shape}.py",
        CORPUS_HEAD.format(root=str(ROOT)) + CORPUS[shape],
    )
    r = _lint(path)
    assert r.returncode == 0, r.stdout
    run = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(path)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0, run.stdout + run.stderr


# ---------------------------------------------------------------------------
# Removal tests: one case per rule, table entry, and branch, so deleting any
# of them turns a test red. Rejected cases name the reason; clean cases must
# lint clean.


def _clean(tmp_path: Path, src: str, name: str = "test_k_case.py") -> None:
    r = _lint(_write(tmp_path, name, src))
    assert r.returncode == 0, r.stdout


HELPERS = "def _assert_denied(d):\n    assert d.verdict is Verdict.DENY\n"

REJECT_MORE = {
    # T9 folding: every operator and builtin the folder knows.
    "add": ("assert 1 + 1 == 0", "", "constant comparison"),
    "sub": ("assert 3 - 1 == 0", "", "constant comparison"),
    "mult": ("assert 2 * 2 == 0", "", "constant comparison"),
    "div": ("assert 3 / 2 == 0", "", "constant comparison"),
    "floordiv": ("assert 3 // 2 == 0", "", "constant comparison"),
    "mod": ("assert 3 % 2 == 0", "", "constant comparison"),
    "pow": ("assert 2 ** 2 == 0", "", "constant comparison"),
    "lshift": ("assert 1 << 1 == 0", "", "constant comparison"),
    "rshift": ("assert 4 >> 1 == 0", "", "constant comparison"),
    "bitor": ("assert (1 | 2) == 0", "", "constant comparison"),
    "bitxor": ("assert (1 ^ 3) == 0", "", "constant comparison"),
    "bitand": ("assert (3 & 1) == 0", "", "constant comparison"),
    "noteq": ("assert 1 != 1", "", "constant comparison"),
    "lt": ("assert 2 < 1", "", "constant comparison"),
    "lte": ("assert 2 <= 1", "", "constant comparison"),
    "gt": ("assert 1 > 2", "", "constant comparison"),
    "gte": ("assert 1 >= 2", "", "constant comparison"),
    "in": ("assert 0 in (1,)", "", "constant comparison"),
    "notin": ("assert 1 not in (1,)", "", "constant comparison"),
    "is_none": ("assert None is not None", "", "constant comparison"),
    "neg": ("assert -1 == 1", "", "constant comparison"),
    "pos": ("assert +1 == 2", "", "constant comparison"),
    "invert": ("assert ~0 == 0", "", "constant comparison"),
    "slice": ("assert [1][1:]", "", "assert False"),
    "dict_display": ("assert {1: 2}[1] == 3", "", "constant comparison"),
    "fstring_truthy": ("assert not f'zq{d}'", "", "assert False"),
    "list_of_unknown_truthy": ("assert not [d]", "", "assert False"),
    "set_unhashable": ("assert {[]}", "", "always raises"),
    "dict_unhashable": ("assert {[]: 1}", "", "always raises"),
    "ifexp_raises": ("assert (1 if 1 // 0 else 2)", "", "always raises"),
    "or_first_raises": ("assert (1 // 0) or d", "", "always raises"),
    "and_unknown_then_raises": ("assert d and 1 // 0", "", "assert False"),
    "compare_raises": ("assert 1 < 'a'", "", "always raises"),
    "unary_raises": ("assert -'a'", "", "always raises"),
    "key_error": ("{}['k']", "", "always raises"),
    "if_test_raises": ("if 1 // 0:\n    pass", "", "always raises"),
    "while_test_raises": ("while 1 // 0:\n    pass", "", "always raises"),
    "assign_raises": ("x = 1 // 0", "", "always raises"),
    "bool_of_lambda": ("assert not bool(lambda: 0)", "", "assert False"),
    "chained_assign": ("a = b = 0\nassert b", "", "assert False"),
    "outer_function_binding": (
        "flag = 0\n\ndef inner():\n    assert flag\n\ninner()",
        "",
        "assert False",
    ),
    "bindings_in_any_order": (
        "assert B == 3",
        "B = A + 1\nA = 1",
        "constant comparison",
    ),
    "pure_float": ("assert float(0)", "", "assert False"),
    "pure_str": ("assert str('')", "", "assert False"),
    "pure_abs": ("assert abs(0)", "", "assert False"),
    "pure_tuple": ("assert tuple()", "", "assert False"),
    "pure_list": ("assert list()", "", "assert False"),
    "pure_frozenset": ("assert frozenset()", "", "assert False"),
    "pure_dict": ("assert dict()", "", "assert False"),
    "pure_min": ("assert min([0])", "", "assert False"),
    "pure_max": ("assert max([0])", "", "assert False"),
    "pure_sum": ("assert sum([])", "", "assert False"),
    "pure_any": ("assert any([])", "", "assert False"),
    "pure_all": ("assert all([0])", "", "assert False"),
    "pure_sorted": ("assert sorted([])", "", "assert False"),
    "pure_repr": ("assert not repr(0)", "", "assert False"),
    "pure_ord": ("assert ord('0') == 0", "", "constant comparison"),
    "pure_chr": ("assert not chr(0)", "", "assert False"),
    "pure_round": ("assert round(0.2)", "", "assert False"),
    # A mutable literal folds while it is only read.
    "read_by_assert": ("items = []\nassert items", "", "assert False"),
    "read_by_compare": ("items = []\nassert items == [1]", "", "constant comparison"),
    "read_by_boolop": ("items = []\nassert items and d", "", "assert False"),
    "read_by_not": ("items = []\nassert not not items", "", "assert False"),
    "read_by_if": ("items = []\nif items:\n    pass\nassert items", "", "assert False"),
    "read_by_ifexp": ("items = []\nassert (1 if items else 0)", "", "assert False"),
    "read_by_while": (
        "items = []\nwhile items:\n    pass\nassert items",
        "",
        "assert False",
    ),
    "read_by_for": (
        "items = []\nfor x in items:\n    pass\nassert items",
        "",
        "assert False",
    ),
    "read_by_comprehension": (
        "items = []\n_ = [x for x in items]\nassert items",
        "",
        "assert False",
    ),
    "read_by_pure_call": ("items = []\nassert len(items)", "", "assert False"),
    # T11 spellings and tables.
    "globals_lookup": ("globals()['pytest'].fail('x')", "", "pytest.fail"),
    "locals_lookup": ("locals()['pytest'].fail('x')", "", "pytest.fail"),
    "vars_unknown_key": ("vars(pytest)[d.reason]('x')", "", "dynamic attribute"),
    "annotated_alias": ("pt.fail('x')", "pt: object = pytest", "pytest.fail"),
    "walrus_module_alias": ("(m := pytest)\nm.fail('x')", "", "pytest.fail"),
    "import_fromlist": (
        "__import__('_pytest.outcomes', fromlist=['fail']).fail('x')",
        "",
        "pytest.fail",
    ),
    "os_kill": ("os.kill(os.getpid(), 9)", "", "forced exit"),
    "raise_signal": (
        "signal.raise_signal(signal.SIGTERM)",
        "import signal",
        "forced exit",
    ),
    "runpy_module": ("runpy.run_module('zqxwvk')", "import runpy", "dynamic code"),
    "exec": ("exec('x = 1')", "", "dynamic code"),
    "raise_keyboard_interrupt": ("raise KeyboardInterrupt", "", "forced exit"),
    "store_to_fail": ("pytest.fail = None", "", "pytest.fail"),
    # T10 tables.
    "unittest_skipif": ("", "import unittest", "unittest.skipIf"),
    "unittest_skipunless": ("", "import unittest", "unittest.skipUnless"),
    "unittest_expected_failure": ("", "import unittest", "unittest.expectedFailure"),
    "skiptest_call": (
        "tc.skipTest('x')",
        "import unittest\n\ntc = unittest.TestCase()",
        "self.skipTest",
    ),
}
_DECO = {
    "unittest_skipif": "@unittest.skipIf(True, 'x')",
    "unittest_skipunless": "@unittest.skipUnless(False, 'x')",
    "unittest_expected_failure": "@unittest.expectedFailure",
}


@pytest.mark.parametrize("shape", sorted(REJECT_MORE))
def test_each_rule_rejects_its_form(tmp_path: Path, shape: str) -> None:
    body, prelude, reason = REJECT_MORE[shape]
    _expect(tmp_path, _kat(body, prelude, deco=_DECO.get(shape, "")), reason)


@pytest.mark.parametrize(
    "module",
    [
        "pytest",
        "_pytest.outcomes",
        "sys",
        "os",
        "builtins",
        "importlib",
        "runpy",
        "unittest",
        "signal",
    ],
)
def test_unknown_attribute_on_a_watched_module(tmp_path: Path, module: str) -> None:
    src = _kat("getattr(watched, d.reason)", f"import {module} as watched")
    _expect(tmp_path, src, "dynamic attribute")


@pytest.mark.parametrize(
    "import_line, body, reason",
    [
        ("from _pytest.outcomes import exit as e", "e('x')", "pytest.exit"),
        ("from _pytest.outcomes import skip as s", "s('x')", "pytest.skip"),
        ("from _pytest.outcomes import xfail as x", "x('x')", "pytest.xfail"),
        (
            "from _pytest.outcomes import importorskip as i",
            "i('zqxwvk')",
            "pytest.importorskip",
        ),
        ("from _pytest.outcomes import Failed", "raise Failed('x')", "pytest.fail"),
        (
            "from _pytest.outcomes import OutcomeException",
            "raise OutcomeException('x')",
            "pytest.fail",
        ),
        ("from _pytest.outcomes import Skipped", "raise Skipped('x')", "pytest.skip"),
        ("from _pytest.outcomes import XFailed", "raise XFailed('x')", "pytest.xfail"),
        ("from _pytest.outcomes import Exit", "raise Exit('x')", "pytest.exit"),
        (
            "from unittest.case import SkipTest",
            "raise SkipTest('x')",
            "unittest.SkipTest",
        ),
    ],
)
def test_internal_spellings_of_outcomes(
    tmp_path: Path, import_line: str, body: str, reason: str
) -> None:
    _expect(tmp_path, _kat(body, import_line), reason)


@pytest.mark.parametrize(
    "import_line, deco, reason",
    [
        ("from unittest.case import skip", "@skip('x')", "unittest.skip"),
        ("from unittest.case import skipIf", "@skipIf(True, 'x')", "unittest.skipIf"),
        (
            "from unittest.case import skipUnless",
            "@skipUnless(False, 'x')",
            "unittest.skipUnless",
        ),
        (
            "from unittest.case import expectedFailure",
            "@expectedFailure",
            "unittest.expectedFailure",
        ),
    ],
)
def test_internal_spellings_of_unittest_marks(
    tmp_path: Path, import_line: str, deco: str, reason: str
) -> None:
    _expect(tmp_path, _kat("", import_line, deco=deco), reason)


T10_MORE_ANY = {
    "unparseable_condition": (
        _deco_test("@pytest.mark.skipif('(', reason='x')"),
        "does not parse",
    ),
    "raising_condition": (
        _deco_test("@pytest.mark.skipif(1 // 0, reason='x')"),
        "always raises",
    ),
    "xfail_condition_no_platform": (
        _deco_test(
            "@pytest.mark.xfail(sys.platform == 'zqxwvk', strict=True, reason='x')",
            "import sys",
            "assert 0",
        ),
        "no platform has",
    ),
    "os_name_no_such_value": (
        _deco_test("@pytest.mark.skipif(os.name == 'zqxwvk', reason='x')", "import os"),
        "no platform has",
    ),
    "platform_system_no_such_value": (
        _deco_test(
            "@pytest.mark.skipif(platform.system() == 'zqxwvk', reason='x')",
            "import platform",
        ),
        "no platform has",
    ),
    "platform_in_no_such_value": (
        _deco_test(
            "@pytest.mark.skipif(sys.platform in ('win32', 'zqxwvk'), reason='x')",
            "import sys",
        ),
        "no platform has",
    ),
    "startswith_no_such_prefix": (
        _deco_test(
            "@pytest.mark.skipif(sys.platform.startswith('zqxwvk'), reason='x')",
            "import sys",
        ),
        "no platform has",
    ),
    "pytest_exit_in_test": ("def test_a():\n    pytest.exit('x')\n", "pytest.exit"),
}


@pytest.mark.parametrize("shape", sorted(T10_MORE_ANY))
def test_more_forms_rejected_in_any_test_file(tmp_path: Path, shape: str) -> None:
    src, reason = T10_MORE_ANY[shape]
    _write(tmp_path, "test_ordinary.py", "import pytest\n" + src)
    r = _lint("--root", tmp_path)
    assert r.returncode == 1, r.stdout
    assert reason in r.stdout, r.stdout


@pytest.mark.parametrize(
    "condition, imports",
    [
        ("sys.platform == 'win32'", "import sys"),
        ("os.name == 'nt'", "import os"),
        ("sys.version_info < (3, 9)", "import sys"),
        ("platform.system() == 'Windows'", "import platform"),
        ("sys.platform == 'win32' or os.name == 'nt'", "import os\nimport sys"),
        ("sys.platform in ('win32', 'cygwin')", "import sys"),
        ("sys.version_info[0] < 3", "import sys"),
        ("sys.platform.startswith('win')", "import sys"),
    ],
    ids=[
        "platform",
        "os-name",
        "version",
        "platform-system",
        "or",
        "in-tuple",
        "subscript",
        "startswith",
    ],
)
def test_platform_only_skipif_is_clean_in_a_kat(
    tmp_path: Path, condition: str, imports: str
) -> None:
    _clean(
        tmp_path,
        _kat("", imports, deco=f"@pytest.mark.skipif({condition}, reason='x')"),
    )


def test_a_cyclic_alias_does_not_crash_the_lint(tmp_path: Path) -> None:
    src = "import pytest\n\nX = Y\nY = X\n\n\n@pytest.mark.skipif(X, reason='x')\ndef test_a():\n    a = b\n    b = a\n    a()\n"
    _write(tmp_path, "test_ordinary.py", src)
    r = _lint("--root", tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr


def test_a_deep_expression_is_not_folded(tmp_path: Path) -> None:
    _clean(tmp_path, _kat("x = " + "not " * 60 + "False\nassert x"))


def test_fold_limits_stop_large_values() -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("kat_lint_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod._LIMIT = 10
    tree = ast.parse(
        "a = 'x' * 3 + 'x' * 9\nb = 2 ** 300\nc = 1 << 5000\nd = 'ab' * 6\n"
        "e = str(10 ** 20)\nf = sum([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])\ng = 'x' * 4\n"
    )
    folder = mod.Folder(tree)
    env = folder.env(tree)
    assert set(env) == {"g"}, env


CLEAN = {
    "keywords_are_not_folded": ("assert int('10', base=2) == 2", ""),
    "shadowed_builtin_is_not_folded": ("assert len([])", "def len(x):\n    return 1"),
    "local_rebinding_shadows_module": (
        "NO = d.verdict is Verdict.DENY\nassert NO",
        "NO = False",
    ),
    "starred_target": ("first, *REST = (1, 2)\nassert REST", "REST = 0"),
    "for_rebinds": ("for X in (1,):\n    pass\nassert X", "X = 0"),
    "with_rebinds": (
        "with contextlib.nullcontext(1) as X:\n    pass\nassert X",
        "X = 0",
    ),
    "except_rebinds": (
        "try:\n    pass\nexcept ValueError as X:\n    pass\nassert X",
        "X = 0",
    ),
    "import_rebinds": ("import os as X\nassert X", "X = 0"),
    "def_rebinds": ("def X():\n    pass\n\nassert X", "X = 0"),
    "class_rebinds": ("class X:\n    pass\n\nassert X", "X = 0"),
    "del_rebinds": ("del X\nassert X", "X = 0"),
    "global_rebinds": ("global X\nX = 1\nassert X", "X = 0"),
    "augmented_rebinds": ("X += 1\nassert X", "X = 0"),
    "walrus_rebinds": ("assert (X := d)", "X = 0"),
    "match_rebinds": ("match d:\n    case X:\n        pass\nassert X", "X = 0"),
    "match_star_rebinds": (
        "match []:\n    case [*X]:\n        pass\nassert X",
        "X = 0",
    ),
    "match_rest_rebinds": (
        "match {}:\n    case {**X}:\n        pass\nassert X",
        "X = 0",
    ),
    "parameter_named_like_a_builtin": ("exit()", "", "gate, exit"),
    "loop_variable_named_like_a_builtin": (
        "for exit in (print,):\n    exit('zqxwvk')",
        "",
    ),
    "unknown_attribute_elsewhere": ("getattr(d, d.reason)", ""),
    "platform_skip_inside_kat": (
        "if sys.platform == 'zqxwvk':\n    pytest.skip('x')",
        "",
    ),
    # A loop over a value the lint cannot see may not run; over a non-empty
    # constant it always runs (rejected, see the review round tests).
    "raise_in_loop": ("for _ in d:\n    raise ValueError('zqxwvk')", ""),
    "raise_in_while": ("while d is None:\n    raise ValueError('zqxwvk')", ""),
    "raise_in_handler": (
        "try:\n    pass\nexcept OSError:\n    raise ValueError('zqxwvk')",
        "",
    ),
    "raise_expected": (
        "with pytest.raises(ValueError):\n    raise ValueError('zqxwvk')",
        "",
    ),
    "raise_in_match": (
        "match d:\n    case None:\n        raise ValueError('zqxwvk')",
        "",
    ),
    "raise_under_false_branch": ("if False:\n    raise ValueError('zqxwvk')", ""),
    "fixture_autouse_false_not_applied": (
        "",
        "@pytest.fixture(autouse=False)\ndef _swap(monkeypatch):\n"
        "    monkeypatch.setattr(Gate, 'evaluate', lambda *a, **k: None)",
    ),
}


@pytest.mark.parametrize("shape", sorted(CLEAN))
def test_each_allowed_form_stays_clean(tmp_path: Path, shape: str) -> None:
    body, prelude, *params = CLEAN[shape]
    _clean(tmp_path, _kat(body, prelude, params=params[0] if params else "gate"))


@pytest.mark.parametrize(
    "body",
    [
        "raise ValueError('zqxwvk')",
        "if True:\n    raise ValueError('zqxwvk')",
        "try:\n    raise ValueError('zqxwvk')\nfinally:\n    pass",
    ],
    ids=["plain", "true-branch", "try-finally"],
)
def test_an_unconditional_raise_is_fiat(tmp_path: Path, body: str) -> None:
    _expect(tmp_path, _kat(body), "forced failure")


def test_the_problem_count_has_no_duplicates(tmp_path: Path) -> None:
    body = "\ndef test_k_exit(gate):\n    gate.evaluate('s', 'read_file', ['zqxwvk'])\n    sys.exit(1)\n"
    r = _lint(_write(tmp_path, "test_k_exit.py", KAT_HEAD + body))
    assert "kat lint: 3 problem(s)" in r.stdout, r.stdout


# T12: more receivers that are not the gate, and patch forms.
T12_MORE = {
    "relative_import": (
        "import pytest\n\nfrom .capability_gate import Gate, Verdict, load_policy\n\n\n"
        + "def test_k(tmp_path):\n"
        + f"    g = Gate({POLICY})\n"
        + ASSERT_DENY
    ),
    "rebound_gate_name": (
        REAL_IMPORTS
        + "def test_k(tmp_path):\n"
        + f"    g = Gate({POLICY})\n"
        + "    g = object()\n"
        + ASSERT_DENY
    ),
    "rebound_helper": (
        KAT_HEAD
        + "def _attempt(gate):\n    return gate.evaluate('s', 'read_file', ['zqxwvk'])\n\n\n"
        + "_attempt = print\n\n\n"
        + "def test_k(gate):\n    assert _attempt(gate).verdict is Verdict.DENY\n"
    ),
    "helper_given_something_else": (
        KAT_HEAD
        + "def _attempt(g):\n    return g.evaluate('s', 'read_file', ['zqxwvk'])\n\n\n"
        + "def test_k(gate):\n    assert _attempt(object()).verdict is Verdict.DENY\n"
    ),
    "while_body": (
        KAT_HEAD
        + "def test_k(gate):\n    n = 0\n    while n < 1:\n"
        + "        d = gate.evaluate('s', 'read_file', ['zqxwvk'])\n        n += 1\n"
        + "    assert d.verdict is Verdict.DENY\n"
    ),
    "dead_short_circuit": (
        KAT_HEAD
        + "RUN = False\n\n\ndef test_k(gate):\n"
        + "    d = RUN and gate.evaluate('s', 'read_file', ['zqxwvk'])\n"
        + "    assert d.verdict is Verdict.DENY\n"
    ),
    "assert_raises_context": (
        KAT_HEAD
        + "import unittest\n\n\ndef test_k(gate):\n    tc = unittest.TestCase()\n"
        + "    with tc.assertRaises(Exception):\n    "
        + GATE_CALL_ASSERT
    ),
}


@pytest.mark.parametrize("shape", sorted(T12_MORE))
def test_t12_more_receivers_that_are_not_the_gate(tmp_path: Path, shape: str) -> None:
    _expect(tmp_path, T12_MORE[shape], "never reaches the gate", "test_k_recv.py")


def test_t12_an_adapters_folder_beside_the_test_is_not_the_gate(tmp_path: Path) -> None:
    (tmp_path / "tests" / "adapters").mkdir(parents=True)
    src = (
        "from adapters.claude_code_hook import _pre\n\n\n"
        "def test_k():\n    assert _pre({'tool_name': 'Read'}) is None\n"
    )
    _expect(tmp_path, src, "never reaches the gate", "test_k_shadow.py")


@pytest.mark.parametrize(
    "imports, call",
    [
        (
            "from capability_gate import open_authorized_read",
            "open_authorized_read('zqxwvk')",
        ),
        ("from adapters.claude_code_hook import _pre", "_pre({'tool_name': 'Read'})"),
        ("import adapters.claude_code_hook as hook", "hook.main()"),
        (
            "from adapters.agentdojo_adapter import pre_tool_call",
            "pre_tool_call('read_file', {})",
        ),
    ],
    ids=["open-authorized-read", "hook-pre", "hook-main", "agentdojo"],
)
def test_t12_real_gate_functions_count(tmp_path: Path, imports: str, call: str) -> None:
    _clean(
        tmp_path,
        f"{imports}\n\n\ndef test_k():\n    r = {call}\n    assert r is None\n",
    )


@pytest.mark.parametrize("func", ["run", "call", "check_call", "check_output", "Popen"])
def test_t12_the_real_hook_script_counts(tmp_path: Path, func: str) -> None:
    src = (
        "import subprocess\nimport sys\n\n\n"
        "def test_k():\n"
        f"    r = subprocess.{func}([sys.executable, 'adapters/claude_code_hook.py'])\n"
        "    assert r\n"
    )
    _clean(tmp_path, src)


def test_t12_the_real_hook_script_by_path_parts_counts(tmp_path: Path) -> None:
    src = (
        "import subprocess\nimport sys\nfrom pathlib import Path\n\nROOT = Path('.')\n\n\n"
        "def test_k():\n"
        "    r = subprocess.run([sys.executable, str(ROOT / 'adapters' / 'claude_code_hook.py')])\n"
        "    assert r.returncode == 2\n"
    )
    _clean(tmp_path, src)


T12_PATCHED_MORE = {
    "delattr": ("monkeypatch.delattr(Gate, 'evaluate')", "", "gate, monkeypatch"),
    "builtin_setattr": ("setattr(gate, 'evaluate', print)", "", "gate"),
    "patch_multiple": (
        "mock.patch.multiple(Gate, evaluate=print).start()",
        "from unittest import mock",
        "gate",
    ),
    "patch_string": (
        "mock.patch('capability_gate.Gate.evaluate').start()",
        "from unittest import mock",
        "gate",
    ),
    "module_class_swap": (
        "monkeypatch.setattr(capability_gate, 'Gate', object)",
        "import capability_gate",
        "gate, monkeypatch",
    ),
    "module_unknown_attribute": (
        "monkeypatch.setattr(capability_gate, d0, object)",
        "import capability_gate\n\nd0 = str(object())",
        "gate, monkeypatch",
    ),
    "assign_module_attribute": (
        "capability_gate.Gate = object",
        "import capability_gate",
        "gate",
    ),
    "delete_method": ("del gate.evaluate", "", "gate"),
    "fixture_taken": (
        "",
        "@pytest.fixture()\ndef swap(monkeypatch):\n"
        "    monkeypatch.setattr(Gate, 'evaluate', lambda *a, **k: None)",
        "gate, swap",
    ),
    "helper_called": (
        "_swap()",
        "def _swap():\n    Gate.evaluate = lambda *a, **k: None",
        "gate",
    ),
}


@pytest.mark.parametrize("shape", sorted(T12_PATCHED_MORE))
def test_t12_more_patch_forms(tmp_path: Path, shape: str) -> None:
    body, prelude, params = T12_PATCHED_MORE[shape]
    src = _kat("", prelude, params=params)
    if body:
        src = src.replace(
            "    d = gate.evaluate", f"    {body}\n    d = gate.evaluate", 1
        )
    _expect(tmp_path, src, "patches the gate")


# T13: more shapes that never assert on the result.
T13_MORE = {
    "assert_in_empty_loop": BOUND
    + "    for _ in ():\n        assert d.verdict is Verdict.DENY\n"
    + OTHER,
    "assert_in_while_false": BOUND
    + "    while False:\n        assert d.verdict is Verdict.DENY\n"
    + OTHER,
    "assert_inside_raises": (
        BOUND
        + "    with pytest.raises(Exception):\n        assert d.verdict is Verdict.DENY\n"
        + OTHER
    ),
    "helper_in_dead_branch": BOUND
    + "    if False:\n        _assert_denied(d)\n"
    + OTHER,
    "helper_in_dead_while": BOUND
    + "    while False:\n        _assert_denied(d)\n"
    + OTHER,
    "helper_in_empty_loop": BOUND
    + "    for _ in ():\n        _assert_denied(d)\n"
    + OTHER,
    "helper_in_raises": BOUND
    + "    with pytest.raises(Exception):\n        _assert_denied(d)\n"
    + OTHER,
    "helper_in_dead_try": (
        BOUND
        + "    try:\n        if False:\n            _assert_denied(d)\n    finally:\n        pass\n"
        + OTHER
    ),
    "helper_in_dead_match": (
        BOUND
        + "    match d:\n        case _:\n            if False:\n                _assert_denied(d)\n"
        + OTHER
    ),
    "flag_set_in_finally": (
        "    denied = False\n    try:\n        d = gate.evaluate('s', 'read_file', ['zqxwvk'])\n"
        "    finally:\n        denied = True\n    assert denied\n"
    ),
    "flag_set_in_while": (
        "    denied = False\n    while gate.evaluate('s', 'read_file', ['zqxwvk']) is None:\n"
        "        denied = True\n    assert denied\n"
    ),
}


def test_t13_rebound_assert_helper_does_not_count(tmp_path: Path) -> None:
    src = (
        KAT_HEAD
        + HELPERS
        + "\n\n_assert_denied = print\n\n\ndef test_k(gate, tmp_path):\n"
        + BOUND
        + "    _assert_denied(d)\n"
        + OTHER
    )
    _expect(tmp_path, src, "never asserts on the gate's result", "test_k_unused.py")


@pytest.mark.parametrize("shape", sorted(T13_MORE))
def test_t13_more_shapes_without_a_result_assert(tmp_path: Path, shape: str) -> None:
    src = KAT_HEAD + HELPERS + "\n\ndef test_k(gate, tmp_path):\n" + T13_MORE[shape]
    _expect(tmp_path, src, "never asserts on the gate's result", "test_k_unused.py")


CORPUS_MORE = {
    "global_flag_set_by_helper": """
FLAG = False


def _mark(d):
    global FLAG
    FLAG = d.verdict is Verdict.DENY


def test_k(gate, tmp_path):
    d = _attempt(gate, tmp_path)
    _mark(d)
    assert d.verdict is Verdict.DENY
    assert FLAG
""",
    "nested_append": """
def test_k(gate, tmp_path):
    seen = []

    def note(v):
        seen.append(v)

    d = _attempt(gate, tmp_path)
    note(d.verdict)
    assert d.verdict is Verdict.DENY
    assert seen == [Verdict.DENY]
""",
    "match_case": """
def test_k(gate, tmp_path):
    denied = False
    match _attempt(gate, tmp_path).verdict:
        case Verdict.DENY:
            denied = True
    assert denied
""",
    "with_head": """
import contextlib


def test_k(gate, tmp_path):
    with contextlib.nullcontext(_attempt(gate, tmp_path)) as d:
        assert d.verdict is Verdict.DENY
""",
    "for_over_results": """
def test_k(gate, tmp_path):
    for v in [_attempt(gate, tmp_path).verdict]:
        assert v is Verdict.DENY
""",
    "class_method_helper": """
class TestK:
    def _try(self, gate, tmp_path):
        return gate.evaluate("writer", "read_file", [str(tmp_path / "x")])

    def test_k(self, gate, tmp_path):
        assert self._try(gate, tmp_path).verdict is Verdict.DENY
""",
    "keyword_arguments": """
def test_k(gate, tmp_path):
    d = _attempt(gate=gate, tmp_path=tmp_path)
    _assert_denied(d=d)
""",
    "helper_builds_gate": """
def _make(tmp_path):
    return Gate(load_policy({"skills": {}}), log_path=str(tmp_path / "m.jsonl"))


def test_k(tmp_path):
    g = _make(tmp_path)
    assert g.evaluate("s", "read_file", ["zqxwvk"]).verdict is Verdict.DENY
""",
    "helper_calls_gate_and_asserts": """
def _expect_deny(gate, tmp_path):
    assert gate.evaluate("writer", "read_file", [str(tmp_path / "x")]).verdict is Verdict.DENY


def test_k(gate, tmp_path):
    _expect_deny(gate, tmp_path)
""",
    "ternary_gate_call": """
def test_k(gate, tmp_path):
    d = _attempt(gate, tmp_path) if POSIX or not POSIX else None
    assert d.verdict is Verdict.DENY
""",
    "dict_comprehension": """
def test_k(gate, tmp_path):
    vs = {n: _attempt(gate, tmp_path, n).verdict for n in ("a.txt",)}
    assert vs == {"a.txt": Verdict.DENY}
""",
    "comprehension_filter": """
def test_k(gate, tmp_path):
    names = ("a.txt", "b.txt")
    denied = [n for n in names if _attempt(gate, tmp_path, n).verdict is Verdict.DENY]
    assert denied == ["a.txt", "b.txt"]
""",
    "nested_comprehension": """
def test_k(gate, tmp_path):
    vs = [v for n in ("a.txt",) for v in [_attempt(gate, tmp_path, n).verdict]]
    assert vs == [Verdict.DENY]
""",
    "annotated_result": """
def test_k(gate, tmp_path):
    d: object = _attempt(gate, tmp_path)
    assert d.verdict is Verdict.DENY
""",
    "augmented_result": """
def test_k(gate, tmp_path):
    total = 0
    total += int(_attempt(gate, tmp_path).verdict is Verdict.DENY)
    assert total == 1
""",
    "walrus_in_if": """
def test_k(gate, tmp_path):
    if (d := _attempt(gate, tmp_path)) is None:
        return
    assert d.verdict is Verdict.DENY
""",
    "flag_in_try_else": """
def test_k(gate, tmp_path):
    answered = False
    try:
        _attempt(gate, tmp_path)
    except OSError:
        pass
    else:
        answered = True
    assert answered
""",
}


@pytest.mark.parametrize("shape", sorted(CORPUS_MORE))
def test_t14_more_legitimate_shapes(tmp_path: Path, shape: str) -> None:
    path = _write(
        tmp_path,
        f"test_k_{shape}.py",
        CORPUS_HEAD.format(root=str(ROOT)) + CORPUS_MORE[shape],
    )
    r = _lint(path)
    assert r.returncode == 0, r.stdout
    run = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(path)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0, run.stdout + run.stderr


_REAL_PLATFORMS = (
    [
        ("sys.platform", "import sys", v)
        for v in (
            "win32",
            "cygwin",
            "msys",
            "linux",
            "darwin",
            "aix",
            "freebsd",
            "openbsd",
            "netbsd",
            "sunos5",
            "emscripten",
            "wasi",
            "ios",
            "android",
        )
    ]
    + [("os.name", "import os", v) for v in ("posix", "nt", "java")]
    + [
        ("platform.system()", "import platform", v)
        for v in ("Windows", "Linux", "Darwin", "Java", "FreeBSD", "OpenBSD", "AIX")
    ]
)


@pytest.mark.parametrize("atom, imports, value", _REAL_PLATFORMS)
def test_every_real_platform_value_is_accepted(
    tmp_path: Path, atom: str, imports: str, value: str
) -> None:
    src = _deco_test(f"@pytest.mark.skipif({atom} == {value!r}, reason='x')", imports)
    _write(tmp_path, "test_ordinary.py", "import pytest\n" + src)
    r = _lint("--root", tmp_path)
    assert r.returncode == 0, r.stdout


# Round two of removal tests, from the mutation survivors.
REJECT_MORE_2 = {
    "nested_def_binding_does_not_count": (
        "def inner():\n    X = 1\n    return X\n\nassert X",
        "X = 0",
        "assert False",
    ),
    "list_element_raises": ("assert [1 // 0]", "", "always raises"),
    "dict_value_raises": ("assert {1: 1 // 0}", "", "always raises"),
    "binop_left_raises": ("assert (1 // 0) + 1", "", "always raises"),
    "binop_right_raises": ("assert 1 + (1 // 0)", "", "always raises"),
    "subscript_value_raises": ("assert (1 // 0)[0]", "", "always raises"),
    "subscript_index_raises": ("assert [1][1 // 0]", "", "always raises"),
    "compare_left_raises": ("assert (1 // 0) == 1", "", "always raises"),
    "compare_right_raises": ("assert 1 == 1 // 0", "", "always raises"),
    "chain_unknown_then_false": ("assert d.n < 1 < 0", "", "constant comparison"),
    "false_chain_value": (
        "x = 1 < 0 < 2\nassert x is False",
        "",
        "constant comparison",
    ),
    "call_arg_raises": ("assert bool(1 // 0)", "", "always raises"),
    "raise_assertion_error_in_helper": (
        "_bad()",
        "def _bad():\n    raise AssertionError('x')",
        "raise AssertionError",
    ),
    "raise_skiptest_in_helper": (
        "_s()",
        "import unittest\n\n\ndef _s():\n    raise unittest.SkipTest",
        "unittest.SkipTest",
    ),
    "assert_in_def_inside_raises": (
        "with pytest.raises(ZeroDivisionError):\n\n    def inner():\n        assert 0\n\n    1 // 0",
        "",
        "assert False",
    ),
    "bindings_reverse_order": (
        "assert B == 3",
        "A = 1\nB = A + 1",
        "constant comparison",
    ),
}


@pytest.mark.parametrize("shape", sorted(REJECT_MORE_2))
def test_each_rule_rejects_its_form_2(tmp_path: Path, shape: str) -> None:
    body, prelude, reason = REJECT_MORE_2[shape]
    _expect(tmp_path, _kat(body, prelude), reason)


CLEAN_2 = {
    "parameter_shadows_module": ("assert X", "X = 0", "gate, X"),
    "walrus_statement_rebinds": ("(X := d)\nassert X", "X = 0"),
    "assigned_builtin": ("assert bool(0)", "bool = str"),
    "imported_builtin_name": ("assert bool(0)", "from os.path import exists as bool"),
    "builtin_named_parameter": ("assert bool(0)", "", "gate, bool"),
    "starred_list_may_be_empty": ("assert [*d.reason]", ""),
    "list_with_unknown_compares_unknown": ("assert [d] != [None]", ""),
    "dict_unpack_may_be_empty": ("assert {**vars(d)}", ""),
    "dict_unknown_compares_unknown": ("assert {1: d} != {1: None}", ""),
    "negating_partial_knowledge": ("assert -(0 if d else 0) == 0", ""),
    "arithmetic_on_partial_knowledge": ("assert (0 if d else 0) + 1 == 1", ""),
    "subscript_of_partial_knowledge": ("assert [d][0] is not None", ""),
    "slice_with_unknown_bound": ("assert [1, 2][len(d.reason) :]", ""),
    "or_with_unknown_side": ("assert d or 0", ""),
    "len_of_partial_knowledge": ("assert len([d]) == 1", ""),
    "dunder_import_returns_the_top_package": (
        "x = __import__('_pytest.outcomes').fail",
        "",
    ),
    "out_of_range_index": ("y = [d][5] if d is None else d", ""),
    "with_a_name": ("lock = contextlib.nullcontext()\nwith lock:\n    pass", ""),
    "recursive_helper": (
        "assert _r(2) == 0",
        "def _r(n):\n    return 0 if n <= 0 else _r(n - 1)",
    ),
    "patch_other_module_attr": (
        "monkeypatch.setattr(capability_gate, '_zqxwvk', print)",
        "import capability_gate",
        "gate, monkeypatch",
    ),
    "shadowed_len_mutates": (
        "items = []\nlen(items)\nassert items",
        "def len(x):\n    x.append(1)\n    return 1",
    ),
    "tuple_holding_a_list_can_change": (
        "box = ([],)\nbox[0].append(d)\nassert len(box[0]) == 1",
        "",
    ),
    "raise_caught": (
        "try:\n    raise ValueError('zqxwvk')\nexcept ValueError:\n    pass",
        "",
    ),
}


@pytest.mark.parametrize("shape", sorted(CLEAN_2))
def test_each_allowed_form_stays_clean_2(tmp_path: Path, shape: str) -> None:
    body, prelude, *params = CLEAN_2[shape]
    _clean(tmp_path, _kat(body, prelude, params=params[0] if params else "gate"))


EVAL = "gate.evaluate('s', 'read_file', ['zqxwvk'])"
VERDICT = "    assert d.verdict is Verdict.DENY\n"
DECISION_FIXTURE = f"@pytest.fixture()\ndef decision(gate):\n    return {EVAL}\n\n\n"
REACH_CLEAN = {
    "true_ternary": f"    d = {EVAL} if True else None\n" + VERDICT,
    "false_ternary_else": f"    d = None if False else {EVAL}\n" + VERDICT,
    "constant_true_if": f"    if True:\n        d = {EVAL}\n" + VERDICT,
    "with_body": f"    with contextlib.nullcontext():\n        d = {EVAL}\n" + VERDICT,
    "assert_inside_branch": f"    d = {EVAL}\n    if d is not None:\n    " + VERDICT,
    "assert_in_true_branch": f"    d = {EVAL}\n    if True:\n    " + VERDICT,
    "assert_in_else": f"    d = {EVAL}\n    if False:\n        pass\n    else:\n    "
    + VERDICT,
    "assert_in_while": (
        f"    d = {EVAL}\n    n = 0\n    while n < 1:\n    "
        + VERDICT
        + "        n += 1\n"
    ),
    "assert_in_try": f"    d = {EVAL}\n    try:\n    "
    + VERDICT
    + "    finally:\n        pass\n",
    "assert_in_match": f"    d = {EVAL}\n    match d:\n        case _:\n        "
    + VERDICT,
}


@pytest.mark.parametrize("shape", sorted(REACH_CLEAN))
def test_reach_and_result_in_every_live_position(tmp_path: Path, shape: str) -> None:
    _clean(tmp_path, KAT_HEAD + "def test_k(gate):\n" + REACH_CLEAN[shape])


def test_cyclic_fixtures_do_not_crash_the_lint(tmp_path: Path) -> None:
    src = (
        KAT_HEAD
        + "@pytest.fixture()\ndef a(b):\n    return b\n\n\n"
        + "@pytest.fixture()\ndef b(a):\n    return a\n\n\n"
        + f"def test_k(gate, a):\n    assert {EVAL} is not None\n"
    )
    _clean(tmp_path, src)


def test_module_xfail_with_raises_is_not_judged_as_a_test(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "test_ordinary.py",
        "import pytest\n\npytestmark = pytest.mark.xfail(raises=ValueError)\n\n\n"
        "def test_a():\n    raise ValueError('zqxwvk')\n",
    )
    r = _lint("--root", tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr


T12_MORE_2 = {
    "dead_ternary": (
        KAT_HEAD + f"def test_k(gate):\n    d = {EVAL} if False else None\n" + VERDICT
    ),
    "uncalled_lambda": (
        KAT_HEAD
        + f"def test_k(gate):\n    later = lambda: {EVAL}\n    assert later is not None\n"
    ),
    "hook_path_not_run": (
        "def test_k():\n    r = print('adapters/claude_code_hook.py')\n    assert r is None\n"
    ),
    "helper_param_named_gate_given_something_else": (
        KAT_HEAD
        + f"def _attempt(gate):\n    return {EVAL}\n\n\n"
        + "def test_k(gate):\n    assert _attempt(object()).verdict is Verdict.DENY\n"
    ),
    "helper_param_named_after_a_fixture": (
        KAT_HEAD
        + DECISION_FIXTURE
        + "def _h(decision):\n    return 1\n\n\n"
        + "def test_k():\n    assert _h(None) == 1\n"
    ),
}


@pytest.mark.parametrize("shape", sorted(T12_MORE_2))
def test_t12_more_receivers_that_are_not_the_gate_2(tmp_path: Path, shape: str) -> None:
    _expect(tmp_path, T12_MORE_2[shape], "never reaches the gate", "test_k_recv.py")


T13_MORE_2 = {
    "assert_after_return": BOUND + "    return\n    assert d.verdict is Verdict.DENY\n",
    "lambda_holding_result": BOUND
    + "    check = lambda: d.verdict\n    assert check is not None\n",
}


@pytest.mark.parametrize("shape", sorted(T13_MORE_2))
def test_t13_more_shapes_without_a_result_assert_2(tmp_path: Path, shape: str) -> None:
    src = KAT_HEAD + "def test_k(gate, tmp_path):\n" + T13_MORE_2[shape]
    _expect(tmp_path, src, "never asserts on the gate's result", "test_k_unused.py")


def test_a_gate_module_at_the_root_is_the_real_one(tmp_path: Path) -> None:
    (tmp_path / "capability_gate.py").write_text(
        "class Gate:\n    pass\n", encoding="utf-8"
    )
    (tmp_path / "test_k_root.py").write_text(_kat(""), encoding="utf-8")
    r = _lint("--root", tmp_path)
    assert r.returncode == 0, r.stdout
    assert "in 1 KAT file(s)" in r.stdout, r.stdout


def test_one_problem_per_line_and_reason(tmp_path: Path) -> None:
    r = _lint(
        _write(tmp_path, "test_k_case.py", _kat("raise pytest.fail.Exception('x')"))
    )
    assert "kat lint: 2 problem(s)" in r.stdout, r.stdout


def test_a_huge_product_is_not_built() -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("kat_lint_under_test_2", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    folder = mod.Folder(ast.parse(""))
    for expr in ("'x' * 10 ** 12", "10 ** 12 * 'x'", "[0] * 10 ** 12"):
        assert folder.fold(ast.parse(expr, mode="eval").body, {})[0] == "unknown", expr


def test_a_string_compare_outside_a_platform_check_is_not_judged(
    tmp_path: Path,
) -> None:
    src = _deco_test(
        "@pytest.mark.skipif(os.environ.get('ZQXWVK') == 'zqxwvk', reason='x')",
        "import os",
    )
    _write(tmp_path, "test_ordinary.py", "import pytest\n" + src)
    r = _lint("--root", tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr


# --- holes from review: platform tautologies, raises, patching, rebinding, asserts ----
# Each case below is a KAT that still looks valid (it calls the real gate and
# asserts on the answer) but is decided by something else.

_EVAL = "d = gate.evaluate('s', 'read_file', ['zqxwvk'])"
_FAKE = "class FakeGate:\n    def evaluate(self, *a, **k):\n        return None"


def _first(line: str, prelude: str = "", params: str = "gate") -> str:
    """A valid KAT whose body starts with the given lines."""
    src = _kat("", prelude, params)
    head = f"def test_k_case({params}):\n"
    return src.replace(head, head + "".join(f"    {x}\n" for x in line.splitlines()))


def _plain(body: str, prelude: str = "", params: str = "gate") -> str:
    """A KAT with a gate call and the given lines instead of the base assert."""
    lines = "".join(f"    {x}\n" for x in body.splitlines())
    return (
        KAT_HEAD
        + prelude
        + "\n\n\n"
        + f"def test_k_case({params}):\n    {_EVAL}\n"
        + lines
    )


HOLE_PLATFORM = {
    "ne_impossible_value": (
        _first("if sys.platform != 'zqxwvk':\n    pytest.skip('x')"),
        "true on every platform",
    ),
    "self_comparison": (
        _first("if os.name == os.name:\n    pytest.skip('x')"),
        "true on every platform",
    ),
    "every_system_listed": (
        _first(
            "if platform.system() in ('Linux', 'Windows', 'Darwin', 'Java', 'FreeBSD', 'OpenBSD', 'AIX'):\n    pytest.skip('x')",
            "import platform",
        ),
        "true on every platform",
    ),
    "alias_or_of_two_values": (
        _first(
            "if P != 'win32' or P != 'linux':\n    pytest.skip('x')", "P = sys.platform"
        ),
        "true on every platform",
    ),
    "skipif_every_system": (
        KAT_HEAD + "import platform\n\n\n@pytest.mark.skipif(platform.system() in "
        "('Linux', 'Windows', 'Darwin', 'Java', 'FreeBSD', 'OpenBSD', 'AIX'), reason='x')\n"
        f"def test_k_case(gate):\n    {_EVAL}\n    assert d.verdict is Verdict.DENY\n",
        "true on every platform",
    ),
    "skipif_name_not_name": (
        KAT_HEAD + "@pytest.mark.skipif(os.name != 'zqxwvk', reason='x')\n"
        f"def test_k_case(gate):\n    {_EVAL}\n    assert d.verdict is Verdict.DENY\n",
        "value no platform has",
    ),
}

HOLE_RAISE = {
    "throw_into_generator": (
        _first("g = (i for i in [1])\nnext(g)\ng.throw(AssertionError('x'))"),
        "throw AssertionError in a KAT file fails by fiat",
    ),
    "throw_alias": (
        _first("g = (i for i in [1])\nnext(g)\ng.throw(E)", "E = SystemExit"),
        "throw forced exit in a KAT file fails by fiat",
    ),
    "helper_raises_local_subclass": (
        _first(
            "_boom()",
            "class Boom(AssertionError):\n    pass\n\n\ndef _boom():\n    raise Boom()",
        ),
        "raise AssertionError in a KAT file fails by fiat",
    ),
    "subclass_of_subclass": (
        _first(
            "_boom()",
            "class Boom(SystemExit):\n    pass\n\n\nclass Boom2(Boom):\n    pass\n\n\n"
            "def _boom():\n    raise Boom2",
        ),
        "forced exit in a KAT file fails by fiat",
    ),
}

HOLE_PATCH = {
    "instance_dict": (_first("gate.__dict__['evaluate'] = lambda *a, **k: None"), None),
    "vars_of_gate": (_first("vars(gate)['evaluate'] = lambda *a, **k: None"), None),
    "vars_update": (_first("vars(gate).update(evaluate=lambda *a, **k: None)"), None),
    "dict_update": (
        _first("gate.__dict__.update(evaluate=lambda *a, **k: None)"),
        None,
    ),
    "object_setattr": (
        _first("object.__setattr__(gate, 'evaluate', lambda *a, **k: None)"),
        None,
    ),
    "type_setattr": (
        _first("type.__setattr__(Gate, 'evaluate', lambda *a, **k: None)"),
        None,
    ),
    "dunder_setattr_method": (
        _first("gate.__setattr__('evaluate', lambda *a, **k: None)"),
        None,
    ),
    "type_of_gate": (_first("type(gate).evaluate = lambda *a, **k: None"), None),
}

HOLE_REBIND = {
    "param_reassigned": (_first("gate = FakeGate()", _FAKE), "rebinds the gate"),
    "tuple_unpacking": (_first("gate, _ = FakeGate(), 1", _FAKE), "rebinds the gate"),
    "walrus": (_first("(gate := FakeGate())", _FAKE), "rebinds the gate"),
    "fixture_defined_again": (
        KAT_HEAD
        + _FAKE
        + "\n\n\n@pytest.fixture()\ndef gate():\n    return FakeGate()\n\n\n"
        f"def test_k_case(gate):\n    {_EVAL}\n    assert d.verdict is Verdict.DENY\n",
        "defined more than once",
    ),
}

HOLE_ASSERT = {
    "equal_to_itself": (_plain("assert d.verdict == d.verdict"), "tautological assert"),
    "is_itself": (_plain("assert d is d"), "tautological assert"),
    "not_unequal_to_itself": (
        _plain("assert not d.verdict != d.verdict"),
        "tautological assert",
    ),
    "isinstance_object": (
        _plain("assert isinstance(d, object)"),
        "tautological assert",
    ),
    "tuple_index_constant": (_plain("assert (d.verdict, 1)[1]"), "tautological assert"),
    "in_every_verdict": (
        _plain(
            "assert d.verdict in "
            "(Verdict.ALLOW, Verdict.DENY, Verdict.ASK, Verdict.THROWN)"
        ),
        "tautological assert",
    ),
    "in_every_verdict_list": (
        _plain(
            "assert d.verdict in "
            "[Verdict.THROWN, Verdict.DENY, Verdict.ASK, Verdict.ALLOW]"
        ),
        "tautological assert",
    ),
    "swallowed_assertion_error": (
        _plain(
            "try:\n    assert d.verdict is Verdict.DENY\nexcept AssertionError:\n    pass"
        ),
        "never asserts on the gate's result",
    ),
    "swallowed_exception": (
        _plain(
            "try:\n    assert d.verdict is Verdict.DENY\nexcept Exception:\n    pass"
        ),
        "never asserts on the gate's result",
    ),
    "swallowed_bare_except": (
        _plain("try:\n    assert d.verdict is Verdict.DENY\nexcept:\n    pass"),
        "never asserts on the gate's result",
    ),
    "swallowed_tuple": (
        _plain(
            "try:\n    assert d.verdict is Verdict.DENY\nexcept (ValueError, AssertionError):\n    pass"
        ),
        "never asserts on the gate's result",
    ),
}

HOLES = {
    **{f"platform-{k}": v for k, v in HOLE_PLATFORM.items()},
    **{f"raise-{k}": v for k, v in HOLE_RAISE.items()},
    **{f"patch-{k}": v for k, v in HOLE_PATCH.items()},
    **{f"rebind-{k}": v for k, v in HOLE_REBIND.items()},
    **{f"assert-{k}": v for k, v in HOLE_ASSERT.items()},
}


@pytest.mark.parametrize("shape", sorted(HOLES))
def test_a_kat_decided_by_something_else_is_rejected(
    tmp_path: Path, shape: str
) -> None:
    src, reason = HOLES[shape]
    _expect(tmp_path, src, reason or "patches the gate at line")


HOLE_CLEAN = {
    # A guard false on every platform never fires the skip; the test runs.
    "eq_impossible_value": _first("if sys.platform == 'zqxwvk':\n    pytest.skip('x')"),
    "real_platform_skip": _first(
        "if sys.platform == 'win32':\n    pytest.skip('posix only')"
    ),
    "real_platform_prefix": _first(
        "if sys.platform.startswith('win'):\n    pytest.skip('posix only')"
    ),
    "real_platform_skipif": (
        KAT_HEAD + "@pytest.mark.skipif(sys.platform == 'win32', reason='posix only')\n"
        f"def test_k_case(gate):\n    {_EVAL}\n    assert d.verdict is Verdict.DENY\n"
    ),
    "two_real_systems": _first(
        "if platform.system() in ('Windows', 'Darwin'):\n    pytest.skip('linux only')",
        "import platform",
    ),
    "fault_injection_elsewhere": _first(
        "monkeypatch.setattr(os, 'lstat', os.lstat)", params="gate, monkeypatch"
    ),
    "vars_of_another_object": _first("vars(tmp_path)", params="gate, tmp_path"),
    "assert_in_one_verdict": _plain("assert d.verdict in (Verdict.DENY,)"),
    # evaluate can return ASK, so naming two verdicts still tells ASK apart.
    "assert_in_two_verdicts": _plain(
        "assert d.verdict in (Verdict.ALLOW, Verdict.DENY)"
    ),
    "assert_equal_to_constant": _plain("assert d.verdict == Verdict.DENY"),
    "try_that_reraises": _plain(
        "try:\n    assert d.verdict is Verdict.DENY\nexcept AssertionError:\n    raise"
    ),
    "try_other_exception": _plain(
        "try:\n    assert d.verdict is Verdict.DENY\nexcept ValueError:\n    pass"
    ),
    "rebound_to_a_real_gate": _first(
        "gate = Gate(load_policy({'skills': {}}), log_path=str(tmp_path / 'e.jsonl'))",
        params="gate, tmp_path",
    ),
    "gate_throw_is_the_gate": _plain(
        "assert gate.throw('drill') is True\nassert d.verdict is Verdict.DENY"
    ),
}


@pytest.mark.parametrize("shape", sorted(HOLE_CLEAN))
def test_the_honest_form_of_each_hole_stays_clean(tmp_path: Path, shape: str) -> None:
    r = _lint(_write(tmp_path, "test_k_case.py", HOLE_CLEAN[shape]))
    assert r.returncode == 0, r.stdout


# --require-kats: a run that finds no KAT file fails, so the CI step cannot pass
# by having nothing to judge.


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "repo"
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    return root


def test_require_kats_fails_when_no_kat_file_is_found(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"tests/test_plain.py": "def test_x():\n    assert 1 + 1\n"})
    r = _lint("--root", root, "--require-kats")
    assert r.returncode == 1, r.stdout + r.stderr
    assert "no KAT file found" in r.stdout, r.stdout
    assert str(tmp_path) not in r.stdout + r.stderr


def test_require_kats_passes_when_a_clean_kat_is_found(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"tests/test_k_case.py": _kat("")})
    r = _lint("--root", root, "--require-kats")
    assert r.returncode == 0, r.stdout + r.stderr


def test_without_the_flag_an_empty_tree_still_passes(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"tests/test_plain.py": "def test_x():\n    assert 1 + 1\n"})
    r = _lint("--root", root)
    assert r.returncode == 0, r.stdout + r.stderr


# --- review round on #101, group A: version guards, always-reached raises, a hook
# script that is only echoed, and the gate module reached through sys.modules.
_HOOK = "adapters/claude_code_hook.py"

# Group A ---------------------------------------------------------------------
GROUP_A = {
    "version-true-on-every-python": (
        _first("if sys.version_info >= (3, 11):\n    pytest.skip('x')"),
        "true on every platform",
    ),
    "version-skipif-true-on-every-python": (
        KAT_HEAD + "@pytest.mark.skipif(sys.version_info > (3, 0), reason='x')\n"
        f"def test_k_case(gate):\n    {_EVAL}\n    assert d.verdict is Verdict.DENY\n",
        "true on every platform",
    ),
    "raise-in-for-over-constant": (
        _kat("for _ in [1]:\n    raise ValueError('x')"),
        "forced failure in a KAT file fails by fiat",
    ),
    "raise-in-while-true": (
        _kat("while True:\n    raise ValueError('x')"),
        "forced failure in a KAT file fails by fiat",
    ),
    "raise-in-wildcard-case": (
        _kat("match d:\n    case _:\n        raise ValueError('x')"),
        "forced failure in a KAT file fails by fiat",
    ),
    "raise-in-capture-case": (
        _kat("match d:\n    case v:\n        raise ValueError('x')"),
        "forced failure in a KAT file fails by fiat",
    ),
    "raise-past-a-handler-that-cannot-catch": (
        _kat("try:\n    raise ValueError('x')\nexcept KeyError:\n    pass"),
        "forced failure in a KAT file fails by fiat",
    ),
    "hook-echoed": (
        KAT_HEAD.replace("import os\n", "import os\nimport subprocess\n")
        + f"\n\n\ndef test_k_case():\n    r = subprocess.run(['echo', '{_HOOK}'])\n"
        "    assert r.returncode == 0\n",
        "never reaches the gate",
    ),
    "hook-catted": (
        KAT_HEAD.replace("import os\n", "import os\nimport subprocess\n")
        + f"\n\n\ndef test_k_case():\n    r = subprocess.run(['cat', '{_HOOK}'])\n"
        "    assert r.returncode == 0\n",
        "never reaches the gate",
    ),
    "hook-python-c": (
        KAT_HEAD.replace("import os\n", "import os\nimport subprocess\n")
        + "\n\n\ndef test_k_case():\n    r = subprocess.run([sys.executable, '-c', "
        f"'print(1)', '{_HOOK}'])\n    assert r.returncode == 0\n",
        "never reaches the gate",
    ),
    "sys-modules-setattr": (
        _first("setattr(sys.modules['capability_gate'], 'Gate', object)"),
        None,
    ),
    "sys-modules-attribute-store": (
        _first("sys.modules['capability_gate'].Gate = object"),
        None,
    ),
    "sys-modules-alias": (
        _first("m = sys.modules['capability_gate']\nsetattr(m, 'Gate', object)"),
        None,
    ),
}

GROUP_A_CLEAN = {
    "version-real-guard": _first(
        "if sys.version_info < (3, 12):\n    pytest.skip('x')"
    ),
    "version-false-everywhere": _first(
        "if sys.version_info >= (3, 99):\n    pytest.skip('x')"
    ),
    "raise-in-for-over-empty": _kat("for _ in []:\n    raise ValueError('x')"),
    "raise-in-refutable-case": _kat(
        "match d:\n    case 1:\n        raise ValueError('x')"
    ),
    "raise-caught-by-its-handler": _kat(
        "try:\n    raise ValueError('x')\nexcept ValueError:\n    pass"
    ),
    "raise-caught-by-a-base-handler": _kat(
        "try:\n    raise KeyError('x')\nexcept LookupError:\n    pass"
    ),
    "hook-run-by-python": (
        KAT_HEAD.replace("import os\n", "import os\nimport subprocess\n")
        + "\n\n\ndef test_k_case():\n    r = subprocess.run([sys.executable, "
        f"'{_HOOK}'], input='x', capture_output=True, text=True)\n"
        "    assert r.returncode == 2\n"
    ),
    "private-helper-in-gate-module": _first(
        "setattr(sys.modules['capability_gate'], '_zqxwvk', object)"
    ),
}


@pytest.mark.parametrize("shape", sorted(GROUP_A))
def test_a_guard_raise_hook_or_module_form_from_review_is_rejected(
    tmp_path: Path, shape: str
) -> None:
    src, reason = GROUP_A[shape]
    _expect(tmp_path, src, reason or "patches the gate at line")


@pytest.mark.parametrize("shape", sorted(GROUP_A_CLEAN))
def test_the_honest_guard_raise_hook_or_module_form_stays_clean(
    tmp_path: Path, shape: str
) -> None:
    r = _lint(_write(tmp_path, "test_k_case.py", GROUP_A_CLEAN[shape]))
    assert r.returncode == 0, r.stdout


# --- review round on #101, group B: dead asserts after a jump, and constants
# routed through a function, lambda, class attribute, dict, partial, getattr or
# staticmethod.

_VERDICT_ASSERT = "assert d.verdict is Verdict.DENY"
_NEVER = "never asserts on the gate's result"

GROUP_B = {
    "return-in-constant-loop-before-assert": (
        _plain(f"for _ in [1]:\n    return\n{_VERDICT_ASSERT}"),
        _NEVER,
    ),
    "return-in-true-branch-before-assert": (
        _plain(f"if True:\n    return\n{_VERDICT_ASSERT}"),
        _NEVER,
    ),
    "return-in-with-before-assert": (
        _plain(f"with contextlib.nullcontext():\n    return\n{_VERDICT_ASSERT}"),
        _NEVER,
    ),
    "return-in-try-before-assert": (
        _plain(f"try:\n    return\nfinally:\n    pass\n{_VERDICT_ASSERT}"),
        _NEVER,
    ),
    "assert-after-break": (
        _plain(f"for _ in [1]:\n    break\n    {_VERDICT_ASSERT}"),
        _NEVER,
    ),
    "assert-after-continue": (
        _plain(f"for _ in [1]:\n    continue\n    {_VERDICT_ASSERT}"),
        _NEVER,
    ),
    "assert-under-finally-return": (
        _plain(f"try:\n    {_VERDICT_ASSERT}\nfinally:\n    return"),
        _NEVER,
    ),
    "assert-under-finally-break": (
        _plain(
            f"for _ in [1]:\n    try:\n        {_VERDICT_ASSERT}\n    finally:\n        break"
        ),
        _NEVER,
    ),
    "constant-through-function": (
        _kat("assert _no()", "def _no():\n    return False"),
        "assert False in a KAT file fails by fiat",
    ),
    "constant-through-lambda": (
        _kat("assert NO()", "NO = lambda: False"),
        "assert False in a KAT file fails by fiat",
    ),
    "constant-through-class-attribute": (
        _kat("assert C.NO", "class C:\n    NO = False"),
        "assert False in a KAT file fails by fiat",
    ),
    "constant-through-dict": (
        _kat("assert D['no']", "D = {'no': False}"),
        "assert False in a KAT file fails by fiat",
    ),
    "constant-through-partial": (
        _kat("assert NO()", "import functools\n\nNO = functools.partial(bool, 0)"),
        "assert False in a KAT file fails by fiat",
    ),
    "constant-through-getattr": (
        _kat("assert getattr(C, 'NO')", "class C:\n    NO = False"),
        "assert False in a KAT file fails by fiat",
    ),
    "constant-through-staticmethod": (
        _kat(
            "assert C.no()",
            "class C:\n    @staticmethod\n    def no():\n        return False",
        ),
        "assert False in a KAT file fails by fiat",
    ),
    "skipif-through-function": (
        KAT_HEAD
        + "def _yes():\n    return True\n\n\n"
        + "@pytest.mark.skipif(_yes(), reason='x')\n"
        + f"def test_k_case(gate):\n    {_EVAL}\n    {_VERDICT_ASSERT}\n",
        "skipif",
    ),
}

GROUP_B_CLEAN = {
    "return-under-unknown-branch": _plain(
        f"if d.reason:\n    return\n{_VERDICT_ASSERT}"
    ),
    "assert-after-loop-with-break": _plain(
        f"for _ in [1]:\n    break\n{_VERDICT_ASSERT}"
    ),
    "assert-under-finally-pass": _plain(
        f"try:\n    {_VERDICT_ASSERT}\nfinally:\n    pass"
    ),
    "function-of-the-result": _plain(
        "assert _denied(d)",
        "def _denied(x):\n    return x.verdict is Verdict.DENY",
    ),
    "class-attribute-compared-with-result": _plain(
        "assert d.verdict is C.WANT", "class C:\n    WANT = Verdict.DENY"
    ),
}


@pytest.mark.parametrize("shape", sorted(GROUP_B))
def test_a_dead_assert_or_routed_constant_from_review_is_rejected(
    tmp_path: Path, shape: str
) -> None:
    src, reason = GROUP_B[shape]
    _expect(tmp_path, src, reason)


@pytest.mark.parametrize("shape", sorted(GROUP_B_CLEAN))
def test_a_live_assert_or_a_result_routed_through_a_helper_stays_clean(
    tmp_path: Path, shape: str
) -> None:
    r = _lint(_write(tmp_path, "test_k_case.py", GROUP_B_CLEAN[shape]))
    assert r.returncode == 0, r.stdout


def test_require_kats_is_a_documented_flag() -> None:
    """CI wiring of the flag follows in the leak scan pull request's floor job."""
    r = _lint("--help")
    assert r.returncode == 0, r.stderr
    assert "--require-kats" in r.stdout
    doc = ast.get_docstring(ast.parse(SCRIPT.read_text(encoding="utf-8")))
    assert "--require-kats" in (doc or "")


# --- review round on #101, group C: source encoding, pytest's own discovery, and
# tautologies built with or and and.

_FIAT_KAT = "import pytest\n\n\ndef test_k_case():\n    pytest.fail('zqxwvk')\n"

GROUP_C_TAUTOLOGY = {
    "or-with-self-comparison": _plain("assert d.verdict == d.verdict or d.verdict"),
    "or-with-identity": _plain("assert d is d or d.verdict is Verdict.DENY"),
    "or-with-isinstance-object": _plain(
        "assert d.verdict is Verdict.DENY or isinstance(d, object)"
    ),
    "and-of-tautologies": _plain("assert d is d and d.verdict == d.verdict"),
}
GROUP_C_TAUTOLOGY_CLEAN = {
    "or-of-two-real-checks": _plain(
        "assert d.verdict is Verdict.DENY or d.verdict is Verdict.ASK"
    ),
    "and-with-one-real-check": _plain("assert d is d and d.verdict is Verdict.DENY"),
    # An always-false side leaves an `or` to its other side.
    "or-with-an-always-false-side": _plain(
        "assert d.verdict != d.verdict or d.verdict is Verdict.DENY"
    ),
}


@pytest.mark.parametrize("shape", sorted(GROUP_C_TAUTOLOGY))
def test_a_tautology_built_with_or_and_is_rejected(tmp_path: Path, shape: str) -> None:
    _expect(tmp_path, GROUP_C_TAUTOLOGY[shape], "tautological assert")


@pytest.mark.parametrize("shape", sorted(GROUP_C_TAUTOLOGY_CLEAN))
def test_an_or_and_that_still_tests_the_answer_stays_clean(
    tmp_path: Path, shape: str
) -> None:
    r = _lint(_write(tmp_path, "test_k_case.py", GROUP_C_TAUTOLOGY_CLEAN[shape]))
    assert r.returncode == 0, r.stdout


@pytest.mark.parametrize(
    ("data", "expect"),
    [
        pytest.param(
            b"# -*- coding: latin-1 -*-\n" + _kat("").encode("utf-8"),
            "declares a source encoding other than UTF-8",
            id="latin-1-cookie",
        ),
        pytest.param(
            b"# vim: set fileencoding=cp1252 :\n" + _kat("").encode("utf-8"),
            "declares a source encoding other than UTF-8",
            id="cp1252-cookie",
        ),
        pytest.param(
            _kat("").encode("utf-8") + b"\n# \xff\xfe\n",
            "is not valid UTF-8",
            id="invalid-bytes",
        ),
    ],
)
def test_a_source_that_is_not_utf8_is_a_lint_problem(
    tmp_path: Path, data: bytes, expect: str
) -> None:
    path = tmp_path / "tests" / "test_k_case.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    r = _lint(path)
    assert r.returncode == 1, r.stdout + r.stderr
    assert expect in r.stdout, r.stdout
    assert "Traceback" not in r.stderr, r.stderr


def test_a_utf8_cookie_stays_clean(tmp_path: Path) -> None:
    path = tmp_path / "tests" / "test_k_case.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"# -*- coding: utf-8 -*-\n" + _kat("").encode("utf-8"))
    r = _lint(path)
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize(
    ("files", "kat"),
    [
        pytest.param(
            {"harness/test_k_case.py": _FIAT_KAT},
            "harness/test_k_case.py",
            id="outside-tests",
        ),
        pytest.param(
            {"tests/k_case_kat_test.py": _FIAT_KAT},
            "tests/k_case_kat_test.py",
            id="suffix-name",
        ),
        pytest.param(
            {
                "pytest.ini": "[pytest]\npython_files = check_*.py\n",
                "tests/check_kat.py": _FIAT_KAT,
            },
            "tests/check_kat.py",
            id="python-files-setting",
        ),
        pytest.param(
            {
                "pytest.ini": "[pytest]\ntestpaths = suite\n",
                "suite/deep/test_k_case.py": _FIAT_KAT,
            },
            "suite/deep/test_k_case.py",
            id="testpaths-setting",
        ),
    ],
)
def test_a_kat_file_pytest_collects_is_never_skipped(
    tmp_path: Path, files: dict[str, str], kat: str
) -> None:
    root = _tree(tmp_path, files)
    r = _lint("--root", root, "--require-kats")
    assert r.returncode == 1, r.stdout + r.stderr
    assert "fails by fiat" in r.stdout, r.stdout
    assert kat in r.stdout.replace("\\", "/"), r.stdout


def test_a_folder_pytest_does_not_recurse_into_is_not_linted(tmp_path: Path) -> None:
    root = _tree(
        tmp_path,
        {
            "pytest.ini": "[pytest]\nnorecursedirs = .* design\n",
            "design/test_k_case.py": _FIAT_KAT,
            "tests/test_k_clean.py": _kat(""),
        },
    )
    r = _lint("--root", root, "--require-kats")
    assert r.returncode == 0, r.stdout + r.stderr


# --- review round on #101, group D: an early return, a reassigned result, the
# length of a display, getattr and __class__ as attribute access, and setitem on a
# gate namespace.

_FAKE_RESULT = "class FakeResult:\n    verdict = Verdict.DENY"

GROUP_D = {
    "return-before-assert": (
        _plain("return\nassert d.verdict is Verdict.DENY"),
        "never asserts on the gate's result",
    ),
    "helper-returns-before-assert": (
        _plain(
            "_check(d)",
            "def _check(x):\n    return\n    assert x.verdict is Verdict.DENY",
        ),
        "never asserts on the gate's result",
    ),
    "result-reassigned-to-a-fake": (
        _plain("d = FakeResult()\nassert d.verdict is Verdict.DENY", _FAKE_RESULT),
        "never asserts on the gate's result",
    ),
    "result-reassigned-to-a-constant": (
        _plain("d = None\nassert d is None"),
        "never asserts on the gate's result",
    ),
    "length-of-a-display": (_plain("assert len([d]) == 1"), "constant comparison"),
    "length-of-a-tuple": (
        _plain("assert len((d, d.verdict)) > 1"),
        "constant comparison",
    ),
    "class-attribute-store": (
        _first("gate.__class__.evaluate = lambda *a, **k: None"),
        None,
    ),
    "setattr-on-class-attribute": (
        _first("setattr(gate.__class__, 'evaluate', lambda *a, **k: None)"),
        None,
    ),
    "getattr-class-store": (
        _first("getattr(gate, '__class__').evaluate = lambda *a, **k: None"),
        None,
    ),
    "monkeypatch-on-getattr-class": (
        _first(
            "monkeypatch.setattr(getattr(gate, '__class__'), 'evaluate', lambda *a, **k: None)",
            params="gate, monkeypatch",
        ),
        None,
    ),
    "monkeypatch-setitem-dict": (
        _first(
            "monkeypatch.setitem(gate.__dict__, 'evaluate', lambda *a, **k: None)",
            params="gate, monkeypatch",
        ),
        None,
    ),
    "monkeypatch-setitem-vars": (
        _first(
            "monkeypatch.setitem(vars(gate), 'evaluate', lambda *a, **k: None)",
            params="gate, monkeypatch",
        ),
        None,
    ),
    "monkeypatch-delitem-class-dict": (
        _first(
            "monkeypatch.delitem(vars(Gate), 'evaluate', raising=False)",
            params="gate, monkeypatch",
        ),
        None,
    ),
}

GROUP_D_CLEAN = {
    "result-rebound-from-the-gate": _plain(
        "d = gate.evaluate('s', 'read_file', ['zqxwvk'])\nassert d.verdict is Verdict.DENY"
    ),
    "length-of-a-real-list": _plain("assert len(d.reason) > 0"),
    "class-of-another-object": _first(
        "monkeypatch.setattr(tmp_path.__class__, 'zqxwvk', 1, raising=False)",
        params="gate, monkeypatch, tmp_path",
    ),
    "setitem-elsewhere": _first(
        "monkeypatch.setitem(os.environ, 'ZQXWVK', '1')", params="gate, monkeypatch"
    ),
}


@pytest.mark.parametrize("shape", sorted(GROUP_D))
def test_a_result_or_patch_form_from_review_is_rejected(
    tmp_path: Path, shape: str
) -> None:
    src, reason = GROUP_D[shape]
    _expect(tmp_path, src, reason or "patches the gate at line")


@pytest.mark.parametrize("shape", sorted(GROUP_D_CLEAN))
def test_the_honest_result_or_patch_form_stays_clean(
    tmp_path: Path, shape: str
) -> None:
    r = _lint(_write(tmp_path, "test_k_case.py", GROUP_D_CLEAN[shape]))
    assert r.returncode == 0, r.stdout
