"""KAT linter: reject tests that are red by fiat or never reach the gate."""

from __future__ import annotations

import ast
import os
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

from capability_gate import Gate, Verdict, load_policy


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
    assert gate.evaluate("s", "read_file", ["x"]).verdict is Verdict.DENY
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
    "fault_injection_outside_the_gate": """
def test_k(gate, tmp_path, monkeypatch):
    def boom(_path):
        raise OSError("zqxwvk")

    monkeypatch.setattr(os, "lstat", boom)
    d = _attempt(gate, tmp_path)
    assert d.verdict is Verdict.DENY
""",
}

# Entries of CORPUS whose answer assert the allowlist now refuses.
CORPUS_REFUSED_BY_ALLOWLIST = {
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
    "helper_asserts": """
def test_k(gate, tmp_path):
    _assert_denied(_attempt(gate, tmp_path))


def test_k2(gate, tmp_path):
    d = gate.evaluate("writer", "read_file", [str(tmp_path / "x")])
    _assert_denied(d)
""",
    "all_over_a_generator": """
def test_k(gate, tmp_path):
    assert all(
        gate.evaluate("writer", "read_file", [str(tmp_path / n)]).verdict is Verdict.DENY
        for n in ("a.txt", "b.txt")
    )
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


@pytest.mark.parametrize("shape", sorted(CORPUS_REFUSED_BY_ALLOWLIST))
def test_t14_legitimate_deny_shapes_refused_by_the_answer_allowlist(
    tmp_path: Path, shape: str
) -> None:
    path = _write(
        tmp_path,
        f"test_k_{shape}.py",
        CORPUS_HEAD.format(root=str(ROOT)) + CORPUS_REFUSED_BY_ALLOWLIST[shape],
    )
    r = _lint(path)
    _assert_refused(r)


# ---------------------------------------------------------------------------
# Removal tests: one case per rule, table entry, and branch, so deleting any
# of them turns a test red. Rejected cases name the reason; clean cases must
# lint clean.


def _assert_refused(r) -> None:
    """The answer allowlist refuses the case by one of its two messages."""
    assert r.returncode == 1, r.stdout
    assert (
        "not an accepted assert on the gate's answer" in r.stdout
        or "never asserts on the gate's result in the accepted form" in r.stdout
    ), r.stdout


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
    # The shadowing helper reads its argument: a helper that returns a constant
    # now folds through the call, which is a different rule.
    "shadowed_builtin_is_not_folded": (
        "assert len([])",
        "def len(x):\n    return x.count(1)",
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
}


# Allowed before the gate class was read only directly: a fixture nothing
# applies still passes the class on as a value.
def test_an_unapplied_fixture_that_passes_the_gate_class_on_is_rejected(
    tmp_path: Path,
) -> None:
    prelude = (
        "@pytest.fixture(autouse=False)\ndef _swap(monkeypatch):\n"
        "    monkeypatch.setattr(Gate, 'evaluate', lambda *a, **k: None)"
    )
    _expect(tmp_path, _kat("", prelude), "the gate class is passed on as a value")


# Entries of CLEAN whose answer assert the allowlist now refuses.
CLEAN_REFUSED_BY_ALLOWLIST = {
    "local_rebinding_shadows_module": (
        "NO = d.verdict is Verdict.DENY\nassert NO",
        "NO = False",
    ),
    "walrus_rebinds": ("assert (X := d)", "X = 0"),
}


@pytest.mark.parametrize("shape", sorted(CLEAN))
def test_each_allowed_form_stays_clean(tmp_path: Path, shape: str) -> None:
    body, prelude, *params = CLEAN[shape]
    _clean(tmp_path, _kat(body, prelude, params=params[0] if params else "gate"))


@pytest.mark.parametrize("shape", sorted(CLEAN_REFUSED_BY_ALLOWLIST))
def test_each_allowed_form_refused_by_the_answer_allowlist(
    tmp_path: Path, shape: str
) -> None:
    body, prelude, *params = CLEAN_REFUSED_BY_ALLOWLIST[shape]
    _assert_refused(
        _lint(
            _write(
                tmp_path,
                "test_k_case.py",
                _kat(body, prelude, params=params[0] if params else "gate"),
            )
        )
    )


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
        "    assert r.returncode == 2\n"
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
    "class_method_helper": """
class TestK:
    def _try(self, gate, tmp_path):
        return gate.evaluate("writer", "read_file", [str(tmp_path / "x")])

    def test_k(self, gate, tmp_path):
        assert self._try(gate, tmp_path).verdict is Verdict.DENY
""",
    "helper_builds_gate": """
def _make(tmp_path):
    return Gate(load_policy({"skills": {}}), log_path=str(tmp_path / "m.jsonl"))


def test_k(tmp_path):
    g = _make(tmp_path)
    assert g.evaluate("s", "read_file", ["zqxwvk"]).verdict is Verdict.DENY
""",
    "annotated_result": """
def test_k(gate, tmp_path):
    d: object = _attempt(gate, tmp_path)
    assert d.verdict is Verdict.DENY
""",
}

# Entries of CORPUS_MORE whose answer assert the allowlist now refuses.
CORPUS_MORE_REFUSED_BY_ALLOWLIST = {
    # A conditional return before the assert makes the assert conditional.
    "walrus_in_if": """
def test_k(gate, tmp_path):
    if (d := _attempt(gate, tmp_path)) is None:
        return
    assert d.verdict is Verdict.DENY
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
    "keyword_arguments": """
def test_k(gate, tmp_path):
    d = _attempt(gate=gate, tmp_path=tmp_path)
    _assert_denied(d=d)
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
    "augmented_result": """
def test_k(gate, tmp_path):
    total = 0
    total += int(_attempt(gate, tmp_path).verdict is Verdict.DENY)
    assert total == 1
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


@pytest.mark.parametrize("shape", sorted(CORPUS_MORE_REFUSED_BY_ALLOWLIST))
def test_t14_more_legitimate_shapes_refused_by_the_answer_allowlist(
    tmp_path: Path, shape: str
) -> None:
    path = _write(
        tmp_path,
        f"test_k_{shape}.py",
        CORPUS_HEAD.format(root=str(ROOT)) + CORPUS_MORE_REFUSED_BY_ALLOWLIST[shape],
    )
    r = _lint(path)
    _assert_refused(r)


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
    # Rebound to int: str of anything is rejected as never testing the answer.
    "assigned_builtin": ("assert bool(0)", "bool = int"),
    "imported_builtin_name": ("assert bool(0)", "from os.path import exists as bool"),
    "builtin_named_parameter": ("assert bool(0)", "", "gate, bool"),
    # A display's length is known whatever its elements are (rejected, see the
    # review round tests); one with a starred part is not.
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

# Entries of CLEAN_2 whose answer assert the allowlist now refuses.
CLEAN_2_REFUSED_BY_ALLOWLIST = {
    "walrus_statement_rebinds": ("(X := d)\nassert X", "X = 0"),
    "starred_list_may_be_empty": ("assert [*d.reason]", ""),
    "list_with_unknown_compares_unknown": ("assert [d] != [None]", ""),
    "dict_unpack_may_be_empty": ("assert {**vars(d)}", ""),
    "dict_unknown_compares_unknown": ("assert {1: d} != {1: None}", ""),
    "negating_partial_knowledge": ("assert -(0 if d else 0) == 0", ""),
    "arithmetic_on_partial_knowledge": ("assert (0 if d else 0) + 1 == 1", ""),
    "subscript_of_partial_knowledge": ("assert [d][0] is not None", ""),
    "slice_with_unknown_bound": ("assert [1, 2][len(d.reason) :]", ""),
    "or_with_unknown_side": ("assert d or 0", ""),
    "len_of_partial_knowledge": ("assert len([*d.reason]) == 1", ""),
}


@pytest.mark.parametrize("shape", sorted(CLEAN_2))
def test_each_allowed_form_stays_clean_2(tmp_path: Path, shape: str) -> None:
    body, prelude, *params = CLEAN_2[shape]
    _clean(tmp_path, _kat(body, prelude, params=params[0] if params else "gate"))


@pytest.mark.parametrize("shape", sorted(CLEAN_2_REFUSED_BY_ALLOWLIST))
def test_each_allowed_form_stays_clean_2_refused_by_the_answer_allowlist(
    tmp_path: Path, shape: str
) -> None:
    body, prelude, *params = CLEAN_2_REFUSED_BY_ALLOWLIST[shape]
    _assert_refused(
        _lint(
            _write(
                tmp_path,
                "test_k_case.py",
                _kat(body, prelude, params=params[0] if params else "gate"),
            )
        )
    )


EVAL = "gate.evaluate('s', 'read_file', ['zqxwvk'])"
VERDICT = "    assert d.verdict is Verdict.DENY\n"
DECISION_FIXTURE = f"@pytest.fixture()\ndef decision(gate):\n    return {EVAL}\n\n\n"
REACH_CLEAN = {
    "constant_true_if": f"    if True:\n        d = {EVAL}\n" + VERDICT,
    "with_body": f"    with contextlib.nullcontext():\n        d = {EVAL}\n" + VERDICT,
    "assert_in_true_branch": f"    d = {EVAL}\n    if True:\n    " + VERDICT,
    "assert_in_else": f"    d = {EVAL}\n    if False:\n        pass\n    else:\n    "
    + VERDICT,
    "assert_in_try": f"    d = {EVAL}\n    try:\n    "
    + VERDICT
    + "    finally:\n        pass\n",
}

# Entries of REACH_CLEAN whose answer assert the allowlist now refuses.
REACH_CLEAN_REFUSED_BY_ALLOWLIST = {
    "true_ternary": f"    d = {EVAL} if True else None\n" + VERDICT,
    "false_ternary_else": f"    d = None if False else {EVAL}\n" + VERDICT,
    "assert_inside_branch": f"    d = {EVAL}\n    if d is not None:\n    " + VERDICT,
    "assert_in_while": (
        f"    d = {EVAL}\n    n = 0\n    while n < 1:\n    "
        + VERDICT
        + "        n += 1\n"
    ),
    "assert_in_match": f"    d = {EVAL}\n    match d:\n        case _:\n        "
    + VERDICT,
}


@pytest.mark.parametrize("shape", sorted(REACH_CLEAN))
def test_reach_and_result_in_every_live_position(tmp_path: Path, shape: str) -> None:
    _clean(tmp_path, KAT_HEAD + "def test_k(gate):\n" + REACH_CLEAN[shape])


@pytest.mark.parametrize("shape", sorted(REACH_CLEAN_REFUSED_BY_ALLOWLIST))
def test_reach_and_result_in_every_live_position_refused_by_the_answer_allowlist(
    tmp_path: Path, shape: str
) -> None:
    _assert_refused(
        _lint(
            _write(
                tmp_path,
                "test_k_case.py",
                KAT_HEAD
                + "def test_k(gate):\n"
                + REACH_CLEAN_REFUSED_BY_ALLOWLIST[shape],
            )
        )
    )


def test_cyclic_fixtures_do_not_crash_the_lint(tmp_path: Path) -> None:
    src = (
        KAT_HEAD
        + "@pytest.fixture()\ndef a(b):\n    return b\n\n\n"
        + "@pytest.fixture()\ndef b(a):\n    return a\n\n\n"
        + f"def test_k(gate, a):\n    assert {EVAL}.verdict is Verdict.DENY\n"
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
    # evaluate can return ASK, so naming two verdicts still tells ASK apart.
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

# Entries of HOLE_CLEAN whose answer assert the allowlist now refuses.
HOLE_CLEAN_REFUSED_BY_ALLOWLIST = {
    "assert_in_one_verdict": _plain("assert d.verdict in (Verdict.DENY,)"),
    "assert_in_two_verdicts": _plain(
        "assert d.verdict in (Verdict.ALLOW, Verdict.DENY)"
    ),
}


@pytest.mark.parametrize("shape", sorted(HOLE_CLEAN))
def test_the_honest_form_of_each_hole_stays_clean(tmp_path: Path, shape: str) -> None:
    r = _lint(_write(tmp_path, "test_k_case.py", HOLE_CLEAN[shape]))
    assert r.returncode == 0, r.stdout


@pytest.mark.parametrize("shape", sorted(HOLE_CLEAN_REFUSED_BY_ALLOWLIST))
def test_the_honest_form_of_each_hole_refused_by_the_answer_allowlist(
    tmp_path: Path, shape: str
) -> None:
    r = _lint(
        _write(tmp_path, "test_k_case.py", HOLE_CLEAN_REFUSED_BY_ALLOWLIST[shape])
    )
    _assert_refused(r)


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
    "hook-as-c-code": (
        KAT_HEAD.replace("import os\n", "import os\nimport subprocess\n")
        + "\n\n\ndef test_k_case():\n    r = subprocess.run([sys.executable, '-c', "
        f"'{_HOOK}'])\n    assert r.returncode == 0\n",
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
    "assert-after-loop-with-break": _plain(
        f"for _ in [1]:\n    break\n{_VERDICT_ASSERT}"
    ),
    "assert-under-finally-pass": _plain(
        f"try:\n    {_VERDICT_ASSERT}\nfinally:\n    pass"
    ),
}

# Entries of GROUP_B_CLEAN whose answer assert the allowlist now refuses.
GROUP_B_CLEAN_REFUSED_BY_ALLOWLIST = {
    # A conditional return before the assert makes the assert conditional.
    "return-under-unknown-branch": _plain(
        f"if d.reason:\n    return\n{_VERDICT_ASSERT}"
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


@pytest.mark.parametrize("shape", sorted(GROUP_B_CLEAN_REFUSED_BY_ALLOWLIST))
def test_a_live_assert_or_a_result_routed_through_a_helper_refused_by_the_answer_allowlist(
    tmp_path: Path, shape: str
) -> None:
    r = _lint(
        _write(tmp_path, "test_k_case.py", GROUP_B_CLEAN_REFUSED_BY_ALLOWLIST[shape])
    )
    _assert_refused(r)


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
# The answer is asserted in the accepted form; the side check reads no
# answer, so the blocklist judges it and must not over-reject it.
GROUP_C_TAUTOLOGY_CLEAN = {
    "or-of-two-side-checks": _kat("n = len(os.listdir('.'))\nassert n == 1 or n == 2"),
}

# Entries of GROUP_C_TAUTOLOGY_CLEAN whose answer assert the allowlist now refuses.
GROUP_C_TAUTOLOGY_CLEAN_REFUSED_BY_ALLOWLIST = {
    "or-of-two-real-checks": _plain(
        "assert d.verdict is Verdict.DENY or d.verdict is Verdict.ASK"
    ),
    "and-with-one-real-check": _plain("assert d is d and d.verdict is Verdict.DENY"),
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


@pytest.mark.parametrize("shape", sorted(GROUP_C_TAUTOLOGY_CLEAN_REFUSED_BY_ALLOWLIST))
def test_an_or_and_that_still_tests_the_answer_refused_by_the_answer_allowlist(
    tmp_path: Path, shape: str
) -> None:
    r = _lint(
        _write(
            tmp_path,
            "test_k_case.py",
            GROUP_C_TAUTOLOGY_CLEAN_REFUSED_BY_ALLOWLIST[shape],
        )
    )
    _assert_refused(r)


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
            b"# -*- coding: zqxwvk -*-\n" + _kat("").encode("utf-8"),
            "declares a source encoding Python does not know",
            id="unknown-cookie",
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
    "cookie",
    [
        pytest.param(b"# -*- coding: utf-8 -*-\n", id="utf-8"),
        pytest.param(b"# coding: utf8\n", id="utf8-alias"),
        pytest.param(b"\xef\xbb\xbf", id="bom"),
    ],
)
def test_a_utf8_source_stays_clean(tmp_path: Path, cookie: bytes) -> None:
    path = tmp_path / "tests" / "test_k_case.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(cookie + _kat("").encode("utf-8"))
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
    assert "in 1 KAT file(s)" in r.stdout, r.stdout


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
    "class-of-another-object": _first(
        "monkeypatch.setattr(tmp_path.__class__, 'zqxwvk', 1, raising=False)",
        params="gate, monkeypatch, tmp_path",
    ),
    "setitem-elsewhere": _first(
        "monkeypatch.setitem(os.environ, 'ZQXWVK', '1')", params="gate, monkeypatch"
    ),
}

# Entries of GROUP_D_CLEAN whose answer assert the allowlist now refuses.
GROUP_D_CLEAN_REFUSED_BY_ALLOWLIST = {
    "length-of-a-real-list": _plain("assert len(d.reason) > 0"),
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


@pytest.mark.parametrize("shape", sorted(GROUP_D_CLEAN_REFUSED_BY_ALLOWLIST))
def test_the_honest_result_or_patch_form_refused_by_the_answer_allowlist(
    tmp_path: Path, shape: str
) -> None:
    r = _lint(
        _write(tmp_path, "test_k_case.py", GROUP_D_CLEAN_REFUSED_BY_ALLOWLIST[shape])
    )
    _assert_refused(r)


# --- always-pass review round: a side and its own negation -------------------------
# An or of a test and its negation is always true; an and of the two is always
# false. Each side is normalised first (not, operand order, bool()).

ALWAYS_PASS_PAIRS = {
    "eq-or-ne": "assert d.verdict == Verdict.DENY or d.verdict != Verdict.DENY",
    "ne-or-eq-swapped": "assert Verdict.DENY != d.verdict or d.verdict == Verdict.DENY",
    "is-or-is-not": "assert d.verdict is Verdict.DENY or d.verdict is not Verdict.DENY",
    "in-or-not-in": (
        "assert d.verdict in (Verdict.DENY,) or d.verdict not in (Verdict.DENY,)"
    ),
    "p-or-not-p": "assert d.reason or not d.reason",
    "bool-or-not-bool": "assert bool(d) or not bool(d)",
    "not-p-or-p": "assert not d.reason or bool(d.reason)",
    "pair-among-three": "assert d.verdict is Verdict.ASK or d.reason or not d.reason",
    "not-of-p-and-not-p": (
        "assert not (d.verdict is Verdict.DENY and not d.verdict is Verdict.DENY)"
    ),
    "p-and-not-p": "assert d.reason and not d.reason",
    "eq-and-ne": "assert d.verdict == Verdict.DENY and d.verdict != Verdict.DENY",
}

# The answer is asserted in the accepted form; the side check reads no
# answer, so the blocklist judges it and must not over-reject it.
ALWAYS_PASS_PAIRS_CLEAN = {
    "side-check-that-is-not-a-pair": "assert d.verdict is Verdict.DENY\nn = len(os.listdir('.'))\nassert n == 1 or n != 2",
}

# Entries of ALWAYS_PASS_PAIRS_CLEAN whose answer assert the allowlist now refuses.
ALWAYS_PASS_PAIRS_CLEAN_REFUSED_BY_ALLOWLIST = {
    "two-different-verdicts": (
        "assert d.verdict is Verdict.DENY or d.verdict is Verdict.ASK"
    ),
    "two-different-fields": "assert d.reason or not d.verdict",
    "not-of-a-real-and": "assert not (d.verdict is Verdict.ALLOW and d.reason)",
    "eq-and-another-ne": (
        "assert d.verdict == Verdict.DENY and d.verdict != Verdict.ALLOW"
    ),
}


@pytest.mark.parametrize("shape", sorted(ALWAYS_PASS_PAIRS))
def test_a_side_and_its_negation_is_a_tautology(tmp_path: Path, shape: str) -> None:
    _expect(tmp_path, _plain(ALWAYS_PASS_PAIRS[shape]), "tautological assert")


@pytest.mark.parametrize("shape", sorted(ALWAYS_PASS_PAIRS_CLEAN))
def test_sides_that_are_not_negations_stay_clean(tmp_path: Path, shape: str) -> None:
    r = _lint(
        _write(tmp_path, "test_k_case.py", _plain(ALWAYS_PASS_PAIRS_CLEAN[shape]))
    )
    assert r.returncode == 0, r.stdout


@pytest.mark.parametrize("shape", sorted(ALWAYS_PASS_PAIRS_CLEAN_REFUSED_BY_ALLOWLIST))
def test_sides_that_are_not_negations_stay_clean_refused_by_the_answer_allowlist(
    tmp_path: Path, shape: str
) -> None:
    r = _lint(
        _write(
            tmp_path,
            "test_k_case.py",
            _plain(ALWAYS_PASS_PAIRS_CLEAN_REFUSED_BY_ALLOWLIST[shape]),
        )
    )
    _assert_refused(r)


# --- always-pass review round: a test that is truthy by construction --------------
# A display, a generator, an f-string, repr/str/format/hasattr of anything,
# any() with a constant-true element and len(...) >= 0 hold whatever the gate
# answered. Non-empty displays and all() of an empty display were already caught
# as constants; they stay here as regressions.

ALWAYS_TRUTHY = {
    "tuple-display": "assert (d.verdict is Verdict.DENY,)",
    "starred-display": "assert (*[d],)",
    "starred-list-display": "assert [*[d]]",
    "list-display": "assert [d.verdict]",
    "set-display": "assert {d.verdict}",
    "dict-display": "assert {1: d.verdict}",
    "generator": "assert (v for v in [d.verdict])",
    "f-string": 'assert f"{d.verdict}"',
    "repr-call": "assert repr(d)",
    "str-call": "assert str(d.verdict)",
    "format-call": "assert format(d.verdict)",
    "hasattr-call": "assert hasattr(d, 'verdict')",
    "any-with-true": "assert any([True, d.verdict is Verdict.DENY])",
    "any-with-truthy-constant": "assert any((d.verdict is Verdict.DENY, 'x'))",
    "all-of-empty-or": "assert all(()) or d.verdict is Verdict.DENY",
    "all-of-empty-list-or": "assert all([]) or d.verdict is Verdict.DENY",
    "len-ge-zero": "assert len(d.reason) >= 0",
    "zero-le-len": "assert 0 <= len(d.reason)",
    "len-gt-minus-one": "assert len(d.reason) > -1",
}

# The answer is asserted in the accepted form; the side check reads no
# answer, so the blocklist judges it and must not over-reject it.
ALWAYS_TRUTHY_CLEAN = {
    "length-of-a-listing": "assert d.verdict is Verdict.DENY\nassert len(os.listdir('.')) > 0",
}

# Entries of ALWAYS_TRUTHY_CLEAN whose answer assert the allowlist now refuses.
ALWAYS_TRUTHY_CLEAN_REFUSED_BY_ALLOWLIST = {
    "len-gt-zero": "assert len(d.reason) > 0",
    "any-of-real-tests": (
        "assert any([d.verdict is Verdict.DENY, d.verdict is Verdict.ASK])"
    ),
    "all-of-real-tests": "assert all([d.verdict is Verdict.DENY, d.reason])",
    "str-compared": "assert str(d.verdict) == 'Verdict.DENY'",
    "list-comprehension": "assert [v for v in d.reason if v]",
}


@pytest.mark.parametrize("shape", sorted(ALWAYS_TRUTHY))
def test_an_assert_that_is_truthy_by_construction_is_rejected(
    tmp_path: Path, shape: str
) -> None:
    _expect(tmp_path, _plain(ALWAYS_TRUTHY[shape]), "assert in a KAT file")


@pytest.mark.parametrize("shape", sorted(ALWAYS_TRUTHY_CLEAN))
def test_an_assert_whose_truth_depends_on_the_answer_stays_clean(
    tmp_path: Path, shape: str
) -> None:
    r = _lint(_write(tmp_path, "test_k_case.py", _plain(ALWAYS_TRUTHY_CLEAN[shape])))
    assert r.returncode == 0, r.stdout


@pytest.mark.parametrize("shape", sorted(ALWAYS_TRUTHY_CLEAN_REFUSED_BY_ALLOWLIST))
def test_an_assert_whose_truth_depends_on_the_answer_refused_by_the_answer_allowlist(
    tmp_path: Path, shape: str
) -> None:
    r = _lint(
        _write(
            tmp_path,
            "test_k_case.py",
            _plain(ALWAYS_TRUTHY_CLEAN_REFUSED_BY_ALLOWLIST[shape]),
        )
    )
    _assert_refused(r)


# --- always-pass review round: an expression compared with itself in disguise -------
# A walrus target is the value it names, the element of a one-off display picked
# by a constant index is that element, and membership in a display holding the
# expression itself always holds. A display's length is known from its shape.

SELF_IN_DISGUISE = {
    "walrus-is-self": "assert (y := d) is y",
    "walrus-eq-self": "assert (y := d.verdict) == y",
    "walrus-value-is-self": "assert (y := d) is d",
    "in-own-tuple": "assert d in (d,)",
    "in-own-list": "assert d.verdict in [d.verdict]",
    "in-own-set-among-others": "assert d.verdict in {Verdict.ASK, d.verdict}",
    "len-set-of-id": "assert len({id(d)}) == 1",
    "len-dict-one": "assert len({1: d}) == 1",
    "first-of-own-list-is": "assert [d][0] is d",
    "first-of-own-tuple-eq": "assert (d.verdict,)[0] == d.verdict",
}

# The answer is asserted in the accepted form; the side check reads no
# answer, so the blocklist judges it and must not over-reject it.
SELF_IN_DISGUISE_CLEAN = {
    "two-different-listings": "assert d.verdict is Verdict.DENY\nassert os.listdir('.') == os.listdir('..')",
}

# Entries of SELF_IN_DISGUISE_CLEAN whose answer assert the allowlist now refuses.
SELF_IN_DISGUISE_CLEAN_REFUSED_BY_ALLOWLIST = {
    "walrus-then-real-compare": "assert (y := d.verdict) is Verdict.DENY",
    "in-other-values": "assert d.verdict in (Verdict.DENY, Verdict.ASK)",
    "len-of-a-real-list": "assert len(d.reason) == 1",
    "len-of-starred-set": "assert len({*d.reason}) == 1",
    "element-compared-with-answer": "assert [d.verdict][0] is Verdict.DENY",
}


@pytest.mark.parametrize("shape", sorted(SELF_IN_DISGUISE))
def test_an_expression_compared_with_itself_in_disguise_is_rejected(
    tmp_path: Path, shape: str
) -> None:
    _expect(tmp_path, _plain(SELF_IN_DISGUISE[shape]), "assert in a KAT file")


@pytest.mark.parametrize("shape", sorted(SELF_IN_DISGUISE_CLEAN))
def test_a_compare_that_reads_the_answer_stays_clean(
    tmp_path: Path, shape: str
) -> None:
    r = _lint(_write(tmp_path, "test_k_case.py", _plain(SELF_IN_DISGUISE_CLEAN[shape])))
    assert r.returncode == 0, r.stdout


@pytest.mark.parametrize("shape", sorted(SELF_IN_DISGUISE_CLEAN_REFUSED_BY_ALLOWLIST))
def test_a_compare_that_reads_the_answer_refused_by_the_answer_allowlist(
    tmp_path: Path, shape: str
) -> None:
    r = _lint(
        _write(
            tmp_path,
            "test_k_case.py",
            _plain(SELF_IN_DISGUISE_CLEAN_REFUSED_BY_ALLOWLIST[shape]),
        )
    )
    _assert_refused(r)


# --- always-pass review round: a constant routed through a call --------------------
# An inline lambda called on the spot, functools.partial of a pure builtin with
# constant arguments, a same-file identity helper and an instance method of a
# same-file class that returns a constant all fold. Each fiat form sits beside a
# valid assert on the answer, so only folding can catch it.

ROUTED_PRELUDE = """

import functools


def ident(x):
    return x


class Fixed:
    def value(self):
        return False

    def yes(self):
        return True

    def same(self, x):
        return x
"""

ROUTED_CONSTANT = {
    "inline-lambda-false": (
        _kat("assert (lambda: False)()", ROUTED_PRELUDE),
        "fails by fiat",
    ),
    "partial-bool-zero": (
        _kat("assert functools.partial(bool, 0)()", ROUTED_PRELUDE),
        "fails by fiat",
    ),
    "identity-helper-false": (
        _kat("assert ident(False)", ROUTED_PRELUDE),
        "fails by fiat",
    ),
    "instance-method-false": (
        _kat("assert Fixed().value()", ROUTED_PRELUDE),
        "fails by fiat",
    ),
    "inline-lambda-true-or": (
        _plain("assert (lambda: True)() or d.verdict is Verdict.DENY", ROUTED_PRELUDE),
        "assert in a KAT file",
    ),
    "partial-bool-one-or": (
        _plain("assert functools.partial(bool, 1)() or d.reason", ROUTED_PRELUDE),
        "assert in a KAT file",
    ),
    "identity-helper-true-or": (
        _plain("assert ident(True) or d.reason", ROUTED_PRELUDE),
        "assert in a KAT file",
    ),
    "instance-method-true-or": (
        _plain("assert Fixed().yes() or d.reason", ROUTED_PRELUDE),
        "assert in a KAT file",
    ),
}

# The answer is asserted in the accepted form; the side check reads no
# answer, so the blocklist judges it and must not over-reject it.
ROUTED_CONSTANT_CLEAN = {
    "call-on-a-side-value": _kat(
        "def count(path):\n    return len(os.listdir(path))\nassert count('.') == 3"
    ),
}

# Entries of ROUTED_CONSTANT_CLEAN whose answer assert the allowlist now refuses.
ROUTED_CONSTANT_CLEAN_REFUSED_BY_ALLOWLIST = {
    "identity-of-the-answer": _plain(
        "assert ident(d.verdict) is Verdict.DENY", ROUTED_PRELUDE
    ),
    "method-of-the-answer": _plain(
        "assert Fixed().same(d.verdict) is Verdict.DENY", ROUTED_PRELUDE
    ),
    "lambda-of-the-answer": _plain(
        "assert (lambda v: v)(d.verdict) is Verdict.DENY", ROUTED_PRELUDE
    ),
}


@pytest.mark.parametrize("shape", sorted(ROUTED_CONSTANT))
def test_a_constant_routed_through_a_call_folds(tmp_path: Path, shape: str) -> None:
    src, reason = ROUTED_CONSTANT[shape]
    _expect(tmp_path, src, reason)


@pytest.mark.parametrize("shape", sorted(ROUTED_CONSTANT_CLEAN))
def test_a_call_on_the_answer_stays_clean(tmp_path: Path, shape: str) -> None:
    r = _lint(_write(tmp_path, "test_k_case.py", ROUTED_CONSTANT_CLEAN[shape]))
    assert r.returncode == 0, r.stdout


@pytest.mark.parametrize("shape", sorted(ROUTED_CONSTANT_CLEAN_REFUSED_BY_ALLOWLIST))
def test_a_call_on_the_answer_refused_by_the_answer_allowlist(
    tmp_path: Path, shape: str
) -> None:
    r = _lint(
        _write(
            tmp_path,
            "test_k_case.py",
            ROUTED_CONSTANT_CLEAN_REFUSED_BY_ALLOWLIST[shape],
        )
    )
    _assert_refused(r)


# --- always-pass review round: an assert in a while-True else never runs ----------
# The else of a while loop runs only when its test turns false. A test that folds
# true never does, so an assert there is dead, and a KAT whose only assert on the
# answer sits there never asserts on it.

DEAD_LOOP_ELSE = {
    "while-true-break-else": (
        "while True:\n    break\nelse:\n    assert d.verdict is Verdict.DENY"
    ),
    "while-one-break-else": (
        "while 1:\n    break\nelse:\n    assert d.verdict is Verdict.DENY"
    ),
    "while-true-conditional-break-else": (
        "while True:\n    if d:\n        break\nelse:\n    assert d.verdict is Verdict.DENY"
    ),
}

# The answer is asserted in the accepted form; the side check reads no
# answer, so the blocklist judges it and must not over-reject it.
LIVE_LOOP_ELSE = {
    "side-check-in-a-live-loop-else": "assert d.verdict is Verdict.DENY\nfor _ in ('x',):\n    pass\nelse:\n    assert len(os.listdir('.')) >= 1",
}

# Entries of LIVE_LOOP_ELSE whose answer assert the allowlist now refuses.
LIVE_LOOP_ELSE_REFUSED_BY_ALLOWLIST = {
    "while-false-else": (
        "while False:\n    pass\nelse:\n    assert d.verdict is Verdict.DENY"
    ),
    "while-on-the-answer-else": (
        "while not d.reason:\n    break\nelse:\n    assert d.verdict is Verdict.DENY"
    ),
    "for-else": "for _ in ():\n    pass\nelse:\n    assert d.verdict is Verdict.DENY",
}


@pytest.mark.parametrize("shape", sorted(DEAD_LOOP_ELSE))
def test_an_assert_in_a_while_true_else_is_dead(tmp_path: Path, shape: str) -> None:
    _expect(
        tmp_path, _plain(DEAD_LOOP_ELSE[shape]), "never asserts on the gate's result"
    )


@pytest.mark.parametrize("shape", sorted(LIVE_LOOP_ELSE))
def test_an_assert_in_a_live_loop_else_stays_clean(tmp_path: Path, shape: str) -> None:
    r = _lint(_write(tmp_path, "test_k_case.py", _plain(LIVE_LOOP_ELSE[shape])))
    assert r.returncode == 0, r.stdout


@pytest.mark.parametrize("shape", sorted(LIVE_LOOP_ELSE_REFUSED_BY_ALLOWLIST))
def test_an_assert_in_a_live_loop_else_refused_by_the_answer_allowlist(
    tmp_path: Path, shape: str
) -> None:
    r = _lint(
        _write(
            tmp_path,
            "test_k_case.py",
            _plain(LIVE_LOOP_ELSE_REFUSED_BY_ALLOWLIST[shape]),
        )
    )
    _assert_refused(r)


# --- review round: class aliases, rebinding stores, coding aliases ----------------

FAKE_PRELUDE = """

class Fake:
    verdict = Verdict.DENY
"""

CLASS_ALIAS_PATCH = {
    "class-alias-setattr": _first(
        "k = gate.__class__\nsetattr(k, 'evaluate', lambda *a, **kw: None)"
    ),
    "class-alias-store": _first("k = type(gate)\nk.evaluate = lambda *a, **kw: None"),
    "type-of-gate-store": _first("type(gate).evaluate = lambda *a, **kw: None"),
    "mro-first-store": _first("type(gate).__mro__[0].evaluate = lambda *a, **kw: None"),
    "class-alias-mro-setattr": _first(
        "k = type(gate).__mro__[0]\nsetattr(k, 'evaluate', lambda *a, **kw: None)"
    ),
}

RESULT_REBOUND_BY_STORE = {
    "tuple-unpack-rebind": _plain(
        "d, = (Fake(),)\nassert d.verdict is Verdict.DENY", FAKE_PRELUDE
    ),
    "list-unpack-rebind": _plain(
        "[d] = [Fake()]\nassert d.verdict is Verdict.DENY", FAKE_PRELUDE
    ),
    "for-loop-rebind": _plain(
        "for d in [Fake()]:\n    pass\nassert d.verdict is Verdict.DENY",
        FAKE_PRELUDE,
    ),
}

STORES_THAT_KEEP_THE_ANSWER = {
    "class-alias-of-another-object": _first(
        "k = type(tmp_path)\nk.zqxwvk = 1", params="gate, tmp_path"
    ),
}

# Entries of STORES_THAT_KEEP_THE_ANSWER whose answer assert the allowlist now refuses.
STORES_THAT_KEEP_THE_ANSWER_REFUSED_BY_ALLOWLIST = {
    "unpack-of-the-answer": _plain("d, = (d,)\nassert d.verdict is Verdict.DENY"),
    "loop-over-the-answer": _plain(
        "for d in [d]:\n    pass\nassert d.verdict is Verdict.DENY"
    ),
}


@pytest.mark.parametrize("shape", sorted(CLASS_ALIAS_PATCH))
def test_patching_the_gate_class_through_an_alias_is_rejected(
    tmp_path: Path, shape: str
) -> None:
    _expect(tmp_path, CLASS_ALIAS_PATCH[shape], "patches the gate at line")


@pytest.mark.parametrize("shape", sorted(RESULT_REBOUND_BY_STORE))
def test_a_result_rebound_by_any_store_stops_counting(
    tmp_path: Path, shape: str
) -> None:
    _expect(
        tmp_path, RESULT_REBOUND_BY_STORE[shape], "never asserts on the gate's result"
    )


@pytest.mark.parametrize("shape", sorted(STORES_THAT_KEEP_THE_ANSWER))
def test_a_store_that_keeps_the_answer_stays_clean(tmp_path: Path, shape: str) -> None:
    r = _lint(_write(tmp_path, "test_k_case.py", STORES_THAT_KEEP_THE_ANSWER[shape]))
    assert r.returncode == 0, r.stdout


@pytest.mark.parametrize(
    "shape", sorted(STORES_THAT_KEEP_THE_ANSWER_REFUSED_BY_ALLOWLIST)
)
def test_a_store_that_keeps_the_answer_refused_by_the_answer_allowlist(
    tmp_path: Path, shape: str
) -> None:
    r = _lint(
        _write(
            tmp_path,
            "test_k_case.py",
            STORES_THAT_KEEP_THE_ANSWER_REFUSED_BY_ALLOWLIST[shape],
        )
    )
    _assert_refused(r)


@pytest.mark.parametrize("cookie", ["utf8", "utf_8", "U8", "UTF8", "utf-8", "UTF-8"])
def test_every_spelling_of_the_utf8_cookie_stays_clean(
    tmp_path: Path, cookie: str
) -> None:
    src = f"# coding: {cookie}\n" + _kat("")
    r = _lint(_write(tmp_path, "test_k_case.py", src))
    assert r.returncode == 0, r.stdout


# --- the answer allowlist: an assert that reads the gate's answer has one form --
# An assert that reads a gate result counts only as a single == or is between the
# result's verdict and a Verdict member or verdict string. A few named richer
# forms are accepted beside it; anything else that reads the answer is refused.

_ANSWER_REFUSED = "not an accepted assert on the gate's answer"
_NO_ANSWER = "never asserts on the gate's result in the accepted form"

ANSWER_ACCEPTED = {
    "is_member": "assert d.verdict is Verdict.DENY",
    "member_first": "assert Verdict.DENY is d.verdict",
    "inline_call": "assert gate.evaluate('s', 'read_file', ['x']).verdict is Verdict.DENY",
    "verdict_name": "v = d.verdict\nassert v is Verdict.DENY",
    "named_reason_substring": "assert 'not' in d.reason",
    "named_enforced_flag": "assert d.enforced is True",
    "named_paths_literal": "assert d.paths == ('zqxwvk',)",
    "named_throw_answer": "assert gate.throw('drill') is True",
}


@pytest.mark.parametrize("shape", sorted(ANSWER_ACCEPTED))
def test_an_accepted_answer_assert_stays_clean(tmp_path: Path, shape: str) -> None:
    r = _lint(_write(tmp_path, "test_k_case.py", _kat(ANSWER_ACCEPTED[shape])))
    assert r.returncode == 0, r.stdout


# Every shape the reviews listed, and the earlier rounds' refused shapes, read
# the answer in a form outside the allowlist; each is refused by name.
ANSWER_PROBES = {
    "bound_partial": "import functools\nchk = functools.partial(lambda a, b: True, d.verdict)\nassert chk(Verdict.DENY)",
    "keyword_partial": "import functools\nchk = functools.partial(lambda a=None, b=None: True, a=d)\nassert chk(b=1)",
    "method_through_a_variable": "class C:\n    def __init__(s, x):\n        s.x = x\n    def v(s):\n        return True\nc = C(d)\nassert c.v()",
    "property": "class P:\n    def __init__(s, x):\n        s.x = x\n    @property\n    def ok(s):\n        return True\nassert P(d).ok",
    "classmethod": "class Q:\n    @classmethod\n    def ok(cls, x):\n        return True\nassert Q.ok(d)",
    "keyword_identity_helper": "def ident(x=None):\n    return x\nassert ident(x=d) is ident(x=d)",
    "default_identity_helper": "def ident(x, y=d):\n    return y\nassert ident(1) is d",
    "helper_chain": "def a(x):\n    return b(x)\ndef b(x):\n    return True\nassert a(d)",
    "lt_ge_pair": "assert d.verdict < 'zzz' or d.verdict >= 'zzz'",
    "bool_p_or_not_p": "assert bool(d.verdict is Verdict.DENY or not d.verdict is Verdict.DENY)",
    "xor": "assert (d.verdict is Verdict.DENY) ^ (d.verdict is not Verdict.DENY)",
    "bitwise_or": "assert (d.verdict is Verdict.DENY) | True",
    "ternary": "assert d.verdict is Verdict.DENY if d else True",
    "comprehension": "assert [x for x in [d]]",
    "constructor": "assert list([d])",
    "format_call": "assert '{}'.format(d)",
    "percent_format": "assert '%s' % (d,)",
    "plus_str": "assert '' + str(d)",
    "ascii": "assert ascii(d)",
    "getattr_default": "assert getattr(d, 'zqxwvk', True)",
    "any_trick": "assert any([d, True])",
    "max_trick": "assert max(1, d is d)",
    "sum_trick": "assert sum([1, d is d])",
    "tuple_of_verdict": "assert d.verdict in tuple(Verdict)",
    "all_of_empty_generator": "assert all(x for x in () if d)",
    "dict_get_is": "assert {1: d}.get(1) is d",
    "comprehension_fake": "assert [d][0] is [d for _ in (1,)][0]",
    "sorted_display": "assert sorted([d.verdict])",
    "repeated_display": "assert [d] * 1",
    "dict_index_is": "assert {1: d}[1] is d",
    "compared_with_itself": "assert d.verdict == d.verdict",
    "itself_or_true": "assert d.verdict is d.verdict or True",
    "isinstance_object": "assert isinstance(d, object)",
    "starred_display": "assert (*[d],)",
    "f_string": "assert f'{d}'",
    "every_member": "assert d.verdict in (Verdict.ALLOW, Verdict.DENY, Verdict.ASK)",
    "length_of_display": "assert len([d]) == 1",
    "not_p_and_not_p": "assert not (d and not d)",
    "not_equal": "assert d.verdict != Verdict.ALLOW",
    "is_not": "assert d.verdict is not Verdict.ALLOW",
    "chained_compare": "assert Verdict.DENY == d.verdict == Verdict.DENY",
    "walrus": "assert (v := d.verdict) is v",
    "subscript": "assert [d.verdict][0] is Verdict.DENY",
    "membership_one": "assert d.verdict in (Verdict.DENY,)",
}


@pytest.mark.parametrize("shape", sorted(ANSWER_PROBES))
def test_every_reviewed_shape_that_reads_the_answer_is_refused(
    tmp_path: Path, shape: str
) -> None:
    _expect(tmp_path, _kat(ANSWER_PROBES[shape]), _ANSWER_REFUSED)


def _kat_without_answer(body: str) -> str:
    lines = [
        "    d = gate.evaluate('s', 'read_file', ['zqxwvk'])",
        *("    " + x for x in body.splitlines()),
    ]
    return KAT_HEAD + "\n\n\ndef test_k_case(gate):\n" + "\n".join(lines) + "\n"


# Only an accepted assert on the test's own straight path satisfies a KAT.
ANSWER_MISSING = {
    "helper_assert": "def check(x):\n    assert x.verdict is Verdict.DENY\ncheck(d)",
    "not_equal_only": "assert d.verdict != Verdict.ALLOW",
    "membership_only": "assert d.verdict in (Verdict.DENY,)",
    "for_else_dead": "for _ in (1,):\n    break\nelse:\n    assert d.verdict is Verdict.DENY",
    "named_form_only": "assert 'zqxwvk' in d.reason",
    "under_a_branch": "if d:\n    assert d.verdict is Verdict.DENY",
}


@pytest.mark.parametrize("shape", sorted(ANSWER_MISSING))
def test_a_kat_without_an_accepted_answer_assert_on_its_path_is_refused(
    tmp_path: Path, shape: str
) -> None:
    _expect(tmp_path, _kat_without_answer(ANSWER_MISSING[shape]), _NO_ANSWER)


# BH101-4: every way a test can rebind the result name takes it out.
REBINDS_OF_THE_RESULT = {
    "with-as": "import contextlib\nwith contextlib.nullcontext(Verdict.DENY) as d:\n    pass\nassert d.verdict is Verdict.DENY",
    "except-as": "try:\n    raise ValueError(Verdict.DENY)\nexcept ValueError as d:\n    pass\nassert d.verdict is Verdict.DENY",
    "import-as": "import os as d\nassert d.verdict is Verdict.DENY",
    "from-import-as": "from os import sep as d\nassert d.verdict is Verdict.DENY",
    "globals-store": "globals()['d'] = None\nassert d.verdict is Verdict.DENY",
    "globals-store-of-a-built-name": "globals()['d' + ''] = None\nassert d.verdict is Verdict.DENY",
}


@pytest.mark.parametrize("shape", sorted(REBINDS_OF_THE_RESULT))
def test_every_rebind_of_the_result_name_takes_it_out(
    tmp_path: Path, shape: str
) -> None:
    _expect(tmp_path, _kat_without_answer(REBINDS_OF_THE_RESULT[shape]), _NO_ANSWER)


def test_an_import_or_handler_name_that_is_not_the_result_stays_clean(
    tmp_path: Path,
) -> None:
    body = (
        "import os as other\n"
        "try:\n    raise ValueError('x')\nexcept ValueError as err:\n    pass\n"
        "assert d.verdict is Verdict.DENY"
    )
    r = _lint(_write(tmp_path, "test_k_case.py", _kat_without_answer(body)))
    assert r.returncode == 0, r.stdout


# BH101-5: the gate's class reached through any alias the result tracking sees.
GATE_CLASS_ALIASES = {
    "unpacking": "k, = (type(gate),)\nsetattr(k, 'evaluate', lambda *a, **kw: None)",
    "list-unpacking": "[k] = [gate.__class__]\nk.evaluate = lambda *a, **kw: None",
    "for-target": "for k in (type(gate),):\n    setattr(k, 'evaluate', lambda *a, **kw: None)",
    "walrus": "(k := type(gate))\nk.evaluate = lambda *a, **kw: None",
    "helper-returning-type": "def cls(x):\n    return type(x)\nk = cls(gate)\nk.evaluate = lambda *a, **kw: None",
    "bases": "setattr(type(gate).__bases__[0], 'evaluate', lambda *a, **kw: None)",
    "bases-through-a-name": "k = type(gate)\nb = k.__bases__[0]\nb.evaluate = lambda *a, **kw: None",
}


@pytest.mark.parametrize("shape", sorted(GATE_CLASS_ALIASES))
def test_the_gate_class_through_any_alias_is_a_gate_patch(
    tmp_path: Path, shape: str
) -> None:
    src = _kat_without_answer(
        GATE_CLASS_ALIASES[shape] + "\nd = gate.evaluate('s', 'read_file', ['zqxwvk'])"
        "\nassert d.verdict is Verdict.DENY"
    )
    _expect(tmp_path, src, "patches the gate")


def test_a_class_alias_of_something_else_is_not_a_gate_patch(tmp_path: Path) -> None:
    body = (
        "for k in (int,):\n    pass\n"
        "def cls(x):\n    return type(x)\n"
        "kind = cls(1)\n"
        "assert d.verdict is Verdict.DENY"
    )
    r = _lint(_write(tmp_path, "test_k_case.py", _kat_without_answer(body)))
    assert r.returncode == 0, r.stdout


# Discovery never follows a symlinked folder (the floor guard also refuses any
# link in the tree); the walk says so explicitly.
def test_discovery_does_not_follow_symlinked_folders(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sys.path.insert(0, str(SCRIPT.parent))
    import kat_lint

    calls: list[dict] = []
    real_walk = os.walk

    def spy(top, *args, **kwargs):
        calls.append(kwargs)
        return real_walk(top, *args, **kwargs)

    monkeypatch.setattr(os, "walk", spy)
    (tmp_path / "tests").mkdir()
    kat_lint.discover(tmp_path)
    assert calls, "discovery never walked a folder"
    assert all(c.get("followlinks") is False for c in calls), calls


# A pytest.xfail, skip, fail or exit called on the straight path ends it: the
# answer assert after it never runs.
ENDS_THE_TEST = {
    "xfail": "pytest.xfail('zqxwvk')",
    "skip": "pytest.skip('zqxwvk')",
    "fail": "pytest.fail('zqxwvk')",
    "exit": "pytest.exit('zqxwvk')",
}


@pytest.mark.parametrize("shape", sorted(ENDS_THE_TEST))
def test_an_assert_after_an_imperative_outcome_never_runs(
    tmp_path: Path, shape: str
) -> None:
    body = ENDS_THE_TEST[shape] + "\nassert d.verdict is Verdict.DENY"
    _expect(tmp_path, _kat_without_answer(body), _NO_ANSWER)


# Each named richer form holds only with its own literal on the other side.
NAMED_FORMS_WITH_THE_WRONG_SIDE = {
    "enforced-against-a-string": "assert d.enforced == 'zqxwvk'",
    "enforced-against-the-reason": "assert d.enforced is d.reason",
    "paths-against-the-reason": "assert d.paths == (d.reason,)",
    "paths-against-a-number": "assert d.paths == (1,)",
}


@pytest.mark.parametrize("shape", sorted(NAMED_FORMS_WITH_THE_WRONG_SIDE))
def test_a_named_form_with_the_wrong_side_is_refused(
    tmp_path: Path, shape: str
) -> None:
    body = "assert d.verdict is Verdict.DENY\n" + NAMED_FORMS_WITH_THE_WRONG_SIDE[shape]
    _expect(tmp_path, _kat_without_answer(body), _ANSWER_REFUSED)


# A globals() store under a key the lint cannot fold may be any name.
def test_a_globals_store_under_an_unknown_key_takes_every_name_out(
    tmp_path: Path,
) -> None:
    # It may rebind Verdict or the gate class as well, so the KAT is refused
    # however the rest of it reads.
    body = "globals()[os.environ.get('ZQXWVK', 'd')] = None\nassert d.verdict is Verdict.DENY"
    _rejected(_lint(_write(tmp_path, "test_k_case.py", _kat_without_answer(body))))


_FIXTURE_RESULT = (
    KAT_HEAD + "\n@pytest.fixture()\ndef decision(gate):\n"
    "    return gate.evaluate('s', 'read_file', ['zqxwvk'])\n\n\n"
    "def test_k_case(decision):\n"
)


# A fixture that returns the gate's result stops counting once the test
# stores to its parameter.
def test_a_result_fixture_rebound_in_the_test_is_not_an_answer(tmp_path: Path) -> None:
    src = (
        _FIXTURE_RESULT
        + "    decision = None\n    assert decision.verdict is Verdict.DENY\n"
    )
    _expect(tmp_path, src, _NO_ANSWER)


def test_a_result_fixture_left_alone_is_an_answer(tmp_path: Path) -> None:
    src = _FIXTURE_RESULT + "    assert decision.verdict is Verdict.DENY\n"
    r = _lint(_write(tmp_path, "test_k_case.py", src))
    assert r.returncode == 0, r.stdout


# --- review round on #101 at 2966616. Each case lints green at 2966616 and, under
# --- pytest against the real gate, passes while the gate's answer is not the one
# --- asserted. Every one must be rejected.

_FAKE = "class _Fake:\n    verdict = Verdict.DENY"
_CALL = "gate.evaluate('s', 'read_file', ['zqxwvk'])"


def _src(prelude: str, params: str, body: str, deco: str = "") -> str:
    """KAT_HEAD, a prelude, and one test with the given body."""
    lines = "".join(f"    {x}\n" for x in body.splitlines())
    return (
        KAT_HEAD
        + prelude
        + "\n\n\n"
        + (deco + "\n" if deco else "")
        + f"def test_k_case({params}):\n"
        + lines
    )


def _fixture(body: str) -> str:
    return (
        _FAKE
        + "\n\n\n@pytest.fixture()\ndef decision(gate):\n"
        + "".join(f"    {x}\n" for x in body.splitlines())
    )


def _rejected(r) -> None:
    assert r.returncode == 1, r.stdout + r.stderr
    assert "Traceback" not in r.stderr, r.stderr


# Item 1: a helper's or fixture's return counts only if it is the gate call or a
# name that only ever holds a gate result.
PROVENANCE_REJECTED = {
    "helper-returns-something-else": _src(
        _FAKE + f"\n\n\ndef _attempt(gate):\n    {_CALL}\n    return _Fake()",
        "gate",
        "assert _attempt(gate).verdict is Verdict.DENY",
    ),
    "helper-result-bound-to-a-name": _src(
        _FAKE + f"\n\n\ndef _attempt(gate):\n    {_CALL}\n    return _Fake()",
        "gate",
        "d = _attempt(gate)\nassert d.verdict is Verdict.DENY",
    ),
    "helper-returns-a-copy": _src(
        "import dataclasses\n\n\ndef _attempt(gate):\n"
        f"    r = {_CALL}\n"
        "    return dataclasses.replace(r, verdict=Verdict.DENY)",
        "gate",
        "assert _attempt(gate).verdict is Verdict.DENY",
    ),
    "helper-returns-result-or-something-else": _src(
        _FAKE + f"\n\n\ndef _attempt(gate):\n    r = {_CALL}\n"
        "    return r if r.verdict is Verdict.DENY else _Fake()",
        "gate",
        "assert _attempt(gate).verdict is Verdict.DENY",
    ),
    "helper-with-one-other-return": _src(
        _FAKE + "\n\n\ndef _attempt(gate):\n    if os.environ.get('ZQXWVK'):\n"
        f"        return _Fake()\n    return {_CALL}",
        "gate",
        "assert _attempt(gate).verdict is Verdict.DENY",
    ),
    "fixture-returns-something-else": _src(
        _fixture(f"{_CALL}\nreturn _Fake()"),
        "decision",
        "assert decision.verdict is Verdict.DENY",
    ),
    "fixture-yields-something-else": _src(
        _fixture(f"{_CALL}\nyield _Fake()"),
        "decision",
        "assert decision.verdict is Verdict.DENY",
    ),
}
PROVENANCE_CLEAN = {
    "helper-returns-the-gate-call": _src(
        f"def _attempt(gate):\n    return {_CALL}",
        "gate",
        "assert _attempt(gate).verdict is Verdict.DENY",
    ),
    "helper-returns-a-result-name": _src(
        f"def _attempt(gate):\n    r = {_CALL}\n    return r",
        "gate",
        "assert _attempt(gate).verdict is Verdict.DENY",
    ),
    "helper-returns-an-answering-helper": _src(
        "def _attempt(gate):\n    return _inner(gate)\n\n\n"
        f"def _inner(gate):\n    return {_CALL}",
        "gate",
        "d = _attempt(gate)\nassert d.verdict is Verdict.DENY",
    ),
    "fixture-yields-the-gate-call": _src(
        f"@pytest.fixture()\ndef decision(gate):\n    yield {_CALL}",
        "decision",
        "assert decision.verdict is Verdict.DENY",
    ),
}


@pytest.mark.parametrize("shape", sorted(PROVENANCE_REJECTED))
def test_a_return_that_is_not_the_gate_call_is_not_the_answer(
    tmp_path: Path, shape: str
) -> None:
    _assert_refused(
        _lint(_write(tmp_path, "test_k_case.py", PROVENANCE_REJECTED[shape]))
    )


@pytest.mark.parametrize("shape", sorted(PROVENANCE_CLEAN))
def test_a_return_that_is_the_gate_call_is_the_answer(
    tmp_path: Path, shape: str
) -> None:
    r = _lint(_write(tmp_path, "test_k_case.py", PROVENANCE_CLEAN[shape]))
    assert r.returncode == 0, r.stdout


# Item 2: every binding form Python has takes a name out of "only ever holds a
# result". Item 5: so does any store into a result.
REBIND_BODIES = {
    "match-capture": "match 0:\n    case d:\n        pass",
    "match-as": "match 0:\n    case int() as d:\n        pass",
    "match-star": "match [0]:\n    case [*d]:\n        pass",
    "match-mapping-rest": "match {}:\n    case {**d}:\n        pass",
    "class-rebinding": "class d:\n    verdict = Verdict.DENY",
    "def-rebinding": "def d():\n    pass",
    "nonlocal-in-a-nested-def": (
        "def _swap():\n    nonlocal d\n    d = _Fake()\n_swap()"
    ),
    "walrus": "(d := _Fake())",
    "attribute-store": "d.verdict = Verdict.DENY",
    "setattr": "setattr(d, 'verdict', Verdict.DENY)",
    "object-setattr": "object.__setattr__(d, 'verdict', Verdict.DENY)",
    "dict-setitem": "d.__dict__['verdict'] = Verdict.DENY",
    "dict-update": "d.__dict__.update(verdict=Verdict.DENY)",
    "vars-setitem": "vars(d)['verdict'] = Verdict.DENY",
    "vars-update": "vars(d).update(verdict=Verdict.DENY)",
}


@pytest.mark.parametrize("shape", sorted(REBIND_BODIES))
def test_every_binding_form_and_store_takes_a_result_name_out(
    tmp_path: Path, shape: str
) -> None:
    body = f"d = {_CALL}\n{REBIND_BODIES[shape]}\nassert d.verdict is Verdict.DENY"
    _expect(tmp_path, _src(_FAKE, "gate", body), _NO_ANSWER)


def test_a_walrus_in_the_gate_class_alias_walk_is_a_gate_patch(tmp_path: Path) -> None:
    body = (
        "(G := Gate)\nG.evaluate = lambda *a, **k: _Fake()\n"
        f"d = {_CALL}\nassert d.verdict is Verdict.DENY"
    )
    _expect(tmp_path, _src(_FAKE, "gate", body), "patches the gate")


# Item 9: a global declaration in the test takes the name out (the store branch
# for global and nonlocal).
def test_a_global_declaration_takes_a_result_name_out(tmp_path: Path) -> None:
    body = f"global d\nd = {_CALL}\nassert d.verdict is Verdict.DENY"
    _expect(tmp_path, _src("", "gate", body), _NO_ANSWER)


# Item 3: any statement that may leave the test ends the straight path.
MAY_LEAVE = {
    "conditional-return": "if os.environ.get('ZQXWVK'):\n    return",
    "conditional-skip": "if os.environ.get('ZQXWVK'):\n    pytest.skip('x')",
    "handler-returns": "try:\n    os.listdir('zqxwvk')\nexcept OSError:\n    return",
    "handler-skips": "try:\n    os.listdir('zqxwvk')\nexcept OSError:\n    pytest.skip('x')",
    "loop-body-returns": "for _ in os.listdir('.'):\n    return",
    "while-body-returns": "while os.environ.get('ZQXWVK'):\n    return",
    "with-body-returns": (
        "with open(os.devnull):\n    if os.environ.get('ZQXWVK'):\n        return"
    ),
    "match-case-returns": "match os.name:\n    case 'nt':\n        return",
}


@pytest.mark.parametrize("shape", sorted(MAY_LEAVE))
def test_a_statement_that_may_leave_the_test_ends_the_straight_path(
    tmp_path: Path, shape: str
) -> None:
    body = f"d = {_CALL}\n{MAY_LEAVE[shape]}\nassert d.verdict is Verdict.DENY"
    _expect(tmp_path, _src("", "gate", body), _NO_ANSWER)


def test_a_statement_that_may_leave_after_the_assert_stays_clean(
    tmp_path: Path,
) -> None:
    body = (
        f"d = {_CALL}\nassert d.verdict is Verdict.DENY\n"
        "if os.environ.get('ZQXWVK'):\n    return"
    )
    r = _lint(_write(tmp_path, "test_k_case.py", _src("", "gate", body)))
    assert r.returncode == 0, r.stdout


# Item 4: the Verdict token must be the real capability_gate.Verdict.
VERDICT_STAND_INS = {
    "local-class": ("class Verdict:\n    DENY = 'deny'", "gate", ""),
    "namespace": (
        "import types\n\nVerdict = types.SimpleNamespace(DENY=object())",
        "gate",
        "",
    ),
    "globals-injected": (
        "globals()['Verdict'] = type('V', (), {'DENY': None})",
        "gate",
        "",
    ),
    "imported-from-elsewhere": ("from zqxwvk_fake import Verdict", "gate", ""),
    "sys-modules-swap": (
        "import types\n\nsys.modules['capability_gate'] = types.ModuleType('x')",
        "gate",
        "",
    ),
    "sys-modules-monkeypatched": (
        "",
        "gate, monkeypatch",
        "monkeypatch.setitem(sys.modules, 'capability_gate', None)",
    ),
    "member-store": ("", "gate", "Verdict.DENY = d.verdict"),
    "member-setattr": ("", "gate", "setattr(Verdict, 'DENY', d.verdict)"),
    "eq-override": ("", "gate", "Verdict.__eq__ = lambda a, b: True"),
    # Verdict rebound through this module's own object.
    "module-attribute-store": (
        "class _NS:\n    DENY = None",
        "gate",
        "sys.modules[__name__].Verdict = _NS",
    ),
    "module-setattr": (
        "class _NS:\n    DENY = None",
        "gate",
        "setattr(sys.modules[__name__], 'Verdict', _NS)",
    ),
    "module-dict-store": (
        "class _NS:\n    DENY = None",
        "gate",
        "sys.modules[__name__].__dict__['Verdict'] = _NS",
    ),
    "module-alias-store": (
        "class _NS:\n    DENY = None",
        "gate",
        "me = sys.modules[__name__]\nme.Verdict = _NS",
    ),
    "globals-update": (
        "class _NS:\n    DENY = None",
        "gate",
        "globals().update(Verdict=_NS)",
    ),
    "globals-setdefault": (
        "class _NS:\n    DENY = None",
        "gate",
        "globals().setdefault('Verdict', _NS)",
    ),
    "globals-ior": (
        "class _NS:\n    DENY = None",
        "gate",
        "g = globals()\ng |= {'Verdict': _NS}",
    ),
}


# The assert is the accepted form, by identity, so only the stand-in can be what
# the lint refuses.
@pytest.mark.parametrize("shape", sorted(VERDICT_STAND_INS))
def test_a_verdict_that_is_not_the_real_one_is_not_an_answer(
    tmp_path: Path, shape: str
) -> None:
    prelude, params, extra = VERDICT_STAND_INS[shape]
    body = f"d = {_CALL}\n{extra}\nassert d.verdict is Verdict.DENY".replace(
        "\n\n", "\n"
    )
    _rejected(_lint(_write(tmp_path, "test_k_case.py", _src(prelude, params, body))))


# Item 6: pytest must run the test the lint read.
def test_a_non_pytest_decorator_on_a_kat_is_rejected(tmp_path: Path) -> None:
    src = _src(
        "def _keep(fn):\n    return lambda *a, **k: None",
        "gate",
        f"d = {_CALL}\nassert d.verdict is Verdict.DENY",
        deco="@_keep",
    )
    _expect(tmp_path, src, "has a decorator other than a pytest mark")


def test_a_rebound_test_name_is_rejected(tmp_path: Path) -> None:
    src = _kat("") + "\n\ntest_k_case = lambda gate: None\n"
    _expect(tmp_path, src, "test_k_case is defined more than once")


def test_a_pytest_mark_on_a_kat_stays_clean(tmp_path: Path) -> None:
    src = _kat("", deco="@pytest.mark.parametrize('n', [1])", params="gate, n")
    r = _lint(_write(tmp_path, "test_k_case.py", src))
    assert r.returncode == 0, r.stdout


# Item 7: patching any capability_gate module attribute patches the gate.
INTERNAL_PATCHES = {
    "assign-decide": (
        "import capability_gate",
        "gate",
        "capability_gate._decide = None",
    ),
    "monkeypatch-path-allowed": (
        "import capability_gate",
        "gate, monkeypatch",
        "monkeypatch.setattr(capability_gate, '_path_allowed', lambda *a: True)",
    ),
    "monkeypatch-dotted-string": (
        "",
        "gate, monkeypatch",
        "monkeypatch.setattr('capability_gate._decide', lambda *a: None)",
    ),
    "setattr-decide": (
        "import capability_gate",
        "gate",
        "setattr(capability_gate, '_decide', None)",
    ),
    # Allowed before this round: any module attribute now counts.
    "monkeypatch-other-module-attr": (
        "import capability_gate",
        "gate, monkeypatch",
        "monkeypatch.setattr(capability_gate, '_zqxwvk', print)",
    ),
    "setattr-through-sys-modules": (
        "",
        "gate",
        "setattr(sys.modules['capability_gate'], '_zqxwvk', object)",
    ),
}


@pytest.mark.parametrize("shape", sorted(INTERNAL_PATCHES))
def test_patching_a_capability_gate_internal_patches_the_gate(
    tmp_path: Path, shape: str
) -> None:
    prelude, params, line = INTERNAL_PATCHES[shape]
    body = f"{line}\nd = {_CALL}\nassert d.verdict is Verdict.DENY"
    _expect(tmp_path, _src(prelude, params, body), "patches the gate")


def test_patching_a_non_gate_object_stays_clean(tmp_path: Path) -> None:
    body = (
        "monkeypatch.setattr(os, 'getcwd', lambda: 'zqxwvk')\n"
        f"d = {_CALL}\nassert d.verdict is Verdict.DENY"
    )
    r = _lint(_write(tmp_path, "test_k_case.py", _src("", "gate, monkeypatch", body)))
    assert r.returncode == 0, r.stdout


# Item 8: the class reached through .mro() is the class reached through __mro__.
def test_a_gate_class_reached_through_mro_is_a_gate_patch(tmp_path: Path) -> None:
    src = _first("type(gate).mro()[0].evaluate = lambda *a, **kw: None")
    _expect(tmp_path, src, "patches the gate")


# Item 10b: a bare xfail mark on a KAT names no reason and no strictness.
def test_a_bare_xfail_mark_on_a_kat_is_rejected(tmp_path: Path) -> None:
    src = _kat("", deco="@pytest.mark.xfail")
    _expect(tmp_path, src, "has a bare xfail mark")


# A real UTF-8 alias is not a foreign encoding.
def test_a_utf8_alias_cookie_stays_clean(tmp_path: Path) -> None:
    path = tmp_path / "tests" / "test_k_case.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"# coding: utf8\n" + _kat("").encode("utf-8"))
    r = _lint(path)
    assert r.returncode == 0, r.stdout + r.stderr


# Item 10a: discovery walks without following links, and the floor guard's ban
# on links is what keeps a linked folder from hiding a KAT. Pin the ban.
def test_the_floor_guard_refuses_a_link_the_kat_walk_would_not_follow(
    tmp_path: Path,
) -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    import floor_guard

    (tmp_path / "real").mkdir()
    try:
        (tmp_path / "tests").symlink_to(tmp_path / "real", target_is_directory=True)
    except OSError:
        pytest.skip("this host cannot create a symbolic link")
    found = floor_guard.symlink_violations(tmp_path)
    assert any("symlink tests" in f for f in found), found


def test_a_name_that_may_be_a_member_or_something_else_is_not_a_verdict(
    tmp_path: Path,
) -> None:
    prelude = "from zqxwvk_fake import Other\n\nWANT = Verdict.DENY\nWANT = Other.DENY"
    body = f"d = {_CALL}\nassert d.verdict == WANT"
    _expect(tmp_path, _src(prelude, "gate", body), _ANSWER_REFUSED)


# --- review round on #101 at df0038b: every binding form counts against the gate
# --- name, the gate class and Verdict, not only against a result name ----------

_FAKE_GATE = (
    "class _FakeGate:\n    def evaluate(self, *a, **k):\n        return _Fake()"
)
_NS = "class _NS:\n    DENY = None"

PROTECTED_REBINDS = {
    "match-capture-of-verdict": (
        _FAKE + "\n\n\n" + _NS,
        "gate",
        f"d = {_CALL}\nmatch _NS:\n    case Verdict:\n        pass\n"
        "assert d.verdict is Verdict.DENY",
    ),
    "match-as-of-verdict": (
        _FAKE + "\n\n\n" + _NS,
        "gate",
        f"d = {_CALL}\nmatch _NS:\n    case type() as Verdict:\n        pass\n"
        "assert d.verdict is Verdict.DENY",
    ),
    "walrus-in-a-call-arg-of-verdict": (
        _FAKE + "\n\n\n" + _NS,
        "gate",
        f"d = {_CALL}\nprint(Verdict := _NS)\nassert d.verdict is Verdict.DENY",
    ),
    "except-name-of-verdict": (
        _FAKE,
        "gate",
        f"d = {_CALL}\ntry:\n    pass\nexcept Exception as Verdict:\n    pass\n"
        "assert d.verdict is Verdict.DENY",
    ),
    "match-capture-of-gate": (
        _FAKE + "\n\n\n" + _FAKE_GATE,
        "gate",
        "match _FakeGate():\n    case gate:\n        pass\n"
        f"d = {_CALL}\nassert d.verdict is Verdict.DENY",
    ),
    "nonlocal-swap-of-gate": (
        _FAKE + "\n\n\n" + _FAKE_GATE,
        "gate",
        "def _swap():\n    nonlocal gate\n    gate = _FakeGate()\n_swap()\n"
        f"d = {_CALL}\nassert d.verdict is Verdict.DENY",
    ),
    "walrus-in-a-call-arg-of-gate": (
        _FAKE + "\n\n\n" + _FAKE_GATE,
        "gate",
        f"print(gate := _FakeGate())\nd = {_CALL}\nassert d.verdict is Verdict.DENY",
    ),
    "for-target-of-gate": (
        _FAKE + "\n\n\n" + _FAKE_GATE,
        "gate",
        f"for gate in [_FakeGate()]:\n    pass\nd = {_CALL}\nassert d.verdict is Verdict.DENY",
    ),
    "with-target-of-gate": (
        _FAKE + "\n\n\n" + _FAKE_GATE,
        "gate",
        "with contextlib.nullcontext(_FakeGate()) as gate:\n    pass\n"
        f"d = {_CALL}\nassert d.verdict is Verdict.DENY",
    ),
    "walrus-of-the-gate-class": (
        _FAKE + "\n\n\n" + _FAKE_GATE,
        "",
        "print(Gate := _FakeGate)\n"
        "g = Gate(load_policy({'skills': {}}))\n"
        "d = g.evaluate('s', 'read_file', ['zqxwvk'])\nassert d.verdict is Verdict.DENY",
    ),
    "module-walrus-of-the-gate-class": (
        _FAKE + "\n\n\n" + _FAKE_GATE + "\n\n\nprint(Gate := _FakeGate)",
        "gate",
        f"d = {_CALL}\nassert d.verdict is Verdict.DENY",
    ),
}


@pytest.mark.parametrize("shape", sorted(PROTECTED_REBINDS))
def test_every_binding_form_of_the_gate_or_verdict_is_rejected(
    tmp_path: Path, shape: str
) -> None:
    prelude, params, body = PROTECTED_REBINDS[shape]
    _rejected(_lint(_write(tmp_path, "test_k_case.py", _src(prelude, params, body))))


# Item 2: a verdict is compared by identity. == reads through __eq__, which any
# route to the class can override, so it never satisfies a KAT.
VERDICT_EQ_PATCHES = {
    "type-of-the-verdict": "type(d.verdict).__eq__ = lambda a, b: True",
    "class-of-the-verdict": "d.verdict.__class__.__eq__ = lambda a, b: True",
    "mro-of-the-verdict": "type(d.verdict).mro()[0].__eq__ = lambda a, b: True",
    "setattr-on-the-type": "setattr(type(d.verdict), '__eq__', lambda a, b: True)",
    "alias-of-the-type": "cls = type(d.verdict)\ncls.__eq__ = lambda a, b: True",
    "monkeypatch-the-type": (
        "monkeypatch.setattr(type(d.verdict), '__eq__', lambda a, b: True)"
    ),
    "string-compare-with-patched-eq": "type(d.verdict).__eq__ = lambda a, b: True",
}


@pytest.mark.parametrize("shape", sorted(VERDICT_EQ_PATCHES))
def test_a_verdict_compared_with_eq_is_never_the_answer(
    tmp_path: Path, shape: str
) -> None:
    target = "'deny'" if shape.startswith("string") else "Verdict.DENY"
    body = f"d = {_CALL}\n{VERDICT_EQ_PATCHES[shape]}\nassert d.verdict == {target}"
    _expect(tmp_path, _src("", "gate, monkeypatch", body), _NO_ANSWER)


def test_a_verdict_compared_by_identity_is_the_answer(tmp_path: Path) -> None:
    body = f"d = {_CALL}\nassert d.verdict is Verdict.DENY"
    r = _lint(_write(tmp_path, "test_k_case.py", _src("", "gate", body)))
    assert r.returncode == 0, r.stdout


# Item 3: a try body with a handler that can swallow a raise is not on the
# straight path; any statement in it may raise before the assert runs.
CAUGHT_RAISES = {
    "conditional-raise-caught": (
        "try:\n    if os.environ.get('ZQXWVK'):\n        raise RuntimeError('x')\n"
        "    assert d.verdict is Verdict.DENY\nexcept RuntimeError:\n    pass"
    ),
    "call-that-may-raise-caught": (
        "try:\n    os.listdir('zqxwvk')\n    assert d.verdict is Verdict.DENY\n"
        "except OSError:\n    pass"
    ),
    "caught-raise-in-a-while-loop": (
        "while True:\n    try:\n        if os.environ.get('ZQXWVK'):\n"
        "            raise RuntimeError('x')\n        assert d.verdict is Verdict.DENY\n"
        "    except RuntimeError:\n        pass\n    break"
    ),
}


@pytest.mark.parametrize("shape", sorted(CAUGHT_RAISES))
def test_an_assert_a_caught_raise_can_skip_is_not_the_answer(
    tmp_path: Path, shape: str
) -> None:
    body = f"d = {_CALL}\n{CAUGHT_RAISES[shape]}"
    _expect(tmp_path, _src("", "gate", body), _NO_ANSWER)


CAUGHT_RAISES_CLEAN = {
    "try-finally": "try:\n    assert d.verdict is Verdict.DENY\nfinally:\n    pass",
    "handler-that-raises-again": (
        "try:\n    os.listdir('.')\n    assert d.verdict is Verdict.DENY\n"
        "except OSError:\n    raise"
    ),
    "assert-after-the-try": (
        "try:\n    os.listdir('zqxwvk')\nexcept OSError:\n    pass\n"
        "assert d.verdict is Verdict.DENY"
    ),
}


@pytest.mark.parametrize("shape", sorted(CAUGHT_RAISES_CLEAN))
def test_an_assert_no_handler_can_skip_stays_the_answer(
    tmp_path: Path, shape: str
) -> None:
    body = f"d = {_CALL}\n{CAUGHT_RAISES_CLEAN[shape]}"
    r = _lint(_write(tmp_path, "test_k_case.py", _src("", "gate", body)))
    assert r.returncode == 0, r.stdout


# Accepted before this round; a verdict is now compared by identity only.
VERDICT_EQ_REFUSED = {
    "eq_member": "assert d.verdict == Verdict.DENY",
    "eq_string": "assert d.verdict == 'deny'",
    "assert_equal_to_constant": "assert Verdict.DENY == d.verdict",
}


@pytest.mark.parametrize("shape", sorted(VERDICT_EQ_REFUSED))
def test_a_verdict_compared_with_eq_is_refused(tmp_path: Path, shape: str) -> None:
    _assert_refused(
        _lint(
            _write(
                tmp_path,
                "test_k_case.py",
                _kat_without_answer(VERDICT_EQ_REFUSED[shape]),
            )
        )
    )


def test_a_mapping_rest_capture_of_verdict_is_rejected(tmp_path: Path) -> None:
    body = (
        f"d = {_CALL}\nmatch {{}}:\n    case {{**Verdict}}:\n        pass\n"
        "assert d.verdict is Verdict.DENY"
    )
    _rejected(_lint(_write(tmp_path, "test_k_case.py", _src(_FAKE, "gate", body))))


def test_a_module_globals_store_of_the_gate_class_is_rejected(tmp_path: Path) -> None:
    prelude = _FAKE + "\n\n\n" + _FAKE_GATE + "\n\n\nglobals()['Gate'] = _FakeGate"
    body = f"d = {_CALL}\nassert d.verdict is Verdict.DENY"
    _rejected(_lint(_write(tmp_path, "test_k_case.py", _src(prelude, "gate", body))))


def test_a_verdict_compared_by_identity_with_a_string_is_refused(
    tmp_path: Path,
) -> None:
    _assert_refused(
        _lint(
            _write(
                tmp_path,
                "test_k_case.py",
                _kat_without_answer("assert d.verdict is 'deny'"),
            )
        )
    )


# --- review round on #101 at 8e4ec28 ----------------------------------------------

# Item 2: a name bound from the gate's class is the gate class; a store through
# it patches the gate.
GATE_CLASS_ALIASES_BY_NAME = {
    "type-of-gate": "k = type(gate)\nk.evaluate = lambda *a, **kw: _Fake()",
    "class-of-gate": "k = gate.__class__\nk.evaluate = lambda *a, **kw: _Fake()",
    "walrus-class-of-gate": "(k := gate.__class__).evaluate = lambda *a, **kw: _Fake()",
    "walrus-type-of-gate": "(k := type(gate)).evaluate = lambda *a, **kw: _Fake()",
    "the-gate-class": "k = Gate\nk.evaluate = lambda *a, **kw: _Fake()",
    "mro-of-gate": "k = type(gate).mro()[0]\nk.evaluate = lambda *a, **kw: _Fake()",
    "alias-setattr": "k = type(gate)\nsetattr(k, 'evaluate', lambda *a, **kw: _Fake())",
    "alias-of-an-alias": (
        "k = type(gate)\nj = k\nj.evaluate = lambda *a, **kw: _Fake()"
    ),
}


def test_a_gate_class_alias_whose_name_is_reused_elsewhere_still_patches(
    tmp_path: Path,
) -> None:
    prelude = _FAKE + "\n\n\ndef _other():\n    k = 1\n    return k"
    body = (
        "k = type(gate)\nk.evaluate = lambda *a, **kw: _Fake()\n"
        f"d = {_CALL}\nassert d.verdict is Verdict.DENY"
    )
    _expect(tmp_path, _src(prelude, "gate", body), "patches the gate")


@pytest.mark.parametrize("shape", sorted(GATE_CLASS_ALIASES_BY_NAME))
def test_a_store_through_a_gate_class_alias_patches_the_gate(
    tmp_path: Path, shape: str
) -> None:
    body = f"{GATE_CLASS_ALIASES_BY_NAME[shape]}\nd = {_CALL}\nassert d.verdict is Verdict.DENY"
    _expect(tmp_path, _src(_FAKE, "gate", body), "patches the gate")


# Item 3: in a try a handler can swallow, the path enters only a simple first
# statement; a compound one may raise inside before the assert runs.
NESTED_CAUGHT_RAISES = {
    "nested-try-finally": (
        "try:\n    try:\n        if os.environ.get('ZQXWVK'):\n"
        "            raise RuntimeError('x')\n"
        "        assert d.verdict is Verdict.DENY\n    finally:\n        pass\n"
        "except RuntimeError:\n    pass"
    ),
    "with-block": (
        "try:\n    with contextlib.nullcontext():\n"
        "        if os.environ.get('ZQXWVK'):\n            raise RuntimeError('x')\n"
        "        assert d.verdict is Verdict.DENY\nexcept RuntimeError:\n    pass"
    ),
    "if-true-block": (
        "try:\n    if True:\n        os.listdir('zqxwvk')\n"
        "        assert d.verdict is Verdict.DENY\nexcept OSError:\n    pass"
    ),
}


@pytest.mark.parametrize("shape", sorted(NESTED_CAUGHT_RAISES))
def test_a_caught_raise_inside_a_nested_block_skips_the_assert(
    tmp_path: Path, shape: str
) -> None:
    body = f"d = {_CALL}\n{NESTED_CAUGHT_RAISES[shape]}"
    _expect(tmp_path, _src("", "gate", body), _NO_ANSWER)


# Item 4: an assert message is evaluated when the assert fails, and can raise
# the error a swallowing handler catches.
def test_a_message_that_can_raise_in_a_swallowing_try_is_refused(
    tmp_path: Path,
) -> None:
    body = (
        f"d = {_CALL}\ntry:\n    assert d.verdict is Verdict.DENY, os.listdir('zqxwvk')\n"
        "except OSError:\n    pass"
    )
    _expect(tmp_path, _src("", "gate", body), _NO_ANSWER)


def test_a_constant_message_in_a_swallowing_try_stays_clean(tmp_path: Path) -> None:
    body = (
        f"d = {_CALL}\ntry:\n    assert d.verdict is Verdict.DENY, 'zqxwvk'\n"
        "except OSError:\n    pass"
    )
    r = _lint(_write(tmp_path, "test_k_case.py", _src("", "gate", body)))
    assert r.returncode == 0, r.stdout


@pytest.mark.parametrize(
    "jump",
    [
        pytest.param("    if os.environ.get('ZQXWVK'):\n        return", id="return"),
        pytest.param(
            "    for _ in [1]:\n        pass\n    if os.environ.get('ZQXWVK'):\n"
            "        return",
            id="return-after-a-loop",
        ),
    ],
)
def test_a_finally_that_may_return_takes_the_try_body_off_the_path(
    tmp_path: Path, jump: str
) -> None:
    body = f"d = {_CALL}\ntry:\n    assert d.verdict is Verdict.DENY\nfinally:\n{jump}"
    _expect(tmp_path, _src("", "gate", body), _NO_ANSWER)


def test_a_finally_that_may_break_out_of_a_loop_takes_the_try_body_off_the_path(
    tmp_path: Path,
) -> None:
    body = (
        f"d = {_CALL}\nfor _ in [1]:\n    try:\n        assert d.verdict is Verdict.DENY\n"
        "    finally:\n        if os.environ.get('ZQXWVK'):\n            break"
    )
    _expect(tmp_path, _src("", "gate", body), _NO_ANSWER)


def test_a_loop_inside_a_finally_may_break_itself(tmp_path: Path) -> None:
    body = (
        f"d = {_CALL}\ntry:\n    assert d.verdict is Verdict.DENY\nfinally:\n"
        "    for _ in os.listdir('.'):\n        break"
    )
    r = _lint(_write(tmp_path, "test_k_case.py", _src("", "gate", body)))
    assert r.returncode == 0, r.stdout


# Item 5: the refusal says what to write, and an assert in a try's else runs
# whenever the test goes on when no handler can swallow.
def test_the_refusal_names_the_identity_form(tmp_path: Path) -> None:
    r = _lint(
        _write(
            tmp_path,
            "test_k_case.py",
            _kat_without_answer("assert d.verdict == 'deny'"),
        )
    )
    assert "is Verdict." in r.stdout, r.stdout
    assert "verdict string" not in r.stdout, r.stdout


def test_an_assert_in_the_else_of_a_try_with_no_swallowing_handler_counts(
    tmp_path: Path,
) -> None:
    body = (
        f"d = {_CALL}\ntry:\n    os.listdir('.')\nexcept OSError:\n    raise\n"
        "else:\n    assert d.verdict is Verdict.DENY"
    )
    r = _lint(_write(tmp_path, "test_k_case.py", _src("", "gate", body)))
    assert r.returncode == 0, r.stdout


def test_an_assert_in_the_else_of_a_swallowing_try_does_not_count(
    tmp_path: Path,
) -> None:
    body = (
        f"d = {_CALL}\ntry:\n    os.listdir('zqxwvk')\nexcept OSError:\n    pass\n"
        "else:\n    assert d.verdict is Verdict.DENY"
    )
    _expect(tmp_path, _src("", "gate", body), _NO_ANSWER)


# Each form below is caught by one rule only: a positional namespace update, a
# setattr under a key the lint cannot fold on this module's object, and a
# subscript store through a name bound to globals().
VERDICT_REBINDS_ONE_RULE = {
    "positional-update": "globals().update({'Verdict': _NS})",
    "unfolded-key-through-sys-modules": (
        "setattr(sys.modules[__name__], os.environ.get('ZQXWVK', 'Verdict'), _NS)"
    ),
    "unfolded-key-through-get": (
        "setattr(sys.modules.get(__name__), os.environ.get('ZQXWVK', 'Verdict'), _NS)"
    ),
    "unfolded-key-through-an-alias": (
        "me = sys.modules[__name__]\n"
        "setattr(me, os.environ.get('ZQXWVK', 'Verdict'), _NS)"
    ),
    "subscript-through-an-alias": "g = globals()\ng['Verdict'] = _NS",
    "vars-of-the-module-object": "vars(sys.modules[__name__])['Verdict'] = _NS",
}


@pytest.mark.parametrize("shape", sorted(VERDICT_REBINDS_ONE_RULE))
def test_verdict_rebound_through_a_namespace_in_any_form_is_not_real(
    tmp_path: Path, shape: str
) -> None:
    body = f"d = {_CALL}\n{VERDICT_REBINDS_ONE_RULE[shape]}\nassert d.verdict is Verdict.DENY"
    _rejected(_lint(_write(tmp_path, "test_k_case.py", _src(_NS, "gate", body))))


def test_the_gate_class_given_by_a_namespace_update_is_not_the_real_class(
    tmp_path: Path,
) -> None:
    prelude = _FAKE + "\n\n\n" + _FAKE_GATE + "\n\n\nglobals().update(Gate=_FakeGate)"
    body = f"d = {_CALL}\nassert d.verdict is Verdict.DENY"
    _rejected(_lint(_write(tmp_path, "test_k_case.py", _src(prelude, "gate", body))))


# A compound first statement in a swallowing try, in the three shapes review
# ran against the real gate: the gate denies, the raise is swallowed, and the
# assert on the wrong verdict never runs.
_GATE_HERE = (
    "g = Gate(load_policy({'skills': {'w': {'tools': ['read_file'], "
    "'paths': [str(tmp_path / 'work')]}}}), str(tmp_path / 'l'))\n"
    "d = g.evaluate('w', 'read_file', [str(tmp_path / 'zqxwvk')])\n"
)
FIRST_STATEMENT_BLOCKS = {
    "nested-try-finally": (
        "try:\n    try:\n        if d:\n            raise KeyError\n"
        "        assert d.verdict is Verdict.ALLOW\n    finally:\n        pass\n"
        "except KeyError:\n    pass"
    ),
    "with-open": (
        "try:\n    with open(os.devnull):\n        if d:\n            raise KeyError\n"
        "        assert d.verdict is Verdict.ALLOW\nexcept KeyError:\n    pass"
    ),
    "if-true": (
        "try:\n    if True:\n        if d:\n            raise KeyError\n"
        "        assert d.verdict is Verdict.ALLOW\nexcept KeyError:\n    pass"
    ),
}


@pytest.mark.parametrize("shape", sorted(FIRST_STATEMENT_BLOCKS))
def test_an_unconditional_caught_raise_in_a_first_statement_block_is_refused(
    tmp_path: Path, shape: str
) -> None:
    body = _GATE_HERE + FIRST_STATEMENT_BLOCKS[shape]
    _expect(tmp_path, _src("", "tmp_path", body), _NO_ANSWER)


# The gate class rebound through an object, the way Verdict is.
GATE_CLASS_OBJECT_REBINDS = {
    "module-attribute-store": "sys.modules[__name__].Gate = _FakeGate",
    "module-setattr": "setattr(sys.modules[__name__], 'Gate', _FakeGate)",
    "module-dict-store": "sys.modules[__name__].__dict__['Gate'] = _FakeGate",
    "module-alias-store": "me = sys.modules[__name__]\nme.Gate = _FakeGate",
    "globals-update": "globals().update({'Gate': _FakeGate})",
}


@pytest.mark.parametrize("shape", sorted(GATE_CLASS_OBJECT_REBINDS))
def test_the_gate_class_rebound_through_an_object_is_not_the_real_class(
    tmp_path: Path, shape: str
) -> None:
    prelude = (
        _FAKE + "\n\n\n" + _FAKE_GATE + "\n\n\n" + GATE_CLASS_OBJECT_REBINDS[shape]
    )
    body = f"d = {_CALL}\nassert d.verdict is Verdict.DENY"
    _rejected(_lint(_write(tmp_path, "test_k_case.py", _src(prelude, "gate", body))))


# --- review round on #101 at cba40bf ------------------------------------------------

# Item 1: a function's __globals__ is this module's namespace.
_POLICY_HELPER = "def _policy():\n    return {'skills': {}}"
FUNCTION_GLOBALS = {
    "subscript-store": "test_k_case.__globals__['Verdict'] = _NS",
    "update": "test_k_case.__globals__.update(Verdict=_NS)",
    "alias-subscript-store": "g = test_k_case.__globals__\ng['Verdict'] = _NS",
    "another-function": "_policy.__globals__['Verdict'] = _NS",
}


@pytest.mark.parametrize("shape", sorted(FUNCTION_GLOBALS))
def test_verdict_rebound_through_a_functions_globals_is_not_real(
    tmp_path: Path, shape: str
) -> None:
    body = f"d = {_CALL}\n{FUNCTION_GLOBALS[shape]}\nassert d.verdict is Verdict.DENY"
    prelude = _NS + "\n\n\n" + _POLICY_HELPER
    _rejected(_lint(_write(tmp_path, "test_k_case.py", _src(prelude, "gate", body))))


def test_the_gate_class_patched_through_a_functions_globals_is_rejected(
    tmp_path: Path,
) -> None:
    body = (
        "test_k_case.__globals__['Gate'].evaluate = lambda *a, **kw: _Fake()\n"
        f"d = {_CALL}\nassert d.verdict is Verdict.DENY"
    )
    _rejected(_lint(_write(tmp_path, "test_k_case.py", _src(_FAKE, "gate", body))))


def test_the_gate_class_patched_through_globals_by_subscript_is_rejected(
    tmp_path: Path,
) -> None:
    body = (
        "globals()['Gate'].evaluate = lambda *a, **kw: _Fake()\n"
        f"d = {_CALL}\nassert d.verdict is Verdict.DENY"
    )
    _rejected(_lint(_write(tmp_path, "test_k_case.py", _src(_FAKE, "gate", body))))


# Item 2: the gate class is read only directly; passed on as a value, it can be
# patched where the lint does not follow it.
GATE_CLASS_AS_A_VALUE = {
    "call-argument": (
        "def _p(k):\n    k.evaluate = lambda *a, **kw: _Fake()",
        "_p(type(gate))",
    ),
    "keyword-argument": (
        "def _p(k=None):\n    k.evaluate = lambda *a, **kw: _Fake()",
        "_p(k=gate.__class__)",
    ),
    "tuple-element": (
        "",
        "ks = (type(gate),)\nks[0].evaluate = lambda *a, **kw: _Fake()",
    ),
    "dict-value": ("", "{'k': type(gate)}['k'].evaluate = lambda *a, **kw: _Fake()"),
    "lambda-return": (
        "",
        "f = lambda: type(gate)\nf().evaluate = lambda *a, **kw: _Fake()",
    ),
    "function-return": (
        "def _cls(g):\n    return type(g)",
        "_cls(gate).evaluate = lambda *a, **kw: _Fake()",
    ),
    "the-class-name-as-an-argument": (
        "def _p(k):\n    k.evaluate = lambda *a, **kw: _Fake()",
        "_p(Gate)",
    ),
    "an-alias-as-an-argument": (
        "def _p(k):\n    k.evaluate = lambda *a, **kw: _Fake()",
        "k = type(gate)\n_p(k)",
    ),
}


@pytest.mark.parametrize("shape", sorted(GATE_CLASS_AS_A_VALUE))
def test_the_gate_class_passed_on_as_a_value_is_rejected(
    tmp_path: Path, shape: str
) -> None:
    helper, line = GATE_CLASS_AS_A_VALUE[shape]
    prelude = _FAKE + ("\n\n\n" + helper if helper else "")
    body = f"{line}\nd = {_CALL}\nassert d.verdict is Verdict.DENY"
    # A helper's own return of type(g) is caught at the call by the patch rule;
    # every other shape by the value rule.
    _rejected(_lint(_write(tmp_path, "test_k_case.py", _src(prelude, "gate", body))))


GATE_CLASS_READ_DIRECTLY = {
    "isinstance": "assert isinstance(gate, Gate)",
    "issubclass": "assert issubclass(type(gate), Gate)",
    "is": "assert type(gate) is Gate",
    "attribute-read": "assert type(gate).__name__ == 'Gate'",
    "annotation": "g: Gate = gate",
    "alias-read": "cls = type(gate)\nassert cls is Gate",
}


@pytest.mark.parametrize("shape", sorted(GATE_CLASS_READ_DIRECTLY))
def test_the_gate_class_read_directly_stays_clean(tmp_path: Path, shape: str) -> None:
    body = f"{GATE_CLASS_READ_DIRECTLY[shape]}\nd = {_CALL}\nassert d.verdict is Verdict.DENY"
    r = _lint(_write(tmp_path, "test_k_case.py", _src("", "gate", body)))
    assert r.returncode == 0, r.stdout


def test_setattr_on_the_gate_class_held_by_globals_is_rejected(tmp_path: Path) -> None:
    body = (
        "setattr(globals()['Gate'], 'evaluate', lambda *a, **kw: _Fake())\n"
        f"d = {_CALL}\nassert d.verdict is Verdict.DENY"
    )
    _rejected(_lint(_write(tmp_path, "test_k_case.py", _src(_FAKE, "gate", body))))


# --- review round on #101 at aacb21e: every namespace object, and every name bound
# --- to one, is tainted; any write through it rebinds ---------------------------

NAMESPACE_WRITES_VERDICT = {
    "vars-of-a-module-alias": "me = sys.modules[__name__]\nvars(me)['Verdict'] = _NS",
    "vars-of-the-module-update": "vars(sys.modules[__name__]).update(Verdict=_NS)",
    "alias-of-vars-of-the-module": "ns = vars(sys.modules[__name__])\nns['Verdict'] = _NS",
    "operator-setitem": "import operator\noperator.setitem(globals(), 'Verdict', _NS)",
    "dict-setitem": "dict.__setitem__(globals(), 'Verdict', _NS)",
    "dict-update": "dict.update(globals(), Verdict=_NS)",
}


@pytest.mark.parametrize("shape", sorted(NAMESPACE_WRITES_VERDICT))
def test_a_write_through_any_namespace_object_rebinds_verdict(
    tmp_path: Path, shape: str
) -> None:
    body = f"d = {_CALL}\n{NAMESPACE_WRITES_VERDICT[shape]}\nassert d.verdict is Verdict.DENY"
    _rejected(_lint(_write(tmp_path, "test_k_case.py", _src(_NS, "gate", body))))


NAMESPACE_WRITES_GATE_CLASS = {
    "vars-of-the-module-store": "vars(sys.modules[__name__])['Gate'] = _FakeGate",
    "vars-of-the-module-update": "vars(sys.modules[__name__]).update(Gate=_FakeGate)",
    "vars-of-a-module-alias": "me = sys.modules[__name__]\nvars(me)['Gate'] = _FakeGate",
}


@pytest.mark.parametrize("shape", sorted(NAMESPACE_WRITES_GATE_CLASS))
def test_a_write_through_any_namespace_object_rebinds_the_gate_class(
    tmp_path: Path, shape: str
) -> None:
    prelude = (
        _FAKE + "\n\n\n" + _FAKE_GATE + "\n\n\n" + NAMESPACE_WRITES_GATE_CLASS[shape]
    )
    body = f"d = {_CALL}\nassert d.verdict is Verdict.DENY"
    _rejected(_lint(_write(tmp_path, "test_k_case.py", _src(prelude, "gate", body))))


GATE_NAMESPACE_WRITES = {
    "ior-on-the-instance-dict": "gate.__dict__ |= {'evaluate': lambda *a, **kw: _Fake()}",
    # vars(x) |= ... does not parse (a call is no augmented target); these are
    # the same write in the forms that do.
    "ior-on-vars-of-the-instance": "vars(gate).__ior__({'evaluate': lambda *a, **kw: _Fake()})",
    "ior-through-an-alias": "ns = vars(gate)\nns |= {'evaluate': lambda *a, **kw: _Fake()}",
    "store-through-an-alias": "ns = gate.__dict__\nns['evaluate'] = lambda *a, **kw: _Fake()",
    "update-through-an-alias": "ns = vars(gate)\nns.update(evaluate=lambda *a, **kw: _Fake())",
    "operator-setitem-on-the-instance": (
        "import operator\noperator.setitem(vars(gate), 'evaluate', lambda *a, **kw: _Fake())"
    ),
}


@pytest.mark.parametrize("shape", sorted(GATE_NAMESPACE_WRITES))
def test_a_write_through_the_gate_instances_namespace_patches_the_gate(
    tmp_path: Path, shape: str
) -> None:
    body = (
        f"{GATE_NAMESPACE_WRITES[shape]}\nd = {_CALL}\nassert d.verdict is Verdict.DENY"
    )
    _expect(tmp_path, _src(_FAKE, "gate", body), "patches the gate")


GATE_MODULE_WRITES = {
    "ior-on-vars-of-the-module": (
        "import operator\noperator.ior(vars(capability_gate), {'_decide': None})"
    ),
    "ior-through-an-alias": "ns = vars(capability_gate)\nns |= {'_decide': None}",
    "store-through-an-alias": "ns = capability_gate.__dict__\nns['_decide'] = None",
}


@pytest.mark.parametrize("shape", sorted(GATE_MODULE_WRITES))
def test_a_write_through_the_gate_modules_namespace_patches_the_gate(
    tmp_path: Path, shape: str
) -> None:
    body = f"{GATE_MODULE_WRITES[shape]}\nd = {_CALL}\nassert d.verdict is Verdict.DENY"
    _expect(tmp_path, _src("import capability_gate", "gate", body), "patches the gate")


def test_the_gate_module_name_rebound_through_this_modules_object_is_rejected(
    tmp_path: Path,
) -> None:
    prelude = (
        "import types\n\nimport capability_gate\n\n"
        + _FAKE
        + "\n\n\n"
        + _FAKE_GATE
        + "\n\n\nsys.modules[__name__].capability_gate = types.SimpleNamespace(Gate=_FakeGate)"
    )
    body = (
        "g = capability_gate.Gate(load_policy({'skills': {}}))\n"
        "d = g.evaluate('s', 'read_file', ['zqxwvk'])\nassert d.verdict is Verdict.DENY"
    )
    _rejected(_lint(_write(tmp_path, "test_k_case.py", _src(prelude, "", body))))


# At module level, so only the namespace rule can refuse it: a write under a
# key the lint cannot fold may be Verdict.
@pytest.mark.parametrize(
    "line",
    [
        pytest.param(
            "globals()[os.environ.get('ZQXWVK', 'Verdict')] = _NS", id="store"
        ),
        pytest.param(
            "globals().setdefault(os.environ.get('ZQXWVK', 'Verdict'), _NS)",
            id="setdefault",
        ),
    ],
)
def test_a_module_level_namespace_write_under_an_unknown_key_is_rejected(
    tmp_path: Path, line: str
) -> None:
    prelude = _NS + "\n\n\n" + line
    body = f"d = {_CALL}\nassert d.verdict is Verdict.DENY"
    _rejected(_lint(_write(tmp_path, "test_k_case.py", _src(prelude, "gate", body))))


# A write into a module namespace under a constant key that names nothing the
# test relies on leaves Verdict and the gate class real.
@pytest.mark.parametrize(
    "line",
    [
        pytest.param("globals().setdefault('zqxwvk_other', 1)", id="setdefault"),
        pytest.param(
            "import operator\noperator.setitem(globals(), 'zqxwvk_other', 1)",
            id="operator-setitem",
        ),
    ],
)
def test_a_namespace_write_under_an_unrelated_key_stays_clean(
    tmp_path: Path, line: str
) -> None:
    body = f"{line}\nd = {_CALL}\nassert d.verdict is Verdict.DENY"
    r = _lint(_write(tmp_path, "test_k_case.py", _src("", "gate", body)))
    assert r.returncode == 0, r.stdout


def test_monkeypatch_setitem_on_the_gate_instances_namespace_patches_the_gate(
    tmp_path: Path,
) -> None:
    body = (
        "monkeypatch.setitem(vars(gate), 'evaluate', lambda *a, **kw: _Fake())\n"
        f"d = {_CALL}\nassert d.verdict is Verdict.DENY"
    )
    _expect(tmp_path, _src(_FAKE, "gate, monkeypatch", body), "patches the gate")
