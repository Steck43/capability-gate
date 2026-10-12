"""KAT linter: reject tests that are red by fiat or never reach the gate."""

from __future__ import annotations

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
        "getattr(pytest, ...)",
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
    ],
    ids=["mark-strict-false", "param-strict-false", "imperative-xfail"],
)
def test_xfail_escape_hatches_rejected_in_any_test_file(
    tmp_path: Path, src: str, reason: str
) -> None:
    # An ordinary test file, not a KAT: these hatches defeat xfail_strict anywhere.
    _write(tmp_path, "test_ordinary.py", src)
    r = _lint("--root", tmp_path)
    assert r.returncode == 1, r.stdout
    assert reason in r.stdout, r.stdout
