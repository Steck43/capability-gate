"""The floor's only conftest: checks a test module cannot opt out of.

1. A plugin that registers once collection has started fails the run. A test
   module can declare pytest_plugins in forms no static scan reads (a name
   built at run time, a module __getattr__), and pytest loads that list while
   it collects; from that point every registration is refused.
2. With FLOOR_RUN_RECORD set (the CI tests job sets it), the finished session
   writes a run record: its exit status, the modules it collected, the
   modules skipped as a whole, the modules where at least one test reached
   its call, and the tests that reported. A process that ends early, such as os._exit during an
   import or a test, writes none, and scripts/run_record_check.py then fails
   the job.
3. Under pytest-xdist (CI runs pytest -n 4) the main process writes the
   record. Workers write none; each hands the modules it collected to the
   main process when it shuts down. The main process sees every test report
   itself. A worker that goes down with an error, or without handing over its
   modules, is a lost worker, and the main process then writes no record.

The floor guard pins this file's exact content. Test modules still run
arbitrary code inside this process, so a module that forges the record or
removes these hooks before they fire is not caught here (see CHANGELOG).
"""

from __future__ import annotations

import dis
import json
import os
from pathlib import Path

import pytest

_STATE: dict = {
    "collecting": False,
    "modules": set(),
    "skipped_modules": set(),
    "called_modules": set(),
    "reported": set(),
    "lost_worker": False,
}


@pytest.hookimpl(tryfirst=True)
def pytest_collection(session) -> None:
    _STATE["collecting"] = True


def pytest_plugin_registered(plugin, plugin_name, manager) -> None:
    if _STATE["collecting"]:
        raise pytest.UsageError(
            f"floor: plugin {plugin_name} registered during collection"
        )


def pytest_collectreport(report) -> None:
    if not report.nodeid.endswith(".py"):
        return
    if report.outcome == "passed":
        _STATE["modules"].add(report.nodeid)
    elif report.outcome == "skipped":
        _STATE["skipped_modules"].add(report.nodeid)


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    if call.when == "call":
        outcome.get_result().floor_ran = _call_ran(item, call, outcome.get_result())


def _call_ran(item, call, report) -> bool:
    """Whether the test's own call reached its checks, judged from how that call
    ended and the xfail mark pytest evaluated for it, never from keywords: those
    hold every marker, parent, parametrize id and attribute name."""
    exc = call.excinfo
    if exc is None:
        return True
    # An imperative skip or xfail ends the body before its asserts, marked or not.
    if exc.errisinstance((pytest.skip.Exception, pytest.xfail.Exception)):
        return False
    if not hasattr(report, "wasxfail"):
        return True
    # pytest sets wasxfail on any other exception only under a mark it evaluated
    # as active. That expected failure counts unless the body raised it itself:
    # a raise statement in the test's own file that is not an AssertionError.
    if exc.errisinstance(AssertionError):
        return True
    tb = exc.tb
    while tb.tb_next is not None:
        tb = tb.tb_next
    code = tb.tb_frame.f_code
    own_file = Path(code.co_filename).resolve() == Path(str(item.path)).resolve()
    raised = dis.opname[code.co_code[tb.tb_lasti]] in ("RAISE_VARARGS", "RERAISE")
    return not (own_file and raised)


def pytest_runtest_logreport(report) -> None:
    _STATE["reported"].add(report.nodeid)
    # A test ran when its call reached its checks (see _call_ran). A test skipped
    # by a mark or at setup has no call report and does not count.
    if report.when == "call" and getattr(report, "floor_ran", False):
        _STATE["called_modules"].add(report.nodeid.split("::", 1)[0])


@pytest.hookimpl(optionalhook=True)
def pytest_testnodedown(node, error) -> None:
    out = getattr(node, "workeroutput", None) or {}
    if error is not None or "floor_modules" not in out:
        _STATE["lost_worker"] = True
        return
    _STATE["modules"].update(out["floor_modules"])
    _STATE["skipped_modules"].update(out["floor_skipped_modules"])


def pytest_sessionfinish(session, exitstatus) -> None:
    path = os.environ.get("FLOOR_RUN_RECORD")
    if not path:
        return
    workeroutput = getattr(session.config, "workeroutput", None)
    if workeroutput is not None:
        workeroutput["floor_modules"] = sorted(_STATE["modules"])
        workeroutput["floor_skipped_modules"] = sorted(_STATE["skipped_modules"])
        return
    if _STATE["lost_worker"]:
        return
    record = {
        "finished": True,
        "exitstatus": int(exitstatus),
        "collected": session.testscollected,
        "reported": len(_STATE["reported"]),
        "modules": sorted(_STATE["modules"]),
        "skipped_modules": sorted(_STATE["skipped_modules"]),
        "called_modules": sorted(_STATE["called_modules"]),
    }
    Path(path).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
