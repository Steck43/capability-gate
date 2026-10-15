"""The floor's only conftest: two checks a test module cannot opt out of.

1. A plugin that registers once collection has started fails the run. A test
   module can declare pytest_plugins in forms no static scan reads (a name
   built at run time, a module __getattr__), and pytest loads that list while
   it collects; from that point every registration is refused.
2. With FLOOR_RUN_RECORD set (the CI tests job sets it), the finished session
   writes a run record: its exit status, the modules it collected and the
   tests that reported. A process that ends early, such as os._exit during an
   import or a test, writes none, and scripts/run_record_check.py then fails
   the job.

The floor guard pins this file's exact content. Test modules still run
arbitrary code inside this process, so a module that forges the record or
removes these hooks before they fire is not caught here (see CHANGELOG).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

_STATE: dict = {"collecting": False, "modules": set(), "reported": set()}


@pytest.hookimpl(tryfirst=True)
def pytest_collection(session) -> None:
    _STATE["collecting"] = True


def pytest_plugin_registered(plugin, plugin_name, manager) -> None:
    if _STATE["collecting"]:
        raise pytest.UsageError(
            f"floor: plugin {plugin_name} registered during collection"
        )


def pytest_collectreport(report) -> None:
    if report.outcome in {"passed", "skipped"} and report.nodeid.endswith(".py"):
        _STATE["modules"].add(report.nodeid)


def pytest_runtest_logreport(report) -> None:
    _STATE["reported"].add(report.nodeid)


def pytest_sessionfinish(session, exitstatus) -> None:
    path = os.environ.get("FLOOR_RUN_RECORD")
    if not path:
        return
    record = {
        "finished": True,
        "exitstatus": int(exitstatus),
        "collected": session.testscollected,
        "reported": len(_STATE["reported"]),
        "modules": sorted(_STATE["modules"]),
    }
    Path(path).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
