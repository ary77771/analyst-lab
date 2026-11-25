"""Stage 1 smoke tests: every dependency imports, and the Windows event log is readable."""

import importlib
import sys

import pytest

DEPENDENCIES = [
    "win32evtlog",  # pywin32
    "psutil",
    "fastapi",
    "uvicorn",
    "yaml",  # pyyaml
    "httpx",
    "pandas",
    "matplotlib",
]


@pytest.mark.parametrize("module", DEPENDENCIES)
def test_dependency_imports(module):
    importlib.import_module(module)


def test_running_inside_project_venv():
    assert sys.prefix != sys.base_prefix, "tests must run from the project .venv"


def test_read_application_event_log():
    """Read the 10 newest records of the Windows Application log (read-only)."""
    import win32evtlog

    query = win32evtlog.EvtQuery(
        "Application",
        win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
    )
    events = win32evtlog.EvtNext(query, 10)
    assert len(events) == 10

    for event in events:
        xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
        assert "<EventRecordID>" in xml
