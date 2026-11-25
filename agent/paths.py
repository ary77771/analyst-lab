"""Where things are, for the project checkout AND for the bundled friend package.

In the checkout, the project root is the folder above agent/. In the bundle (PyInstaller
"onedir", DESIGN 9.2) the code lives in <install folder>\\_internal, so the root is the folder
of AnalystLab.exe: that is what the origin tagger must treat as "our own tools" (the status
app and its self-test run from there). Recordings of the bundle live in ProgramData, which
the installer makes writable for the user (pause file, statistics cache).
"""

import os
import sys


def frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def project_root() -> str:
    if frozen():
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def data_root() -> str:
    """Bundle: %ProgramData%\\AnalystLab (or ANALYSTLAB_DATA, for tests). Checkout: the project."""
    if os.environ.get("ANALYSTLAB_DATA"):
        return os.environ["ANALYSTLAB_DATA"]
    if frozen():
        return os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "AnalystLab")
    return project_root()


def recordings_root() -> str:
    return os.path.join(data_root(), "recordings")
