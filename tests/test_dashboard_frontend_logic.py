"""Runs the front end's own logic tests (vitest: dashboard/src/ui2/logic.test.ts) from pytest, so the
usual test command covers them: the story is told in Python's order and only from Python's rows, a
link is drawn only when its row is told and keeps its ink, and a new alert fires once and never
changes the story on screen."""

import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASH = os.path.join(ROOT, "dashboard")
NPM = shutil.which("npm")


@pytest.mark.skipif(NPM is None or not os.path.isdir(os.path.join(DASH, "node_modules", "vitest")),
                    reason="node or vitest not installed (npm install in dashboard/)")
def test_the_front_end_logic_tests_pass():
    r = subprocess.run([NPM, "test"], cwd=DASH, capture_output=True, text=True, timeout=300, encoding="utf-8", errors="replace")
    assert r.returncode == 0, (r.stdout + r.stderr)[-3000:]