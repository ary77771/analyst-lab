"""The Story screen in the REAL browser, on the shapes of the biggest and oddest real stories.

dashboard/sweep/story_check.cjs opens each story of tests/fixtures/stories/ in the installed Edge at
1463 x 780 (the demo laptop) and measures the page itself: the film is drawn and has room, the header
keeps its height with many alerts, no name or word is written across another, the alert's own steps are
on the last frame, the line under the film and the "declared" sentence are Python's, and the report
holds every row in Python's order with its ink.

Why a browser: every screen bug the sweep of 2026-11-21 found was invisible to the unit tests.
Skipped (with the reason) where Edge, Node or playwright-core is missing; nothing is ever downloaded."""

import dataclasses
import json
import os
import shutil
import socket
import subprocess
import threading
import time

import pytest

from engine.alerts import AlertStore
from engine.dashboard.app import create_app
from tests.test_report import s1_like

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORIES = os.path.join(ROOT, "tests", "fixtures", "stories")
CHECK = os.path.join(ROOT, "dashboard", "sweep", "story_check.cjs")
DEV = os.path.join(ROOT, "engine", "dashboard", "static", "dev")
EDGE = [os.path.join(os.environ.get(v, ""), "Microsoft", "Edge", "Application", "msedge.exe") for v in ("ProgramFiles(x86)", "ProgramFiles")]
PREFIX = "shape-"                # the copies served for this test (static/dev is git-ignored)


def _why_not():
    if not any(os.path.exists(p) for p in EDGE):
        return "Microsoft Edge is not installed here"
    if not shutil.which("node"):
        return "Node.js is not on the PATH"
    if not os.path.isdir(os.path.join(ROOT, "dashboard", "node_modules", "playwright-core")):
        return "playwright-core is not installed (cd dashboard; npm install)"
    return None


def test_the_browser_tool_never_downloads_a_browser_and_is_never_served():
    """playwright-core only DRIVES the Edge that is already installed. It must stay a development tool: no
    install step that could fetch a browser, not the full `playwright` package (whose install does fetch),
    and nothing of it in the build the dashboard serves offline."""
    with open(os.path.join(ROOT, "dashboard", "package.json"), encoding="utf-8") as f:
        pkg = json.load(f)
    assert "playwright-core" in pkg["devDependencies"] and "playwright-core" not in pkg.get("dependencies", {})
    everything = {**pkg.get("dependencies", {}), **pkg["devDependencies"]}
    assert "playwright" not in everything and "@playwright/test" not in everything and not any(k.startswith("playwright-") and k != "playwright-core" for k in everything)
    assert not any("playwright" in v or "install" in k for k, v in pkg.get("scripts", {}).items())
    own = os.path.join(ROOT, "dashboard", "node_modules", "playwright-core", "package.json")
    if os.path.exists(own):
        with open(own, encoding="utf-8") as f:
            assert not any(k in ("install", "preinstall", "postinstall") for k in (json.load(f).get("scripts") or {}))
    assets = os.path.join(ROOT, "engine", "dashboard", "static", "app", "assets")
    for name in os.listdir(assets):
        if name.endswith((".js", ".css", ".html")):
            with open(os.path.join(assets, name), encoding="utf-8", errors="replace") as f:
                assert "playwright" not in f.read(), name
    with open(CHECK, encoding="utf-8") as f:
        script = f.read()
    code = "\n".join(line for line in script.splitlines() if not line.lstrip().startswith("//"))
    assert 'chromium.launch({ channel: "msedge"' in code                 # the installed Edge, never a browser of its own
    assert not any(word in code for word in ("install", "download", "registry", "executablePath"))


@pytest.fixture(scope="module")
def served(tmp_path_factory):
    """A plain development dashboard on a free local port, whose store holds 45 alerts (so the Story
    header shows its many-alerts form), serving the story shapes as development fixtures."""
    why = _why_not()
    if why:
        pytest.skip(why)
    import uvicorn
    tmp = tmp_path_factory.mktemp("browser")
    con, alert, _ = s1_like(tmp)
    con.close()
    store = AlertStore(str(tmp / "alerts.db"))
    store.write([alert] + [dataclasses.replace(alert, incident=f"another alert {i}") for i in range(44)])
    store.close()
    app = create_app(str(tmp / "s.db"), str(tmp / "alerts.db"), recordings=str(tmp / "rec"))
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.1)
    os.makedirs(DEV, exist_ok=True)
    folder = tmp / "stories"
    folder.mkdir()
    copies = []
    for f in sorted(os.listdir(STORIES)):
        if f.endswith(".json"):
            shutil.copyfile(os.path.join(STORIES, f), os.path.join(DEV, PREFIX + f))
            shutil.copyfile(os.path.join(STORIES, f), str(folder / (PREFIX + f)))
            copies.append(os.path.join(DEV, PREFIX + f))
    yield f"http://127.0.0.1:{port}", str(folder)
    server.should_exit = True
    for c in copies:
        try:
            os.remove(c)
        except OSError:
            pass


def run_check(base, folder, *names):
    env = dict(os.environ, NODE_PATH=os.path.join(ROOT, "dashboard", "node_modules"))
    p = subprocess.run(["node", CHECK, base, folder, *names], capture_output=True, text=True, encoding="utf-8", errors="replace",
                       cwd=os.path.join(ROOT, "dashboard"), env=env, timeout=600)
    assert p.returncode in (0, 1), f"the browser check could not run: {p.stderr.strip()[-400:]}"
    return [json.loads(line) for line in p.stdout.splitlines() if line.startswith("{")]


def test_every_real_story_shape_holds_up_in_the_real_browser(served):
    base, folder = served
    results = run_check(base, folder)
    assert len(results) == len([f for f in os.listdir(STORIES) if f.endswith(".json")]) >= 10
    problems = {r["name"]: r["problems"] for r in results if r["problems"]}
    assert not problems, json.dumps(problems, indent=1)
    big = next(r for r in results if r["name"] == PREFIX + "biggest-1120-rows")
    assert big["rows"] == 1120 and big["film"] <= 12                 # the biggest story plays as a short film; its report keeps 1,120 rows


def test_the_check_notices_a_report_that_lost_a_row(served):
    """The check must be able to fail: a story whose served copy lost a row of its timeline (so the page
    shows fewer rows than the file the check reads) is reported."""
    base, folder = served
    name = PREFIX + "two-alerts-same-second"
    served_copy = os.path.join(DEV, name + ".json")
    with open(served_copy, encoding="utf-8") as f:
        whole = f.read()
    story = json.loads(whole)
    story["report"]["timeline"] = story["report"]["timeline"][:-1]
    try:
        with open(served_copy, "w", encoding="utf-8") as f:
            json.dump(story, f)
        results = run_check(base, folder, name)
    finally:
        with open(served_copy, "w", encoding="utf-8") as f:
            f.write(whole)
    assert len(results) == 1 and any("report:" in p for p in results[0]["problems"]), results
