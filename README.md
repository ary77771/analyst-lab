# Analyst Lab

**Evidence-based investigation of security alerts on a Windows computer.**

Analyst Lab records what happens on a Windows machine (which programs start, which files they
write, where they connect), raises an alert when something looks suspicious, and then rebuilds
the story behind the alert. Every step of that story is marked by how sure it is:

- **Proven**: a recorded event shows it.
- **Suspected**: likely, but not directly recorded.
- **Can't be known**: the recording cannot answer it.

Every claim on screen points back to the recorded events behind it.

Student project for the Object-Oriented Programming course.

## Features

- **Recording agent**: reads Windows' Sysmon event log and adds file fingerprints and open ports.
- **Detection**: Sigma rules, the project's own explainable rules, and a "regular check-in rhythm"
  check for programs that call home on a timer.
- **Evidence graph**: links processes, files and network connections into one story per alert.
- **Dashboard** (local web page):
  - **Watch**: alerts arrive while a test runs.
  - **Story**: the attack drawn step by step.
  - **Proof**: the project's measured results.
  - **Labs**: an investigation path from "I have an alert" to a printable incident report, with
    a "test a claim" page.
- **Safe test lab**: harmless test programs (written in Go) that run only inside an isolated
  virtual machine with no internet access.

## Requirements

- Windows 10 or 11
- Python 3.14
- Optional:
  - Sysmon (built into Windows 11 as an optional feature, or from Microsoft Sysinternals) to
    record your own machine
  - VirtualBox to run the test lab
  - Go to rebuild the test programs
  - Node.js to rebuild the dashboard's front end (a built copy is included)

## Install

```powershell
git clone https://github.com/ary77771/analyst-lab.git
cd analyst-lab
py -3.14 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
```

`requirements.txt` lists the direct dependencies. `requirements-lock.txt` pins every version.

## Run the tests

```powershell
.venv\Scripts\python.exe -m pytest -q
```

Recordings are never part of the repository, so a few tests cannot pass in a fresh copy (7 of
about 2,350 when this was published):
- 5 tests need the "normal behaviour" baselines learned on the lab's own machines (kept in
  `recordings/`);
- 2 tests check a pinned file fingerprint, which changes when Git converts line endings on Windows.

## Run the dashboard

The dashboard reads an event store and an alert database. To open it on empty ones:

```powershell
.venv\Scripts\python.exe -c "from engine.store import EventStore; from engine.alerts import AlertStore; EventStore('events.db').close(); AlertStore('alerts.db').close()"
.venv\Scripts\python.exe -m engine.dashboard --events events.db --alerts alerts.db --port 8780
```

Then open http://127.0.0.1:8780. It only listens on this computer.

To fill it with your own machine's activity:
1. Enable Sysmon with `tools\install_sysmon.ps1` (needs administrator rights).
2. Run the agent (`agent\`), which writes recordings to `recordings\`.
3. Load and score the recordings with `engine\load.py` and `engine\live.py`.

To rebuild the front end:

```powershell
cd dashboard
npm install
npm run build
```

## Repository layout

| Folder | Contents |
|---|---|
| `agent/` | Recording agent (reads Sysmon events, writes `recordings/`) |
| `engine/` | Event store, detection, scoring, evidence graph, reports, live loop, dashboard back end (FastAPI), Labs |
| `dashboard/` | Dashboard front end (React + TypeScript) |
| `rules/`, `config/` | Detection rules and the fixed settings |
| `scenarios/` | Harmless test programs (Go) with their answer sheets |
| `tools/` | Test-lab runner, checkers, experiments, setup scripts |
| `demo/` | Demo start-up and practice scripts |
| `tests/` | Unit, integration and replay tests (pytest) |
| `docs/results/` | Measured results that the dashboard's Proof page reads |

## Team

- Yousif Salwan Jawad
- Ahmed Abbas
- Malak Mohammed

## License

[MIT](LICENSE). Third-party libraries bundled with the dashboard are listed, with their
licenses, in `engine/dashboard/static/vendor/README.md`.
