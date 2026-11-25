"""Entry point of the bundled AnalystLab.exe (friend package, DESIGN 9.2). One program, three jobs:

    AnalystLab.exe                      the status window (friend mode)
    AnalystLab.exe status [--mode lab] [--first-run]
    AnalystLab.exe agent [agent options]    the recorder (started by the scheduled task)
    AnalystLab.exe selftest             run the self-test without a window; exit code 0 = pass

The bundle is built "windowed" (no console window), so there is no stdout: output goes nowhere
instead of crashing.
"""

import os
import sys


def main(argv=None):
    if sys.stdout is None:                    # windowed bundle: no console
        sys.stdout = open(os.devnull, "w")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w")
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv.pop(0) if argv and argv[0] in ("agent", "status", "selftest") else "status"
    if cmd == "agent":
        from agent import main as agent_main
        return agent_main.main(argv)
    if cmd == "selftest":
        from agent.paths import data_root, recordings_root
        from statusapp import selftest
        control = os.path.join(data_root(), "control")
        return 0 if selftest.run(recordings_root(), state_dir=control).get("passed") else 1
    from statusapp import app
    return app.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
