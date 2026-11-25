"""Shared test set-up."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))

# a hand-made hub list for every test that runs the scenario graph checker: the real list is
# private (recordings/hubs/hubs.json, never in a clone), and tests must not depend on it
TEST_HUBS = frozenset({r"c:\windows\explorer.exe", r"c:\windows\system32\svchost.exe"})


def tcp_listen_state_broken() -> bool:
    """True when this Windows reports a fresh listening socket with a state other than LISTEN.
    Seen 2026-10-31 after the preview update KB5127936 (build 26300.9818) on the developer laptop:
    Windows' own Get-NetTCPConnection fails on state 0 too, so it is the system's table, not our
    code. Tests that need the real port table are expected to fail there, and only there."""
    import socket
    import psutil
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        mine = [c for c in psutil.net_connections(kind="tcp") if c.laddr and c.laddr.port == port]
        return bool(mine) and all(c.status != psutil.CONN_LISTEN for c in mine)
    finally:
        s.close()


TCP_STATE_BROKEN = pytest.mark.xfail(
    condition=sys.platform == "win32" and tcp_listen_state_broken(), strict=True,
    reason="this Windows reports listening sockets with a wrong TCP state (KB5127936, build 26300.9818; VERIFICATION_LOG 2026-10-31)")


import check_graph_scenario  # noqa: E402

# kept on the module: this file can be imported twice (as conftest and as tests.conftest), the second
# time after the fixture below has already replaced load_hubs
if not hasattr(check_graph_scenario, "_real_load_hubs"):
    check_graph_scenario._real_load_hubs = check_graph_scenario.load_hubs
REAL_LOAD_HUBS = check_graph_scenario._real_load_hubs


@pytest.fixture(autouse=True)
def _hand_made_hub_list(monkeypatch):
    monkeypatch.setattr(check_graph_scenario, "load_hubs", lambda: TEST_HUBS)
    # never in official mode by accident (it would check the real, private frozen files)
    monkeypatch.delenv("ANALYSTLAB_OFFICIAL", raising=False)

@pytest.fixture(autouse=True)
def _no_real_detection_check(monkeypatch):
    # tests of the VM runner use fake runs: the real detection checker (tools/check_alerts.py, a
    # subprocess over recordings/) must never run from them; tests that care pass detect_check=
    import run_in_vm
    monkeypatch.setattr(run_in_vm, "default_detect_check", lambda s, rid, recordings=None: "NOT CHECKED")

from engine.graph import Layer2 as _Layer2  # noqa: E402

REAL_FROM_POOL_FILE = _Layer2.from_pool_file.__func__


@pytest.fixture(autouse=True)
def _hand_made_pools_skip_the_frozen_hash(monkeypatch):
    # the frozen pool hash (confidence.pool_sha256, set 2026-10-30) names the REAL laptop pool;
    # tests build their own small pools, so for them the hash check is off. Everything else in
    # the config is the frozen one. tests/test_confidence.py checks the real refusal with
    # REAL_FROM_POOL_FILE.
    from dataclasses import replace
    from engine import confidence as C

    def from_pool_file(cls, path, cfg=None):
        cfg = replace(cfg or C.load_config(), pool_sha256=None)
        return REAL_FROM_POOL_FILE(cls, path, cfg)
    monkeypatch.setattr(_Layer2, "from_pool_file", classmethod(from_pool_file))


from engine import evaluation as _evaluation  # noqa: E402

# Captured ONCE on the module itself: a test that imports tests.conftest again (a second module object)
# while the autouse stub below is active would otherwise capture the stub (2026-11-14: order-dependent
# failure of test_the_freeze_tag_checked_is_the_current_one when run alone).
if not hasattr(_evaluation, "_real_code_problems"):
    _evaluation._real_code_problems = _evaluation.code_problems
REAL_CODE_PROBLEMS = _evaluation._real_code_problems


@pytest.fixture(autouse=True)
def _frozen_code_for_tests(monkeypatch):
    # official work needs the git tag freeze-v2 and the code exactly as frozen (engine/evaluation.py);
    # tests run on a working tree, so for them the code counts as frozen. tests/test_evaluation.py
    # checks the real gate with REAL_CODE_PROBLEMS on a throw-away git repository.
    monkeypatch.setattr(_evaluation, "code_problems", lambda tag=None, root=None, check_sigma=True: [])
    monkeypatch.setattr(_evaluation, "code_state", lambda root=None: {"commit": "test", "tag": _evaluation.FREEZE_TAG, "frozen": True})