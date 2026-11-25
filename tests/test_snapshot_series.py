"""harness/snapshot_series.py: a frozen run_series series on another snapshot."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "harness"))
import snapshot_series as D  # noqa: E402


def test_every_run_command_names_the_snapshot():
    cmd = D.runner_cmd("REC", "lived-in", headless=True)
    own = D.RS.item_cmd(cmd, "s0", "practice")
    blind = D.RS.item_cmd(cmd, r"blind:C:\x\b18", "official")
    for c in (own, blind):
        i = c.index("--snapshot")
        assert c[i + 1] == "lived-in"
    assert os.path.basename(own[2]) == "run_in_vm.py" and os.path.basename(blind[2]) == "run_blind.py"
    assert blind[-3:] == ["--label", "official", r"C:\x\b18"] and own[-1] == "s0"


def test_official_is_refused_without_the_frozen_code(monkeypatch, capsys):
    monkeypatch.setattr(D.RS, "has_freeze_tag", lambda *a: True)
    monkeypatch.setattr(D.RS, "official_problems", lambda *a: ["tools differ from freeze-v4"])
    monkeypatch.setattr(D.RS, "run_series", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not run")))
    assert D.main(["--snapshot", "lived-in", "--label", "official", "s0"]) == 2
    assert "Refusing" in capsys.readouterr().out


def test_the_series_gets_the_snapshot_command_and_the_official_env(monkeypatch):
    got = {}
    monkeypatch.setattr(D.RS, "has_freeze_tag", lambda *a: True)
    monkeypatch.setattr(D.RS, "official_problems", lambda *a: [])

    def fake(order, label, seed, cmd, rec, stop_after, pause, env=None):
        got.update(order=order, label=label, cmd=cmd, env=env)
        return {"runs": [{"exit_code": 0} for _ in order]}
    monkeypatch.setattr(D.RS, "run_series", fake)
    monkeypatch.setattr(D.RS, "keep_awake", __import__("contextlib").nullcontext)
    assert D.main(["--snapshot", "lived-in", "--label", "official", "--repeats", "3", "--seed", "7", "s0"]) == 0
    assert got["order"] == ["s0"] * 3 and got["label"] == "official" and got["env"]["ANALYSTLAB_OFFICIAL"] == "1"
    assert got["cmd"][got["cmd"].index("--snapshot") + 1] == "lived-in"
