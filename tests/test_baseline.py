"""Package B part 2: learned-normal baselines (engine/baseline.py) and the two rules using them."""

import hashlib
import json
import sqlite3

from engine import baseline as bl
from engine import own_rules
from engine.store import EventStore
from tests.test_detect import ev, store


def port(seconds, image, host="h1", origin="normal", port_no=47213, ip="127.0.0.1"):
    r = ev(None, seconds, host=host, origin=origin, channel=None, Image=image, LocalIp=ip, LocalPort=port_no)
    r.update({"source": "agent", "type": "PORT_LISTEN_START", "record_id": None, "session": "s1", "seq": int(seconds * 10) + 1})
    return r


def con_of(tmp_path, recs):
    return sqlite3.connect(store(tmp_path, recs))


LEARN = [ev(1, 0, Image=r"C:\Windows\System32\cmd.exe", ParentImage=r"C:\Windows\explorer.exe"),
         ev(1, 1, Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", ParentImage=r"C:\Windows\System32\cmd.exe"),
         ev(1, 2, Image=r"C:\x\notepad.exe", ParentImage=r"C:\Windows\explorer.exe"),          # not a shell
         ev(1, 3, origin="project", Image=r"C:\Windows\System32\cmd.exe", ParentImage=r"C:\tools\ours.exe"),
         port(4, r"C:\Windows\System32\svchost.exe")]


def test_learn_keeps_only_shell_pairs_and_listeners_of_normal_use(tmp_path):
    b = bl.learn(con_of(tmp_path, LEARN))
    assert b["h1"]["shell_pairs"] == [["cmd.exe", "powershell.exe"], ["explorer.exe", "cmd.exe"]]
    assert b["h1"]["listeners"] == ["svchost.exe"]                # our own tools never learned


def test_learn_until_and_sessions(tmp_path):
    con = con_of(tmp_path, LEARN)
    assert bl.learn(con, until="2026-10-22T10:00:01")["h1"]["shell_pairs"] == [["explorer.exe", "cmd.exe"]]
    assert bl.learn(con, sessions=["nope"]) == {}


def test_save_load_round_trip(tmp_path):
    b = bl.learn(con_of(tmp_path, LEARN))
    digest = bl.save(b, str(tmp_path / "b" / "x.json"), "test")
    assert len(digest) == 64
    assert hashlib.sha256((tmp_path / "b" / "x.json").read_bytes()).hexdigest() == digest   # = Get-FileHash
    m = bl.load([str(tmp_path / "b" / "x.json")])
    assert ("explorer.exe", "cmd.exe") in m["h1"]["shell_pairs"] and "svchost.exe" in m["h1"]["listeners"]


def test_new_shell_parent_fires_only_on_unseen_pairs(tmp_path):
    b = {"h1": {"shell_pairs": {("explorer.exe", "cmd.exe"), ("cmd.exe", "powershell.exe")}, "listeners": set()}}
    later = [ev(1, 100, Image=r"C:\Windows\System32\cmd.exe", ParentImage=r"C:\Windows\explorer.exe"),       # known
             ev(1, 101, Image=r"C:\Windows\System32\CMD.EXE", ParentImage=r"C:\Users\u\viewer.exe"),        # new
             ev(1, 102, Image=r"C:\x\notepad.exe", ParentImage=r"C:\Users\u\viewer.exe"),                   # not a shell
             ev(1, 103, origin="project", Image=r"C:\Windows\System32\cmd.exe", ParentImage=r"C:\Users\u\viewer.exe"),
             ev(1, 104, host="h2", Image=r"C:\Windows\System32\cmd.exe", ParentImage=r"C:\Users\u\viewer.exe")]  # no baseline
    alerts = own_rules.new_shell_parent(con_of(tmp_path, later), b)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_id == "analystlab.new_shell_parent" and a.details == {"parent": "viewer.exe", "shell": "cmd.exe"}
    assert a.evidence == (EventStore.dedup_key(later[1]),) and a.time == "2026-10-22T10:01:41.000Z"


def test_new_listener_fires_only_on_unseen_programs(tmp_path):
    b = {"h1": {"shell_pairs": set(), "listeners": {"svchost.exe"}}}
    later = [port(100, r"C:\Windows\System32\svchost.exe", port_no=7680),
             port(101, r"D:\s3\s3_listen.exe"),
             port(102, r"D:\s3\s3_listen.exe", origin="project"),
             port(103, r"D:\s3\s3_listen.exe", host="h2")]
    alerts = own_rules.new_listener(con_of(tmp_path, later), b)
    assert [a.details["program"] for a in alerts] == ["s3_listen.exe"]
    assert alerts[0].details["address"] == "127.0.0.1:47213"


def test_new_listener_loopback_only_is_low_network_is_medium(tmp_path):
    """v4 F5: a loopback port can only be reached from this machine -> low (stored, not raised);
    any other address keeps the rule's level."""
    b = {"h1": {"shell_pairs": set(), "listeners": set()}}
    later = [port(100 + i, rf"D:\x\p{i}.exe", port_no=40000 + i, ip=ip)
             for i, ip in enumerate(["127.0.0.1", "127.5.6.7", "::1", "0.0.0.0", "::", "10.0.2.15"])]
    alerts = own_rules.new_listener(con_of(tmp_path, later), b)
    levels = {a.details["address"].rsplit(":", 1)[0]: a.level for a in alerts}
    assert levels == {"127.0.0.1": "low", "127.5.6.7": "low", "::1": "low",
                      "0.0.0.0": "medium", "::": "medium", "10.0.2.15": "medium"}
    assert own_rules.new_listener(con_of(tmp_path, later), b, loopback_level="medium")[0].level == "medium"


def test_learn_wipers_and_load_merges_them(tmp_path):
    """v4 F3: the programs that created files and deleted them again, learned into their own file;
    load() merges them with the other baselines; older files without 'wipers' still load."""
    from tests.test_create_send_wipe import creates_with_image, story
    recs = creates_with_image(story(), r"C:\Apps\Updater.exe")
    con = con_of(tmp_path, recs)
    w = bl.learn_wipers(con)
    assert w["h1"]["wipers"] == ["updater.exe"] and w["h1"]["shell_pairs"] == [] and w["h1"]["listeners"] == []
    assert bl.learn_wipers(con, until="2026-10-22T10:00:10")["h1"]["wipers"] == []   # the episode came later
    bl.save(w, str(tmp_path / "b" / "w.json"), "test")
    bl.save(bl.learn(con_of(tmp_path, LEARN)), str(tmp_path / "b" / "x.json"), "test")
    m = bl.load([str(tmp_path / "b" / "x.json"), str(tmp_path / "b" / "w.json")])
    assert m["h1"]["wipers"] == {"updater.exe"} and "svchost.exe" in m["h1"]["listeners"]


def test_learn_wipers_filters_and_never_learns_shells(tmp_path):
    from tests.test_create_send_wipe import creates_with_image, story
    recs = [dict(r, session="S1") for r in creates_with_image(story(), r"C:\Apps\Updater.exe")]
    recs += [dict(r, host="h2", session="S2") for r in creates_with_image(story(), r"C:\Windows\System32\cmd.exe")]
    con = con_of(tmp_path, recs)
    w = bl.learn_wipers(con)
    assert w["h1"]["wipers"] == ["updater.exe"] and w["h2"]["wipers"] == []          # a shell is never learned
    assert set(bl.learn_wipers(con, host="H1")) == {"h1"}
    assert "h1" not in bl.learn_wipers(con, sessions=["S2"])                          # h1 had no S2 events
    assert bl.learn_wipers(con, sessions=["S1"])["h1"]["wipers"] == ["updater.exe"]


def test_run_all_uses_the_baseline_only_when_given(tmp_path):
    b = {"h1": {"shell_pairs": set(), "listeners": set()}}
    con = con_of(tmp_path, [ev(1, 0, Image=r"C:\Windows\System32\cmd.exe", ParentImage=r"C:\x\viewer.exe")])
    assert own_rules.run_all(con) == []
    assert [a.rule_id for a in own_rules.run_all(con, baseline=b)] == ["analystlab.new_shell_parent"]


def test_sessions_of_runs(tmp_path):
    recs = [dict(ev(1, 5), session="A"), dict(ev(1, 500), session="B")]
    con = con_of(tmp_path, recs)
    run = {"start": "2026-10-22T10:00:00Z", "end": "2026-10-22T10:01:00Z"}
    assert bl.sessions_of_runs(con, [run]) == ["A"]

def test_load_refuses_a_file_that_is_not_a_baseline(tmp_path):
    import pytest
    (tmp_path / "hubs.json").write_text('{"hubs": ["c:\\\\x.exe"]}', encoding="utf-8")
    with pytest.raises(ValueError, match="not a learned-normal baseline"):
        bl.load([str(tmp_path / "hubs.json")])
