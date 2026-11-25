"""v4 F1: follow-through (engine/follow.py): what a flagged process and its descendants did next.
A derived view: never evidence, never new alerts."""
import sqlite3

import pytest

from engine import follow
from engine.alerts import Alert
from engine.graph import norm_path
from engine.store import EventStore
from tests.test_detect import ev, store

ROOT, SHELL, KID, GRAND, OTHER = "{RRRR}", "{SSSS}", "{KKKK}", "{GGGG}", "{OOOO}"
ZERO = "{00000000-0000-0000-0000-000000000000}"
EXPLORER = r"C:\Windows\explorer.exe"


def story():
    """ROOT (a viewer) starts SHELL at 10 s (the flagged start); SHELL connects, writes, starts KID,
    KID starts GRAND which connects; OTHER is unrelated; ROOT itself also acts."""
    return {
        "root_start": ev(1, 0, ProcessGuid=ROOT, ParentProcessGuid="{XXXX}", Image=r"C:\x\viewer.exe"),
        "shell_start": ev(1, 10, ProcessGuid=SHELL, ParentProcessGuid=ROOT, Image=r"C:\Windows\System32\cmd.exe"),
        "shell_before": ev(11, 5, ProcessGuid=SHELL, TargetFilename=r"C:\AnalystLab\early.txt"),     # before the trigger
        "shell_conn": ev(3, 12, ProcessGuid=SHELL, Initiated="true", DestinationIp="10.0.2.2", DestinationPort=80),
        "shell_file": ev(11, 13, ProcessGuid=SHELL, TargetFilename=r"C:\AnalystLab\a.exe"),
        "kid_start": ev(1, 14, ProcessGuid=KID, ParentProcessGuid=SHELL, Image=r"C:\Windows\System32\PING.EXE"),
        "grand_start": ev(1, 50, ProcessGuid=GRAND, ParentProcessGuid=KID, Image=r"C:\AnalystLab\stage2.exe"),
        "grand_conn": ev(3, 55, ProcessGuid=GRAND, Initiated="true", DestinationIp="10.0.2.2", DestinationPort=80),
        "late": ev(3, 700, ProcessGuid=GRAND, Initiated="true", DestinationIp="10.0.2.2", DestinationPort=80),
        "root_conn": ev(3, 20, ProcessGuid=ROOT, Initiated="true", DestinationIp="10.0.2.2", DestinationPort=80),
        "other": ev(3, 21, ProcessGuid=OTHER, Initiated="true", DestinationIp="10.0.2.2", DestinationPort=80),
        "ours": ev(3, 22, ProcessGuid=SHELL, origin="project", Initiated="true", DestinationIp="10.0.2.2", DestinationPort=80),
    }


def alert_on(rec, level="medium", rule="analystlab.new_shell_parent"):
    return Alert(rule, "t", "analystlab", level, "2026-10-22T10:00:10.000Z", rec["host"], "because",
                 (EventStore.dedup_key(rec),))


def followed(tmp_path, s, alerts, hubs=frozenset(), **kw):
    con = sqlite3.connect(store(tmp_path, list(s.values())))
    try:
        got = follow.follow_through(con, alerts, hubs=hubs, min_level="medium", **kw)
    finally:
        con.close()
    names = {EventStore.dedup_key(r): n for n, r in s.items()}
    return {aid: [names[k] for k in keys] for aid, keys in got.items()}


def test_the_flagged_process_and_its_descendants_are_followed_in_time_order(tmp_path):
    s = story()
    a = alert_on(s["shell_start"])
    assert followed(tmp_path, s, [a]) == {a.alert_id: ["shell_conn", "shell_file", "kid_start", "grand_start", "grand_conn"]}
    # not: its own evidence, what it did before the trigger, the parent's or a stranger's actions,
    # our own tools' rows, anything after the 10-minute window


def test_the_subject_of_a_start_alert_is_the_started_process_never_the_parent(tmp_path):
    s = story()
    a = alert_on(s["root_start"])                 # the viewer itself was flagged: now ITS tree follows
    got = followed(tmp_path, s, [a])[a.alert_id]
    assert "root_conn" in got and "shell_start" in got and "grand_conn" in got and "other" not in got


def test_an_alert_on_a_later_action_follows_from_that_action(tmp_path):
    s = story()
    a = alert_on(s["shell_file"])                 # e.g. a file rule: evidence is event 11 at 13 s
    assert followed(tmp_path, s, [a])[a.alert_id] == ["kid_start", "grand_start", "grand_conn"]


def test_low_alerts_earn_nothing_and_settings_bound_the_view(tmp_path):
    s = story()
    assert followed(tmp_path, s, [alert_on(s["shell_start"], level="low")]) == {}
    a = alert_on(s["shell_start"])
    assert followed(tmp_path, s, [a], window=3.5)[a.alert_id] == ["shell_conn", "shell_file"]
    assert followed(tmp_path, s, [a], max_events=2)[a.alert_id] == ["shell_conn", "shell_file"]


def test_hubs_are_never_followed_or_walked_through(tmp_path):
    s = story()
    s["root_start"] = ev(1, 0, ProcessGuid=ROOT, ParentProcessGuid="{XXXX}", Image=EXPLORER)
    hubs = frozenset({norm_path(EXPLORER)})
    assert followed(tmp_path, s, [alert_on(s["root_start"])], hubs=hubs) == {}          # an alert ON a hub
    # a hub BELOW the flagged process: its start is kept, what it does and starts is not
    s = story()
    s["kid_start"] = ev(1, 14, ProcessGuid=KID, ParentProcessGuid=SHELL, Image=EXPLORER)
    s["kid_conn"] = ev(3, 15, ProcessGuid=KID, Initiated="true", DestinationIp="10.0.2.2", DestinationPort=80)
    a = alert_on(s["shell_start"])
    assert followed(tmp_path, s, [a], hubs=hubs)[a.alert_id] == ["shell_conn", "shell_file", "kid_start"]


@pytest.mark.parametrize("guid", [ZERO, None])
def test_an_unknown_process_is_never_a_subject(tmp_path, guid):
    s = story()
    data = dict(Initiated="true", DestinationIp="10.0.2.2", DestinationPort=80)
    if guid:
        data["ProcessGuid"] = guid
    s["unknown"] = ev(3, 30, **data)
    s["unknown2"] = ev(3, 31, **data)
    assert followed(tmp_path, s, [alert_on(s["unknown"])]) == {}


def test_other_computers_and_big_families(tmp_path, monkeypatch):
    s = story()
    s["elsewhere"] = ev(3, 12, host="h2", ProcessGuid=SHELL, Initiated="true", DestinationIp="10.0.2.2", DestinationPort=80)
    monkeypatch.setattr(follow, "_CHUNK", 2)       # the family is queried in chunks
    a = alert_on(s["shell_start"])
    assert followed(tmp_path, s, [a])[a.alert_id] == ["shell_conn", "shell_file", "kid_start", "grand_start", "grand_conn"]


def test_evidence_and_alert_id_are_untouched(tmp_path):
    s = story()
    a = alert_on(s["shell_start"])
    before = (a.evidence, a.alert_id)
    followed(tmp_path, s, [a])
    assert (a.evidence, a.alert_id) == before


def test_guid_spelling_does_not_break_the_tree(tmp_path):
    s = story()
    s["kid_start"] = ev(1, 14, ProcessGuid=KID, ParentProcessGuid=SHELL.lower(), Image=r"C:\Windows\System32\PING.EXE")
    a = alert_on(s["shell_start"])
    assert "grand_conn" in followed(tmp_path, s, [a])[a.alert_id]


def test_our_own_tools_rows_give_no_subject_and_no_tree_link(tmp_path):
    s = story()
    s["shell_start"] = ev(1, 10, origin="project", ProcessGuid=SHELL, ParentProcessGuid=ROOT, Image=r"C:\Windows\System32\cmd.exe")
    assert followed(tmp_path, s, [alert_on(s["shell_start"])]) == {}                 # evidence is a lab row: no subject
    got = followed(tmp_path, s, [alert_on(s["root_start"])])                         # the runner is not a tree link:
    assert "kid_start" not in next(iter(got.values()))                               # nothing below it is reached


def test_several_subjects_and_a_hub_subject_named_by_a_later_row(tmp_path):
    s = story()
    a = Alert("r", "t", "sigma", "medium", "2026-10-22T10:00:10.000Z", "h1", "because",
              (EventStore.dedup_key(s["other"]), EventStore.dedup_key(s["grand_start"])))
    assert followed(tmp_path, s, [a])[a.alert_id] == ["grand_conn"]                  # OTHER did nothing more; GRAND did
    s = story()
    s["hub_a"] = ev(3, 30, ProcessGuid="{HHHH}", Initiated="true", DestinationIp="10.0.2.2", DestinationPort=80)
    s["hub_b"] = ev(3, 31, ProcessGuid="{HHHH}", Image=EXPLORER, Initiated="true", DestinationIp="10.0.2.2", DestinationPort=80)
    s["hub_c"] = ev(3, 32, ProcessGuid="{HHHH}", Image=EXPLORER, Initiated="true", DestinationIp="10.0.2.2", DestinationPort=80)
    a = Alert("r", "t", "sigma", "medium", "2026-10-22T10:00:30.000Z", "h1", "because",
              (EventStore.dedup_key(s["hub_a"]), EventStore.dedup_key(s["hub_b"])))
    assert followed(tmp_path, s, [a], hubs=frozenset({norm_path(EXPLORER)})) == {}
