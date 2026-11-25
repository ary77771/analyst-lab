"""Package A: the detection engine (engine/detect.py) on small hand-made event stores."""

import hashlib
import sqlite3
import os
import stat
from datetime import datetime, timedelta, timezone

import pytest

from engine import detect
from engine.alerts import AlertStore
from engine.store import EventStore

SYSMON = "Microsoft-Windows-Sysmon/Operational"
T0 = datetime(2026, 10, 22, 10, 0, 0, tzinfo=timezone.utc)
_seq = [0]


def ev(event_id, seconds=0.0, origin="normal", channel=SYSMON, paused=None, host="h1", happened=None, **data):
    """A Sysmon-like record logged at T0+seconds; happened = seconds of its UtcTime if different."""
    _seq[0] += 1
    t = (T0 + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
    if happened is not None:
        data["UtcTime"] = (T0 + timedelta(seconds=happened)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    r = {"host": host, "channel": channel, "record_id": _seq[0], "time": t, "event_id": event_id,
         "origin": origin, "source": "sysmon", "data": data}
    if paused:
        r["paused"] = 1
    return r


def store(tmp_path, records, name=None):
    _seq[0] += 1
    path = str(tmp_path / (name or f"e{_seq[0]}.db"))         # a fresh store every call
    st = EventStore(path)
    st.insert(records)
    st.close()
    return path


def rules_from(tmp_path, text, source="sigma", name="r.yml"):
    d = tmp_path / f"rules_{name}"
    d.mkdir(exist_ok=True)
    (d / name).write_text(text, encoding="utf-8")
    rules, skipped, failures = detect.load_rules([str(d)], source)
    assert not failures, failures
    return rules


def run(tmp_path, records, rule_text, source="sigma", **kw):
    con = detect.open_store(store(tmp_path, records))
    alerts = detect.detect(con, rules_from(tmp_path, rule_text, source), **kw)
    con.close()
    return alerts


EVIL = """
title: evil program started
id: 00000000-0000-0000-0000-000000000001
status: test
level: high
author: test author
logsource: {category: process_creation, product: windows}
detection: {sel: {Image|endswith: '\\\\evil.exe'}, condition: sel}
"""


def test_simple_rule_fires_and_near_misses_do_not(tmp_path):
    recs = [ev(1, 0, Image=r"C:\x\evil.exe"),
            ev(1, 1, Image=r"C:\x\notevil.exe"),        # different name
            ev(1, 2, Image=r"C:\x\evil.exe.txt"),       # doesn't END with it
            ev(3, 3, Image=r"C:\x\evil.exe")]           # right program, wrong event type
    alerts = run(tmp_path, recs, EVIL)
    assert len(alerts) == 1
    a = alerts[0]
    assert (a.rule_id, a.level, a.source, a.host) == ("00000000-0000-0000-0000-000000000001", "high", "sigma", "h1")
    assert a.time == "2026-10-22T10:00:00.000Z" and a.evidence == (EventStore.dedup_key(recs[0]),)
    assert "test author" in a.reason and "evil program started" in a.reason


def test_matching_ignores_case_like_sigma(tmp_path):
    rule = """
title: exact name
id: 00000000-0000-0000-0000-000000000002
level: medium
logsource: {category: process_creation, product: windows}
detection: {sel: {OriginalFileName: 'powershell.exe'}, condition: sel}
"""
    assert len(run(tmp_path, [ev(1, 0, OriginalFileName="PowerShell.EXE")], rule)) == 1
    assert len(run(tmp_path, [ev(1, 0, OriginalFileName="powershell.exe.bak")], rule)) == 0


def test_own_tools_paused_rows_and_other_channels_never_match(tmp_path):
    recs = [ev(1, 0, origin="project", Image=r"C:\x\evil.exe"),
            ev(1, 1, paused=True, Image=r"C:\x\evil.exe"),
            ev(1, 2, channel="Security", Image=r"C:\x\evil.exe")]
    assert run(tmp_path, recs, EVIL) == []


def test_regex_rules_and_a_broken_pattern(tmp_path):
    rule = """
title: regex
id: 00000000-0000-0000-0000-000000000003
level: low
logsource: {category: process_creation, product: windows}
detection: {sel: {CommandLine|re: '-e(nc)? [A-Za-z0-9+/=]{20,}'}, condition: sel}
"""
    recs = [ev(1, 0, CommandLine="x -enc QUJDREVGR0hJSktMTU5PUFFSU1RVVg=="), ev(1, 1, CommandLine="x -enc short")]
    assert len(run(tmp_path, recs, rule)) == 1
    assert detect._regexp("(", "anything") is False
    assert detect._regexp(".*", None) is False          # a missing field never matches, not even '.*'
    assert detect._regexp(".*", "") is True


def test_min_level_filters(tmp_path):
    recs = [ev(1, 0, Image=r"C:\x\evil.exe")]
    assert len(run(tmp_path, recs, EVIL, min_level="high")) == 1
    assert run(tmp_path, recs, EVIL, min_level="critical") == []


BURST = """
title: file created in lab folder
name: lab_file
logsource: {category: file_event, product: windows}
detection: {sel: {TargetFilename|contains: '\\\\AnalystLab\\\\'}, condition: sel}
---
title: many new files by one process
name: file_burst
level: medium
correlation:
  type: event_count
  rules: [lab_file]
  group-by: [ProcessGuid]
  timespan: 15s
  condition: {gte: 30}
"""


def files(n, spread, guid="{AAAA}", start=0.0):
    step = spread / (n - 1) if n > 1 else 0
    return [ev(11, start + i * step, ProcessGuid=guid, TargetFilename=fr"C:\AnalystLab\f{i}.txt") for i in range(n)]


def test_event_count_correlation_boundaries(tmp_path):
    recs = files(30, 14.0)
    alerts = run(tmp_path, recs, BURST, source="analystlab")
    assert len(alerts) == 1, "30 files in 14 s must fire, once"
    a = alerts[0]
    assert a.rule_id == "analystlab.file_burst" and a.host == "h1"
    assert set(a.evidence) == {EventStore.dedup_key(r) for r in recs}    # the whole burst is evidence
    assert a.time == "2026-10-22T10:00:14.000Z"                          # when the 30th file arrived
    assert a.details["window_end"] == "2026-10-22T10:00:14.000Z"
    assert a.details["window_start"] == "2026-10-22T09:59:59.000Z"       # 15 s before it
    assert "30" in a.reason
    assert run(tmp_path, files(29, 14.0), BURST, source="analystlab") == []        # one short
    assert run(tmp_path, files(30, 16.0), BURST, source="analystlab") == []        # too slow
    two = files(15, 5.0, "{AAAA}") + files(15, 5.0, "{BBBB}")
    assert run(tmp_path, two, BURST, source="analystlab") == []                    # two processes


def test_one_long_burst_is_one_alert(tmp_path):
    """40 files in 14 s: the backend reports 11 overlapping windows; they are one burst."""
    alerts = run(tmp_path, files(40, 14.0), BURST, source="analystlab")
    assert len(alerts) == 1 and len(alerts[0].evidence) == 40
    assert alerts[0].details["windows_merged"] == 11
    assert alerts[0].time.startswith("2026-10-22T10:00:10.")                     # the 30th of 40 files
    # two bursts a minute apart stay two alerts
    two = files(30, 10.0) + files(30, 10.0, start=60)
    assert len(run(tmp_path, two, BURST, source="analystlab")) == 2


def test_correlations_never_mix_computers(tmp_path):
    split = [dict(r, host="h2") if i % 2 else r for i, r in enumerate(files(30, 10.0))]
    assert run(tmp_path, split, BURST, source="analystlab") == []                  # 15 + 15 on two machines
    both = files(30, 10.0) + [dict(r, host="h2") for r in files(30, 10.0, start=0.5)]
    alerts = run(tmp_path, both, BURST, source="analystlab")
    assert sorted(a.host for a in alerts) == ["h1", "h2"]
    assert all(len(a.evidence) == 30 for a in alerts)


SEQUENCE = """
title: outgoing connection
name: conn
logsource: {category: network_connection, product: windows}
detection: {sel: {Initiated: 'true'}, condition: sel}
---
title: executable written
name: exe_written
logsource: {category: file_event, product: windows}
detection: {sel: {TargetFilename|endswith: '.exe'}, condition: sel}
---
title: program started
name: started
logsource: {category: process_creation, product: windows}
detection: {sel: {Image|endswith: '.exe'}, condition: sel}
---
title: connect, write a program, start it
name: fetch_write_run
level: high
correlation:
  type: temporal_ordered
  rules: [conn, exe_written, started]
  aliases:
    proc:
      conn: ProcessGuid
      exe_written: ProcessGuid
      started: ParentProcessGuid
  group-by: [proc]
  timespan: 60s
"""


def chain(t_conn=0, t_file=1, t_start=5, writer="{AAAA}", parent="{AAAA}"):
    return [ev(3, t_conn, ProcessGuid=writer, Initiated="true", DestinationIp="10.0.2.2"),
            ev(11, t_file, ProcessGuid=writer, TargetFilename=r"C:\Users\u\Downloads\p.exe"),
            ev(1, t_start, ProcessGuid="{CCCC}", ParentProcessGuid=parent, Image=r"C:\Users\u\Downloads\p.exe")]


@pytest.mark.parametrize("case,fires", [
    (dict(), True),
    (dict(t_start=59), True),
    (dict(t_start=61), False),                    # outside the 60 s window
    (dict(t_conn=2, t_file=1), False),            # wrong order: file before connection
    (dict(parent="{BBBB}"), False),               # started by someone else
])
def test_temporal_ordered_join_across_field_names(tmp_path, case, fires):
    """The S1 spike (plan B): different field names joined with Sigma correlation aliases."""
    alerts = run(tmp_path, chain(**case), SEQUENCE, source="analystlab")
    assert bool(alerts) == fires
    if fires:
        assert all(len(a.evidence) == 3 for a in alerts)
        assert alerts[0].details["metric"] == "temporal_ordered"


def test_sequence_uses_when_events_happened_not_when_logged(tmp_path):
    """Sysmon logs network events late: the connection happened first but was logged last."""
    recs = chain()
    recs[0] = ev(3, 4.0, happened=0.0, ProcessGuid="{AAAA}", Initiated="true", DestinationIp="10.0.2.2")
    alerts = run(tmp_path, recs, SEQUENCE, source="analystlab")
    assert len(alerts) == 1
    recs[0] = ev(3, 0.0, happened=4.0, ProcessGuid="{AAAA}", Initiated="true", DestinationIp="10.0.2.2")
    assert run(tmp_path, recs, SEQUENCE, source="analystlab") == []              # really happened after


def test_simple_alert_time_is_when_it_happened(tmp_path):
    alerts = run(tmp_path, [ev(1, 9.0, happened=2.5, Image=r"C:\x\evil.exe")], EVIL)
    assert alerts[0].time == "2026-10-22T10:00:02.500Z"


TEMPORAL = """
title: name lookup
name: lookup
logsource: {category: dns_query, product: windows}
detection: {sel: {QueryName|endswith: '.test'}, condition: sel}
---
title: file written
name: written
logsource: {category: file_event, product: windows}
detection: {sel: {TargetFilename|endswith: '.txt'}, condition: sel}
---
title: both, any order
name: both
level: low
correlation:
  type: temporal
  rules: [lookup, written]
  group-by: [ProcessGuid]
  timespan: 30s
---
title: many different names looked up
name: many_names
level: low
correlation:
  type: value_count
  rules: [lookup]
  group-by: [ProcessGuid]
  timespan: 60s
  condition: {gte: 3, field: QueryName}
"""


def test_temporal_and_value_count(tmp_path):
    recs = [ev(11, 0, ProcessGuid="{A}", TargetFilename=r"C:\a.txt"),
            ev(22, 5, ProcessGuid="{A}", QueryName="one.test"),
            ev(22, 6, ProcessGuid="{A}", QueryName="two.test"),
            ev(22, 7, ProcessGuid="{A}", QueryName="two.test")]
    got = {a.rule_id for a in run(tmp_path, recs, TEMPORAL, source="analystlab")}
    assert got == {"analystlab.both"}                    # only 2 different names: no value_count alert
    recs.append(ev(22, 8, ProcessGuid="{A}", QueryName="three.test"))
    got = {a.rule_id for a in run(tmp_path, recs, TEMPORAL, source="analystlab")}
    assert got == {"analystlab.both", "analystlab.many_names"}


def test_same_alerts_twice_and_written_once(tmp_path):
    path = store(tmp_path, chain() + files(30, 10.0, "{DDDD}", start=100))
    rules = rules_from(tmp_path, SEQUENCE, "analystlab") + rules_from(tmp_path, BURST, "analystlab", "b.yml")
    con = detect.open_store(path)
    first, second = detect.detect(con, rules), detect.detect(con, rules)
    con.close()
    assert first and [a.alert_id for a in first] == [a.alert_id for a in second]
    s = AlertStore(str(tmp_path / "a.db"))
    assert s.write(first) == len({a.alert_id for a in first})
    assert s.write(second) == 0
    s.close()


def test_after_id_scores_only_new_events(tmp_path):
    path = store(tmp_path, [ev(1, 0, Image=r"C:\x\evil.exe"), ev(1, 1, Image=r"C:\y\evil.exe")])
    con = detect.open_store(path)
    alerts = detect.detect(con, rules_from(tmp_path, EVIL), after_id=1)
    assert len(alerts) == 1 and alerts[0].time.startswith("2026-10-22T10:00:01")


def test_store_is_only_read(tmp_path):
    path = store(tmp_path, [ev(1, 0, Image=r"C:\x\evil.exe")])
    before = hashlib.sha256(open(path, "rb").read()).hexdigest()
    con = detect.open_store(path)
    assert len(detect.detect(con, rules_from(tmp_path, EVIL))) == 1
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        con.execute("DELETE FROM events")
    con.close()
    assert hashlib.sha256(open(path, "rb").read()).hexdigest() == before


@pytest.mark.parametrize("product", ["linux", None])
def test_rules_for_other_products_are_not_used(tmp_path, product):
    text = EVIL.replace("product: windows", f"product: {product}") if product else EVIL.replace(", product: windows", "")
    d = tmp_path / "other"
    d.mkdir()
    (d / "r.yml").write_text(text, encoding="utf-8")
    rules, skipped, failures = detect.load_rules([str(d)])
    assert rules == [] and skipped == 1 and failures == []


def test_stream_hash_category_is_ours(tmp_path):
    rule = """
title: downloaded file mark
id: 00000000-0000-0000-0000-000000000015
level: low
logsource: {category: create_stream_hash, product: windows}
detection: {sel: {TargetFilename|endswith: ':Zone.Identifier'}, condition: sel}
"""
    alerts = run(tmp_path, [ev(15, 0, TargetFilename=r"C:\d\x.exe:Zone.Identifier"), ev(11, 1, TargetFilename=r"C:\d\x.exe:Zone.Identifier")], rule)
    assert len(alerts) == 1 and alerts[0].details["event_id"] == 15


def test_duplicate_own_rule_names_are_refused(tmp_path):
    d = tmp_path / "dups"
    d.mkdir()
    one = "title: a\nname: same\nlevel: low\nlogsource: {category: process_creation, product: windows}\ndetection: {sel: {Image|endswith: 'a.exe'}, condition: sel}\n"
    (d / "a.yml").write_text(one, encoding="utf-8")
    (d / "b.yml").write_text(one.replace("a.exe", "b.exe"), encoding="utf-8")
    rules, _, failures = detect.load_rules([str(d)], "analystlab")
    assert len(rules) == 1 and "duplicate rule id analystlab.same" in failures[0][1]


def test_rule_loading_reports_problems(tmp_path):
    d = tmp_path / "mixed"
    d.mkdir()
    (d / "broken.yml").write_text("title: [unclosed\n", encoding="utf-8")
    (d / "registry.yml").write_text("""
title: image load
id: 00000000-0000-0000-0000-000000000009
logsource: {category: image_load, product: windows}
detection: {sel: {ImageLoaded|endswith: 'x.dll'}, condition: sel}
""", encoding="utf-8")
    (d / "good.yml").write_text(EVIL, encoding="utf-8")
    rules, skipped, failures = detect.load_rules([str(d)])
    assert [r.title for r in rules] == ["evil program started"]
    assert skipped == 1                                     # a category we don't record
    assert [os.path.basename(p) for p, _ in failures] == ["broken.yml"]
    # our own rules need a name: their id is analystlab.<name>
    (d / "broken.yml").unlink()
    (d / "registry.yml").unlink()
    rules, _, failures = detect.load_rules([str(d)], "analystlab")
    assert rules == [] and "need a name" in failures[0][1]


def test_sql_errors_are_reported_not_silent(tmp_path):
    con = detect.open_store(store(tmp_path, [ev(1, 0, Image="x")]))
    bad = detect.Rule("bad", "bad", "high", "sigma", "x.yml", ["SELECT * FROM logs WHERE NoSuchColumn = 1"])
    timings = {}
    assert detect.detect(con, [bad], timings=timings) == []
    assert timings["_errors"][0][0] == "bad"


def test_an_event_without_a_readable_time_is_skipped_not_fatal(tmp_path):
    recs = [ev(1, 0, Image=r"C:\x\evil.exe"), dict(ev(1, 1, Image=r"C:\y\evil.exe"), time="garbage")]
    timings = {}
    con = detect.open_store(store(tmp_path, recs))
    alerts = detect.detect(con, rules_from(tmp_path, EVIL), timings=timings)
    assert len(alerts) == 1 and len(timings["_untimed"]) == 1 and "_errors" not in timings


def test_correlation_alert_keeps_its_id_as_the_burst_grows(tmp_path):
    a = run(tmp_path, files(30, 14.0), BURST, source="analystlab")
    b = run(tmp_path, files(30, 14.0) + files(10, 3.0, start=14.5), BURST, source="analystlab")
    assert a[0].alert_id == b[0].alert_id and len(b[0].evidence) == 40


# --- registry categories (config v0.3, version 2 package C1) ---

RUN_KEY = r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\updater"


def reg_rule(category, rid="00000000-0000-0000-0000-000000000012"):
    return f"""
title: run key {category}
id: {rid}
level: medium
logsource: {{category: {category}, product: windows}}
detection: {{sel: {{TargetObject|contains: '\\\\CurrentVersion\\\\Run'}}, condition: sel}}
"""


@pytest.mark.parametrize("category, fires_on", [
    ("registry_set", [(13, "SetValue")]), ("registry_add", [(12, "CreateKey")]),
    ("registry_delete", [(12, "DeleteKey"), (12, "DeleteValue")]), ("registry_rename", [(14, "RenameKey")]),
    ("registry_event", [(12, "CreateKey"), (12, "DeleteKey"), (12, "DeleteValue"), (13, "SetValue"), (14, "RenameKey")]),
])
def test_registry_categories_match_their_sysmon_events(tmp_path, category, fires_on):
    """Sysmon's event 12 holds key creation AND deletion: add/delete also need EventType (SigmaHQ's own
    Sysmon pipeline; v4 fix 2026-11-17, tests/test_registry_pipeline.py)."""
    kinds = [(12, "CreateKey"), (12, "DeleteKey"), (12, "DeleteValue"), (13, "SetValue"), (14, "RenameKey")]
    recs = [ev(e, i, EventType=t, TargetObject=RUN_KEY, Details="C:\\u\\a.exe") for i, (e, t) in enumerate(kinds)]
    recs.append(ev(11, 9, TargetFilename=r"C:\u\CurrentVersion\Run\a.exe"))      # a file, not the registry
    con = detect.open_store(store(tmp_path, recs))
    try:
        alerts = detect.detect(con, rules_from(tmp_path, reg_rule(category)), declared=False)
        got = sorted(con.execute("SELECT event_id, EventType FROM events WHERE dedup_key = ?", (a.evidence[0],)).fetchone()
                     for a in alerts)
    finally:
        con.close()
    assert got == sorted(fires_on)


def test_a_store_made_before_the_registry_fields_still_scores(tmp_path):
    path = store(tmp_path, [ev(1, 0, Image=r"C:\x\evil.exe")])
    con = sqlite3.connect(path)
    for col in ("EventType", "TargetObject", "Details", "NewName"):
        con.execute(f'ALTER TABLE events DROP COLUMN "{col}"')                   # as in an old store
    con.commit()
    con.close()
    con = detect.open_store(path)
    timings = {}
    alerts = detect.detect(con, rules_from(tmp_path, EVIL) + rules_from(tmp_path, reg_rule("registry_set"), name="g.yml"),
                           timings=timings)
    con.close()
    assert [a.title for a in alerts] == ["evil program started"] and not timings.get("_errors")