"""Lab "Why is this suspicious?" (engine/labs/why.py, engine/labs/_sigma_explain.py): fixtures only.

The key check ties the explanation to the real engine: a fixture rule is run by engine.detect over a
fixture store, and the page's explanation of the resulting alert must reproduce the match and highlight
exactly the matching characters."""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from sigma.collection import SigmaCollection

from engine import detect
from engine.alerts import Alert
from engine.labs import _sigma_explain as sx
from engine.labs import why
from engine.store import EventStore

SYSMON = "Microsoft-Windows-Sysmon/Operational"
T0 = datetime(2026, 10, 22, 10, 0, 0, tzinfo=timezone.utc)

RULE = r"""
title: Fixture ping delay
id: 0f0f0f0f-0000-4000-8000-000000000001
status: test
description: A fixture rule for the Why lab.
author: fixture author
references: [https://example.invalid/ref]
falsepositives: [A fixture false positive]
logsource: {category: process_creation, product: windows}
detection:
  selection_img:
    - Image|endswith: '\ping.exe'
    - OriginalFileName: 'PING.EXE'
  selection_cli:
    CommandLine|contains|all: ['-n ', '127.0.0.1']
  filter_parent:
    ParentImage|startswith: 'C:\Windows\System32\svchost'
  condition: all of selection_* and not filter_parent
level: high
tags: [attack.defense-evasion, attack.t1497.003]
"""

CORRELATION = r"""
title: Fixture many files
id: 0f0f0f0f-0000-4000-8000-000000000002
name: fixture_file
status: test
logsource: {category: file_event, product: windows}
detection:
  sel: {TargetFilename|endswith: '.tmp'}
  condition: sel
level: low
---
title: Fixture burst of files
id: 0f0f0f0f-0000-4000-8000-000000000003
status: test
correlation:
  type: event_count
  rules: [fixture_file]
  group-by: [ProcessGuid]
  timespan: 60s
  condition: {gte: 3}
level: medium
"""

_seq = [0]


def ev(event_id, seconds=0.0, **data):
    _seq[0] += 1
    t = (T0 + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
    data.setdefault("UtcTime", (T0 + timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3])
    return {"host": "h1", "channel": SYSMON, "record_id": _seq[0], "time": t, "event_id": event_id,
            "origin": "normal", "source": "sysmon", "data": data}


class FakeCtx:
    """The parts of engine.labs.Context the lab uses, over a fixture store."""

    def __init__(self, path, report=None):
        self.path, self._report = path, report

    def event(self, key):
        con = sqlite3.connect("file:" + path_uri(self.path) + "?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        row = con.execute("SELECT * FROM events WHERE dedup_key = ?", (key,)).fetchone()
        con.close()
        return {k: row[k] for k in row.keys() if row[k] is not None} if row else None

    def report(self, alert):
        if self._report is None:
            raise RuntimeError("no graph in this fixture")
        return self._report


def path_uri(p):
    import os
    return os.path.abspath(p).replace("\\", "/")


def setup(tmp_path, records, rule_text, name="fixture.yml"):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(exist_ok=True)
    (rules_dir / name).write_text(rule_text, encoding="utf-8")
    db = str(tmp_path / "e.db")
    st = EventStore(db)
    st.insert(records)
    st.close()
    rules, _, failures = detect.load_rules([str(rules_dir)], "sigma", filters=[])
    assert not failures, failures
    con = detect.open_store(db)
    alerts = detect.detect(con, rules, declared=False)
    con.close()
    return db, str(rules_dir), alerts


def test_explanation_reproduces_the_engines_match_and_highlights_the_exact_characters(tmp_path):
    hit = ev(1, 0, Image=r"C:\Tools\PING.exe", CommandLine="ping -n 5 127.0.0.1", ParentImage=r"C:\x\cmd.exe")
    miss = ev(1, 1, Image=r"C:\Tools\ping.exe", CommandLine="ping -n 5 10.0.0.1", ParentImage=r"C:\x\cmd.exe")
    filtered = ev(1, 2, Image=r"C:\Tools\ping.exe", CommandLine="ping -n 5 127.0.0.1",
                  ParentImage=r"C:\Windows\System32\svchost.exe")
    db, rules_dir, alerts = setup(tmp_path, [hit, miss, filtered], RULE)
    assert len(alerts) == 1                                    # the engine's verdict: only `hit`
    out = why.explain(FakeCtx(db), alerts[0], folders=[rules_dir])
    assert out["rule"]["found"] and out["rule"]["title"] == "Fixture ping delay"
    assert out["rule"]["tags"] == ["attack.defense-evasion", "attack.t1497.003"]
    assert out["rule"]["logsource"]["event_ids"] == [1]
    assert out["check"] == "reproduced" and not out["partly_checked"]
    e = out["events"][0]
    assert e["matched"] is True and set(e["matched_fields"]) == {"Image", "CommandLine"}
    fields = dict(e["fields"])
    cl = fields["CommandLine"]
    assert [cl[s:t] for s, t in e["highlights"]["CommandLine"]] == ["-n ", "127.0.0.1"]
    assert [fields["Image"][s:t] for s, t in e["highlights"]["Image"]] == [r"\PING.exe"]   # case ignored, like Sigma
    assert e["fields"][0][0] in ("Image", "CommandLine")       # matched fields come first
    sel = {s["name"]: s for s in e["selections"]}
    assert sel["selection_img"]["matched"] and sel["selection_cli"]["matched"]
    assert sel["filter_parent"]["matched"] is False and sel["filter_parent"]["filter"]
    # values are shown as the rule writes them, without the * a modifier added (found on real data: were empty)
    cli = sel["selection_cli"]["groups"][0][0]
    assert cli["values"] == ["-n ", "127.0.0.1"] and cli["words"] == ["contains", "all of"]
    assert cli["matched_values"] == ["-n ", "127.0.0.1"]
    assert sel["selection_img"]["groups"][0][0]["values"] == ["\\ping.exe"]
    assert sel["filter_parent"]["groups"][0][0]["values"] == ["C:\\Windows\\System32\\svchost"]
    assert "raw_xml" not in fields and "dedup_key" not in fields


def test_the_check_can_fail_an_event_the_rule_does_not_match_is_not_reproduced(tmp_path):
    # prove the test can fail: explain the engine's alert, but swap in an event the rule does not match
    hit = ev(1, 0, Image=r"C:\Tools\ping.exe", CommandLine="ping -n 5 127.0.0.1")
    other = ev(1, 1, Image=r"C:\Tools\notepad.exe", CommandLine="notepad")
    db, rules_dir, alerts = setup(tmp_path, [hit, other], RULE)
    a = alerts[0]
    forged = Alert(a.rule_id, a.title, a.source, a.level, a.time, a.host, a.reason, (EventStore.dedup_key(other),),
                   a.details)
    out = why.explain(FakeCtx(db), forged, folders=[rules_dir])
    assert out["check"] == "not_reproduced"
    assert out["events"][0]["highlights"] == {}


def test_correlation_alert_shows_its_structure_and_which_base_rule_each_event_matched(tmp_path):
    recs = [ev(11, i, TargetFilename=fr"C:\t\f{i}.tmp", ProcessGuid="{AAAA}") for i in range(4)]
    db, rules_dir, alerts = setup(tmp_path, recs, CORRELATION)
    burst = [a for a in alerts if a.rule_id.endswith("0003")]
    assert len(burst) == 1
    out = why.explain(FakeCtx(db), burst[0], folders=[rules_dir], max_events=2)
    r = out["rule"]
    assert r["kind"] == "correlation" and r["correlation"]["type"] == "event_count"
    assert r["correlation"]["group_by"] == ["ProcessGuid"] and r["correlation"]["rules"][0]["title"] == "Fixture many files"
    assert out["events_total"] == 4 and len(out["events"]) == 2
    assert all(e["matched"] and e["base_rule"] == "Fixture many files" for e in out["events"])
    assert out["check"] == "reproduced"


def test_rule_file_not_on_this_laptop_is_said_not_guessed(tmp_path):
    hit = ev(1, 0, Image=r"C:\Tools\ping.exe", CommandLine="ping -n 5 127.0.0.1")
    db, rules_dir, alerts = setup(tmp_path, [hit], RULE)
    empty = tmp_path / "empty"
    empty.mkdir()
    out = why.explain(FakeCtx(db), alerts[0], folders=[str(empty)])
    assert out["rule"] == {"found": False, "kind": "missing", "title": "Fixture ping delay",
                           "id": alerts[0].rule_id, "author": "fixture author", "techniques": []}
    assert out["check"] == "na" and out["events"][0]["fields"]


def test_python_rule_shows_its_own_docstring_and_settings(tmp_path):
    rec = ev(1, 0, Image=r"C:\x\svch0st.exe")
    db = str(tmp_path / "e.db")
    st = EventStore(db)
    st.insert([rec])
    st.close()
    a = Alert("analystlab.lookalike_name", "A program's name is a small typo away from a Windows program", "analystlab",
              "medium", "2026-10-22T10:00:00.000Z", "h1", "svch0st.exe is 1 edit from svchost.exe.",
              (EventStore.dedup_key(rec),), {"name": "svch0st.exe"})
    out = why.explain(FakeCtx(db), a)
    assert out["rule"]["kind"] == "python" and "typo" in out["rule"]["doc"].lower() or out["rule"]["doc"]
    assert out["rule"]["function"].endswith("lookalike_name") and out["check"] == "na"
    assert out["story"] == {"available": False, "problem": "RuntimeError"}


def test_story_rows_are_the_reports_own_rows(tmp_path):
    hit = ev(1, 0, Image=r"C:\Tools\ping.exe", CommandLine="ping -n 5 127.0.0.1")
    db, rules_dir, alerts = setup(tmp_path, [hit], RULE)
    report = {"timeline": [{"ink": "fact", "text": "cmd.exe started ping.exe", "short": "started ping.exe",
                            "time_precise": "2026-10-22T10:00:00.000000Z", "offset_text": "start", "in_chain": True,
                            "placement": "at"},
                           {"ink": "gap", "text": "Before this: who started cmd.exe", "placement": "before"}],
              "counts": {"facts": 1, "gaps": 1}, "summary": "s", "limitations": ["l"]}
    out = why.explain(FakeCtx(db, report), alerts[0], folders=[rules_dir])
    assert [r["ink"] for r in out["story"]["rows"]] == ["fact", "gap"]
    assert out["story"]["rows"][0]["text"] == "cmd.exe started ping.exe" and out["story"]["rows"][0]["in_chain"]


FILTER_DOC = r"""
title: Fixture filter
id: 0f0f0f0f-0000-4000-8000-0000000000f1
logsource: {category: process_creation, product: windows}
filter:
  rules: [0f0f0f0f-0000-4000-8000-000000000001]
  selection:
    ParentImage|endswith: '\trusted.exe'
  condition: not selection
"""


def test_the_projects_filter_documents_apply_as_in_the_engine(tmp_path):
    """rules/filters/ documents change what a rule fires on (engine/detect.load_rules applies them): the page
    must show the rule as the engine ran it, with the filter as a selection marked 'filter'."""
    from sigma.collection import SigmaCollection
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "fixture.yml").write_text(RULE, encoding="utf-8")
    filters = SigmaCollection.from_yaml(FILTER_DOC, collect_filters=True).filters
    path = str(rules_dir / "fixture.yml")
    rid = "0f0f0f0f-0000-4000-8000-000000000001"
    r = sx.load_rule(path, rid, filters=filters)
    event = {"Image": r"C:\t\ping.exe", "CommandLine": "ping -n 1 127.0.0.1", "ParentImage": r"C:\x\trusted.exe"}
    assert sx.evaluate(sx.load_rule(path, rid, filters=[]), event)["matched"] is True
    res = sx.evaluate(r, event)
    assert res["matched"] is False                                   # filtered, as the engine would
    added = [s for s in res["selections"] if s["name"].startswith("_filt")]
    assert added and all(s["filter"] for s in added) and added[0]["matched"] is True


def one_item(text):
    r = SigmaCollection.from_yaml("title: t\nlogsource: {category: process_creation, product: windows}\n"
                                  f"detection:\n  s:\n    {text}\n  condition: s\n").rules[0]
    return r


@pytest.mark.parametrize("item,event,want", [
    ("CommandLine|windash|contains: '-enc '", {"CommandLine": "powershell /enc AAA"}, True),
    ("CommandLine|windash|contains: '-enc '", {"CommandLine": "powershell enc AAA"}, False),
    ("DestinationIp|cidr: '10.0.0.0/8'", {"DestinationIp": "10.2.3.4"}, True),
    ("DestinationIp|cidr: '10.0.0.0/8'", {"DestinationIp": "192.168.0.1"}, False),
    ("CommandLine|re: 'a[0-9]+b'", {"CommandLine": "xx a123b yy"}, True),
    ("CommandLine|re: 'A[0-9]+B'", {"CommandLine": "xx a123b yy"}, False),        # regex is case-sensitive
    ("Image|cased: 'X.exe'", {"Image": "x.exe"}, False),
    ("Image: 'X.exe'", {"Image": "x.exe"}, True),
    ("ParentImage: null", {"Image": "x"}, True),
    ("ParentImage: null", {"ParentImage": "y"}, False),
    ("User|exists: true", {"User": "u"}, True),
    ("DestinationPort|gt: 1000", {"DestinationPort": 4444}, True),
    ("DestinationPort|gt: 1000", {"DestinationPort": 80}, False),
    ("EventID: 1", {"event_id": 1}, True),
    ("Image|endswith: '\\a?c.exe'", {"Image": r"C:\abc.exe"}, True),
])
def test_value_kinds_follow_sigma(item, event, want):
    assert sx.evaluate(one_item(item), event)["matched"] is want


def test_a_placeholder_is_not_checked_never_guessed():
    r = one_item("Image|expand: '%programs%'")
    res = sx.evaluate(r, {"Image": "anything"})
    assert res["matched"] is None


def test_every_own_rule_has_a_description_on_the_page():
    """fetch_write_run's description lives in engine/own_rules.py's module docstring, not on the function: the page
    showed an empty box on the S1 replay (found 2026-11-24). Every own rule must now show its description."""
    from engine import own_rules
    for rid in list(own_rules.RULES) + list(own_rules.BASELINE_RULES):
        a = Alert(rid, "t", "analystlab", "medium", "2026-10-22T10:00:00.000Z", "h1", "r", ("k",))
        assert why.python_rule(a)["doc"].strip(), rid
    a = Alert("analystlab.fetch_write_run", "t", "analystlab", "medium", "2026-10-22T10:00:00.000Z", "h1", "r", ("k",))
    assert why.python_rule(a)["doc"].startswith("fetch_write_run:")


def test_why_carries_the_word_for_word_view_and_the_rules_noise_line(tmp_path):
    """2026-11-24: "This is what an alarm says" merged into Why (its first screen), plus one line on how often the
    rule rang on normal use, from the receipts lab's committed-results reader."""
    hit = ev(1, 0, Image=r"C:\Tools\ping.exe", CommandLine="ping -n 5 127.0.0.1")
    db, rules_dir, alerts = setup(tmp_path, [hit], RULE)
    out = why.explain(FakeCtx(db), alerts[0], folders=[rules_dir])
    ww = out["wordforword"]
    assert ww and [r["key"] for r in ww["records"]] == list(alerts[0].evidence) and "lines" in ww
    assert "noise" in out
    own = Alert("analystlab.fetch_write_run", "Program connected out, wrote an executable, and it was started", "analystlab",
                "medium", "2026-10-22T10:00:00.000Z", "h1", "r", ("k",))
    line = why.noise_line(own)
    assert line is None or (line["text"] and "{" not in line["text"])        # filled from the results, never a template
