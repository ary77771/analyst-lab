"""Lab "What would prove it?" (engine/labs/prove.py): every link/gap type of the graph has a witness row, and
"collected here" is read from the Sysmon configuration, never written by hand."""

import os
import re

from fastapi.testclient import TestClient

from engine.labs import prove

GRAPH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "engine", "graph.py")


def graph_kinds():
    """Hypothesis link kinds and gap kinds engine/graph.py can emit, read from its source."""
    src = open(GRAPH, encoding="utf-8").read()
    from engine.graph import TIMING_KINDS
    kinds = set(TIMING_KINDS.values())
    for chunk in src.split("self._edge(")[1:]:
        m = re.search(r'"(\w+)",\s*"hypothesis"', chunk[:600])
        if m:
            kinds.add(m.group(1))
    gaps = set(re.findall(r'_gap\([^)]*?"(\w+_unknown)"', src)) | set(re.findall(r'^\s+(\w+_unknown)\s{2,}', src, re.M))
    return kinds, gaps


def test_every_link_and_gap_type_of_the_graph_has_a_witness_row():
    kinds, gaps = graph_kinds()
    assert {"content_from", "remote_command", "fetched_then_ran", "same_path_unknown_content", "copy_of",
            "name_for_connection", "started_with_file_argument"} <= kinds            # the parse itself works
    assert {"parent_unknown", "origin_unknown", "actor_unknown", "content_unknown", "owner_unknown"} <= gaps
    missing = (kinds | gaps) - set(prove.WITNESSES)
    assert not missing, f"graph types without a witness row: {missing}"


def test_the_check_can_fail():
    kinds, gaps = graph_kinds()
    assert (kinds | gaps | {"a_new_kind"}) - set(prove.WITNESSES) == {"a_new_kind"}


def test_verdicts_from_the_real_sysmon_config():
    cfg = prove.config()
    assert cfg is not None
    v = {r["kind"]: r for r in prove.table(cfg)}
    assert v["content_from"]["verdict"] == "elsewhere"                     # Sysmon never records content
    assert v["content_from"]["helps"][0]["state"] == "all"                 # event 15 is on in this config
    assert v["same_path_unknown_content"]["verdict"] == "collected"
    assert v["copy_of"]["verdict"] == "elsewhere" and v["started_with_file_argument"]["verdict"] == "elsewhere"
    assert v["parent_unknown"]["verdict"] == "collected"
    assert v["name_for_connection"]["helps"][0]["events"] == [22]


def test_collected_here_follows_the_config_file(tmp_path):
    p = tmp_path / "sysmon.xml"
    p.write_text("""<Sysmon schemaversion="4.91"><EventFiltering>
      <RuleGroup name="a" groupRelation="or"><ProcessCreate onmatch="include"/></RuleGroup>
      <RuleGroup name="b" groupRelation="or"><FileCreateStreamHash onmatch="include"/></RuleGroup>
      <RuleGroup name="c" groupRelation="or"><DnsQuery onmatch="include"><QueryName condition="is">x</QueryName></DnsQuery></RuleGroup>
    </EventFiltering></Sysmon>""", encoding="utf-8")
    cfg = prove.config(str(p))
    v = {r["kind"]: r for r in prove.table(cfg)}
    assert v["parent_unknown"]["verdict"] == "not_configured"              # process starts switched off
    assert v["content_from"]["helps"][0]["state"] == "none"
    assert v["name_for_connection"]["helps"][0]["state"] == "some"
    assert v["same_path_unknown_content"]["verdict"] == "collected"        # the recorder's fingerprint still is
    assert prove.config(str(tmp_path / "missing.xml")) is None


def test_the_alerts_own_lines_each_get_their_witness(tmp_path):
    from tests.labs.test_registry import NoRun
    from tests.test_report import s1_like
    from engine.alerts import AlertStore
    from engine.dashboard.app import create_app
    con, a, _ = s1_like(tmp_path)
    con.close()
    s = AlertStore(str(tmp_path / "alerts.db"))
    s.write([a])
    s.close()
    events = next(str(p) for p in tmp_path.iterdir() if p.suffix == ".db" and p.name != "alerts.db")
    c = TestClient(create_app(events, str(tmp_path / "alerts.db"), recordings=str(tmp_path / "rec"), runner=NoRun(),
                              labs_hosts=None))
    whole = c.get("/api/labs/prove").json()
    assert len(whole["table"]) == len(prove.WITNESSES) and whole["config"] and whole["alerts"]
    r = c.get(f"/api/labs/prove/{a.alert_id}").json()
    assert r["story"] is True and r["lines"]
    assert all(l["witness"] is not None and l["text"] for l in r["lines"])
    assert {l["ink"] for l in r["lines"]} <= {"hypothesis", "gap"}
    assert c.get("/api/labs/prove/nope").status_code == 404


def test_the_recorders_internal_codes_reach_the_page_in_plain_words():
    from engine.labs._explain_common import HASH_STATUS, plainer
    s = "what a.ps1 contained: fingerprint failed (hash_status=gone)"
    assert plainer(s) == "what a.ps1 contained: the file was gone before its fingerprint could be taken"
    assert "hash_status" not in plainer("x: fingerprint failed (hash_status=new_code)")
    assert set(HASH_STATUS) >= {"gone", "busy", "unreadable", "too_large", "directory"}       # agent/enrich.py's statuses
    assert plainer("nothing to change") == "nothing to change" and plainer(None) is None


def test_recording_edge_is_apart_from_real_gaps_and_a_before_row_has_no_time_of_its_own():
    """Analyst critique 2026-11-24: on S1 all origin-unknown programs are the 55 s replay cut, and a "Before this"
    row was stamped 20:01:48, after the alert (its stored time is when the recording NOTICED the program)."""
    content = {"hypotheses": [], "gaps": [
        {"kind": "origin_unknown", "plain": "how a.exe was started", "placement": "before", "time_precise": None,
         "noticed_time": "2026-10-30T20:01:48.000000Z"},
        {"kind": "content_unknown", "plain": "what b.ps1 contained", "time_precise": "2026-10-30T20:01:30.000000Z"}]}
    lines = {l["kind"]: l for l in prove.lines_of(content, prove.config())}
    assert lines["origin_unknown"]["edge"] is True and lines["content_unknown"]["edge"] is False
    assert lines["origin_unknown"]["time"] is None and lines["origin_unknown"]["noticed"].startswith("2026-10-30T20:01:48")
    off = prove.lines_of(content, {"ProcessCreate": {"state": "none", "rules": 0}})          # starts not recorded:
    assert not any(l["edge"] for l in off)                                                   # then it IS a blind spot


def test_a_command_line_naming_the_address_corroborates_but_does_not_prove(tmp_path):
    import sqlite3
    from engine.store import EventStore
    from tests.test_detect import ev
    db = str(tmp_path / "e.db")
    s = EventStore(db)
    s.insert([ev(1, 0, host="vm", Image=r"C:\t\fetch.exe", ProcessId=7, CommandLine="fetch.exe -server http://10.0.2.2:18765 -sha256 AB"),
              ev(1, 1, host="vm", Image=r"C:\t\other.exe", ProcessId=8, CommandLine="other.exe")])
    s.close()
    con = sqlite3.connect("file:" + db.replace("\\", "/") + "?mode=ro", uri=True)
    lines = [{"ink": "hypothesis", "text": "the content of x.exe may have come from 10.0.2.2:18765"},
             {"ink": "hypothesis", "text": "the content may have come from 10.0.2.2:9999"},
             {"ink": "gap", "text": "10.0.2.2:18765 in a gap is not a claim"}]
    prove.corroborate(con, "vm", lines)
    assert [c["image"] for c in lines[0]["corroborating"]] == [r"C:\t\fetch.exe"]
    assert lines[1]["corroborating"] == [] and "corroborating" not in lines[2]
    assert "does not prove" in prove.WORDS["corroborating"]


def test_a_command_line_naming_the_written_files_fingerprint_corroborates_without_changing_the_grade(tmp_path):
    """PROOF 2026-11-24: on S1 the fetcher's command line names -sha256 5277F0EF..., and the written payload's
    recorded fingerprint is 5277f0ef... (same, ignoring case): shown as corroboration, the grade stays the engine's."""
    import sqlite3
    from engine.store import EventStore
    from tests.test_detect import T0, ev
    sha = "5277f0ef" + "a1" * 28
    db = str(tmp_path / "e.db")
    s = EventStore(db)
    s.insert([ev(1, 0, host="vm", Image=r"C:\t\fetch.exe", ProcessId=7, CommandLine=f"fetch.exe -sha256 {sha.upper()} -out C:\\t\\pay.exe"),
              ev(1, 1, host="vm", Image=r"C:\t\other.exe", ProcessId=8, CommandLine="other.exe -sha256 " + "b" * 64),
              {"host": "vm", "session": "s", "source": "agent", "seq": 1, "type": "FILE_HASH", "origin": "normal",
               "time": T0.isoformat().replace("+00:00", "Z"),
               "data": {"TargetFilename": r"C:\T\Pay.exe", "hash_status": "ok", "sha256": sha}}])
    s.close()
    con = sqlite3.connect("file:" + db.replace("\\", "/") + "?mode=ro", uri=True)
    lines = [{"ink": "hypothesis", "kind": "content_from", "band": "low", "text": "pay.exe may have come from the server",
              "v": r"file:vm:C:\t\pay.exe"},
             {"ink": "hypothesis", "kind": "content_from", "text": "other may have come from the server", "v": r"file:vm:C:\t\x.exe"},
             {"ink": "hypothesis", "kind": "remote_command", "text": "not a content line", "v": r"file:vm:C:\t\pay.exe"},
             {"ink": "hypothesis", "kind": "content_from", "text": "the graph's own node: path|sha",          # as engine/graph.py
              "v": r"file:vm:c:\t\q.exe|" + sha.upper()}]
    prove.corroborate(con, "vm", lines)
    fp = lines[0]["fingerprint"]
    assert fp["sha256"] == sha.upper() and fp["file"] == r"C:\t\pay.exe"
    assert [p["image"] for p in fp["programs"]] == [r"C:\t\fetch.exe"] and fp["programs"][0]["pid"] == 7
    assert lines[0]["band"] == "low"                                            # the grade is untouched
    assert "fingerprint" not in lines[1] and "fingerprint" not in lines[2]       # no recorded fingerprint / not a content link
    assert lines[3]["fingerprint"]["file"] == r"c:\t\q.exe" and lines[3]["fingerprint"]["programs"][0]["pid"] == 7
    assert "not proven" in prove.WORDS["fingerprint_note"]

