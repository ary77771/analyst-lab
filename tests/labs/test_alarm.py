"""Lab "This is what an alarm says" (engine/labs/alarm.py): raw records next to the plain sentences, every traced
word pointing at the field it came from. Fixtures only."""

from fastapi.testclient import TestClient

from engine.labs import alarm

START = {"event_id": 1, "Image": r"C:\Windows\System32\conhost.exe", "ProcessId": 5744,
         "ParentImage": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "ParentProcessId": 2180,
         "host": "analystlab-vm", "channel": "Microsoft-Windows-Sysmon/Operational", "record_id": 12, "raw_xml": None,
         "dedup_key": "k1", "id": 7}
NET = {"event_id": 3, "Image": r"C:\x\powershell.exe", "ProcessId": 2180, "DestinationIp": "10.0.2.2", "DestinationPort": 8770}


def spans(sentence, recs):
    return [(sentence[t["start"]:t["end"]], t["field"]) for t in alarm.trace(sentence, recs)]


def test_every_traced_word_points_at_its_field():
    s = "powershell.exe (PID 2180) started conhost.exe (PID 5744)"
    assert spans(s, [("k1", START)]) == [("powershell.exe", "ParentImage"), ("2180", "ParentProcessId"),
                                          ("started", "EventID"), ("conhost.exe", "Image"), ("5744", "ProcessId")]


def test_a_number_is_never_traced_inside_another_number_and_untraced_words_stay_ours():
    s = "powershell.exe (PID 21800) connected to 10.0.2.2:8770"
    got = spans(s, [("k2", NET)])
    assert ("10.0.2.2", "DestinationIp") in got and ("8770", "DestinationPort") in got
    assert ("connected to", "EventID") in got
    assert not any(field == "ProcessId" for _, field in got)          # 2180 is not 21800
    assert alarm.trace("nothing from the record here", [("k2", NET)]) == []


def test_the_raw_record_keeps_every_field_and_says_which_record():
    v = alarm.record_view("k1", START)
    assert v["name"] == "process start" and v["event_id"] == 1
    assert dict(v["header"])["record_id"] == 12 and "Image" in dict(v["fields"])
    assert not {"raw_xml", "dedup_key", "id"} & ({k for k, _ in v["fields"]} | {k for k, _ in v["header"]})
    assert alarm.record_view("k9", None)["missing"] is True


def test_through_the_dashboard(tmp_path):
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
    r = c.get(f"/api/labs/alarm/{a.alert_id}").json()
    assert r["alarm"]["reason"] == a.reason and r["alarm"]["title"] == a.title
    assert r["story"] is True and r["lines"] and r["records"]
    assert r["lines"][0]["own"]                                         # the alert's own records come first
    keys = {x["key"] for x in r["records"]}
    assert all(k in keys for l in r["lines"] for k in l["keys"])          # every cited record is shown
    traced = [t for l in r["lines"] for t in l["traces"]]
    assert traced and all(t["key"] in keys for t in traced)
    for l in r["lines"]:                                                  # a trace is the literal text of its field
        for t in l["traces"]:
            word = l["text"][t["start"]:t["end"]].lower()
            assert t["field"] == "EventID" or word in t["value"].lower()
    assert c.get("/api/labs/alarm").json()["alerts"] and c.get("/api/labs/alarm/nope").status_code == 404
