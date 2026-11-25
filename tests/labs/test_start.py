"""Lab "I have an alert" (engine/labs/start.py): each of the six steps says what the owning lab says (a test
compares them through the real dashboard), a failing lab gives "Not checked", repeated alerts are shown once."""

import pytest
from fastapi.testclient import TestClient

from engine.alerts import Alert
from engine.labs import start


@pytest.fixture
def client(tmp_path, monkeypatch):
    """The report tests' small S1-like story, recorded on the lab VM's name (so every lab answers by default)."""
    import functools
    from tests import test_report
    from tests.labs.test_registry import NoRun
    from engine.dashboard.demo_mode import VM_HOSTS
    monkeypatch.setattr(test_report, "ev", functools.partial(test_report.ev, host=sorted(VM_HOSTS)[0]))
    s1_like = test_report.s1_like
    from engine.alerts import AlertStore
    from engine.dashboard.app import create_app
    con, a, _ = s1_like(tmp_path)
    con.close()
    s = AlertStore(str(tmp_path / "alerts.db"))
    s.write([a])
    s.close()
    events = next(str(p) for p in tmp_path.iterdir() if p.suffix == ".db" and p.name != "alerts.db")
    return TestClient(create_app(events, str(tmp_path / "alerts.db"), recordings=str(tmp_path / "rec"), runner=NoRun())), a


def test_each_step_matches_its_own_lab(client):
    c, a = client
    r = c.get(f"/api/labs/start/{a.alert_id}").json()
    st = {s["key"]: s for s in r["steps"]}
    assert list(st) == ["fired", "around", "sure", "spread", "unseen", "todo"]
    assert all(s["status"] in ("fact", "hypothesis", "gap", "none", "unchecked", "mixed", "unproven", "raised", "listed") and s["line"] for s in r["steps"])
    from engine.labs import _attack
    unchecked = [(s["key"], s.get("reason")) for s in r["steps"] if s["status"] == "unchecked"]
    if _attack.load() is None:                                               # no downloaded ATT&CK here: said so
        assert unchecked == [("todo", st["todo"]["reason"])] and "ATT&CK data" in st["todo"]["reason"]
        return
    assert not unchecked, unchecked                                          # every lab is present on night
    why = c.get(f"/api/labs/why/{a.alert_id}").json()
    assert st["fired"]["numbers"]["events"] == why["events_total"] and st["fired"]["lab"] == "why"
    mom = c.get(f"/api/labs/moment?alert={a.alert_id}&seconds=30").json()
    assert st["around"]["numbers"]["events"] == sum(1 for e in mom["events"] if not e["own_tool"])
    rep = c.get(f"/api/alerts/{a.alert_id}").json()["report"]["counts"]
    assert st["sure"]["numbers"] == {"facts": rep["facts"], "hyps": rep["hypotheses"], "gaps": rep["gaps"]}
    pv = c.get(f"/api/labs/prove/{a.alert_id}").json()
    assert st["unseen"]["numbers"]["lines"] == sum(1 for l in pv["lines"] if not l.get("edge"))
    assert st["unseen"]["numbers"]["edges"] == sum(1 for l in pv["lines"] if l.get("edge"))     # the recording's edge, apart
    rs = c.get(f"/api/labs/respond/{a.alert_id}").json()
    assert st["todo"]["numbers"]["techniques"] == len(rs["techniques"])
    cl = {q["key"]: q for q in c.get(f"/api/labs/checklist/{a.alert_id}").json()["questions"]}
    assert st["spread"]["numbers"]["inks"] == [cl["network"]["status"], cl["persist"]["status"]]


def test_a_failing_lab_reads_not_checked(client, monkeypatch):
    c, a = client
    from engine.labs import _triage
    monkeypatch.setattr(_triage, "step_fired", lambda ctx, a: 1 / 0)
    st = {s["key"]: s for s in c.get(f"/api/labs/start/{a.alert_id}").json()["steps"]}
    assert st["fired"]["status"] == "unchecked" and st["fired"]["status_word"] == "Not checked"
    assert st["around"]["status"] != "unchecked"                              # the others go on


def test_repeated_alerts_are_shown_once_newest_first():
    mk = lambda n, t, title="A shell": Alert("r1", title, "sigma", "medium", t, "vm", "x", (f"k{n}",))
    g = start.groups([mk(1, "2026-10-31T10:00:00Z"), mk(2, "2026-10-31T11:00:00Z"), mk(3, "2026-10-31T09:00:00Z", "Other")])
    assert [x["title"] for x in g] == ["A shell", "Other"]
    assert g[0]["count"] == 2 and g[0]["first"] == "2026-10-31T10:00:00Z" and g[0]["id"] == mk(2, "2026-10-31T11:00:00Z").alert_id


def test_no_overclaiming_words():
    import json
    from tests.test_dashboard_words_scan import scan
    assert not scan(json.dumps(start.WORDS, ensure_ascii=False))


def test_an_alert_not_in_this_recording_is_said_plainly(client):
    c, _ = client
    for lab in ("start", "why", "respond", "prove", "alarm", "checklist"):
        r = c.get(f"/api/labs/{lab}/not-an-alert")
        assert r.status_code == 404 and r.json()["detail"] == "This alert isn't in this recording.", lab


def test_a_status_word_is_never_stronger_than_its_evidence(client):
    """Analyst critique 2026-11-24: "fired" was Proven while its own check was na, and "spread" was Proven while
    autostarts read "Nothing recorded"."""
    from engine.labs._triage import honest
    assert honest(["fact", "fact"]) == "fact" and honest(["fact", "none"]) == "mixed" and honest(["none", "none"]) == "none"
    assert honest(["fact", "gap"]) == "mixed" and honest(["hypothesis", "gap"]) == "gap" and honest([]) == "none"
    c, a = client
    st = {s["key"]: s for s in c.get(f"/api/labs/start/{a.alert_id}").json()["steps"]}
    assert st["fired"]["numbers"]["check"] != "reproduced" and st["fired"]["status"] == "raised"   # an own rule: not re-checked
    inks = st["spread"]["numbers"]["inks"]
    assert st["spread"]["status"] == ("fact" if all(i == "fact" for i in inks) else st["spread"]["status"])
    assert st["spread"]["status"] != "fact" or all(i == "fact" for i in inks)
    assert st["todo"]["status"] in ("listed", "none", "unchecked")                                # never "Proven"
