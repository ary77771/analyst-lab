"""Labs, case exports (engine/labs/_case_export.py through engine/labs/cases.py): the printable report, the
Timesketch timeline and the STIX 2.1 bundle, on the made-up story of tests/labs/pivotfix.py."""

import csv
import io
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine.labs import cases as C
from tests.labs.pivotfix import FETCH, HASH, TOOL, FakeContext, story, use
from tests.labs.test_story_svg import world  # noqa: F401  (the real report.build story)


def fake_report(alert):
    """A report with one of each ink (the made-up store has no pool of normal rates for real hypotheses)."""
    return {"summary": "x",
            "facts": [{"id": "f1", "sentence": "fetch.exe (PID 10) created tool.exe", "time": "2026-10-22T10:00:02Z", "in_chain": True},
                      {"id": "f2", "sentence": "explorer.exe started notepad.exe", "time": "2026-10-22T10:00:09Z", "in_chain": False}],
            "hypotheses": [{"id": "h1", "sentence": "the content of tool.exe may have come from 10.0.2.2:18765",
                            "band": "medium", "band_label": "possible link", "reason": "created 0.5 s after the connection",
                            "alternative": "the program had the content already"}],
            "gaps": [{"id": "g1", "what": "origin unknown", "plain": "how fetch.exe was started: its start was not recorded"}]}


@pytest.fixture
def case(tmp_path, monkeypatch):
    events_db, alerts_db, alert, keys = story(tmp_path)
    ctx = FakeContext(events_db, alerts_db, recordings=str(tmp_path / "rec"), report=fake_report)
    use(monkeypatch, ctx)
    app = FastAPI()
    app.include_router(C.router)
    c = TestClient(app)
    cid = c.post("/api/labs/cases", json={"title": "Tool <b>case</b>", "summary": "what started tool.exe?"}).json()["id"]
    base = f"/api/labs/cases/{cid}"
    c.post(f"{base}/pins", json={"type": "entity", "kind": "ip", "ref": "10.0.2.2"})     # pinned BEFORE the event naming it
    c.post(f"{base}/pins", json={"type": "alert", "ref": alert.alert_id})
    c.post(f"{base}/pins", json={"type": "event", "ref": keys[2]})
    c.post(f"{base}/pins", json={"type": "entity", "kind": "hash", "ref": HASH})
    c.post(f"{base}/pins", json={"type": "entity", "kind": "registry", "ref": "HKU\\x\\Run\\it's"})
    h = c.post(f"{base}/pins", json={"type": "hypothesis", "ref": "fetch.exe was started by a script"}).json()
    c.post(f"{base}/notes", json={"text": "check <script>alert(1)</script> the downloads"})
    c.put(f"{base}/marks", json={"key": f"p:{h['id']}", "status": "ruled_out", "note": "no script ran"})
    c.put(f"{base}/marks", json={"key": f"h:{alert.alert_id}:h1", "status": "confirmed"})
    return c, base, cid, alert, keys


def test_the_printable_report(case):
    """PROOF 2026-11-24, the end of the professor's path: page 1 reads like an incident report (the alert in plain
    words; what happened, how sure, what is not known; the analyst's marks), the evidence follows on page 2, A4."""
    c, base, cid, alert, keys = case
    r = c.get(f"{base}/report")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    html = r.text
    page1, rest = html.split("<div class='pb'></div>")
    assert "Incident report" in page1 and f"<h1>{alert.title}</h1>" in page1           # the alert, in plain words
    assert "Case: Tool &lt;b&gt;case&lt;/b&gt;" in page1                                 # case title escaped
    for line in ("What happened", "How sure", "What is not known"):
        assert line in page1, line
    assert "In order: fetch.exe (PID 10) created tool.exe." in page1                    # the alert's own chain
    assert "proven by a record" in page1 and "Proven: a recorded event says so; suspected: possible link." in page1
    assert "The analyst confirmed 1 and ruled out 1." in page1
    assert "how fetch.exe was started: its start was not recorded" in page1             # the gap, plain
    assert "<th>The analyst says</th>" in page1
    assert "the content of tool.exe may have come from 10.0.2.2:18765" in page1 and "confirmed by the analyst" in page1
    assert "fetch.exe was started by a script" in page1 and "ruled out by the analyst" in page1
    assert "<h2>The analyst's summary</h2>" in page1 and "what started tool.exe?" in page1
    assert "never changes it" in page1
    assert "@page { size: A4" in html and ".pb { break-before: page; }" in html
    for heading in ("1. Timeline of the pinned items", "2. Evidence",
                    "3. What is recorded, what is suspected, what cannot be known", "4. Analyst notes",
                    "5. How this report was made"):
        assert heading in rest, heading
    assert "<script>alert(1)" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html     # notes are data
    assert "Proven" in html and "Suspected" in html and "Can" in html                             # the three inks' words
    assert "explorer.exe started notepad.exe" not in html                                         # the chain only
    assert "1 more recorded link" in rest
    assert "Analyst: confirmed by the analyst" in rest and "Analyst: ruled out by the analyst" in rest
    assert "Other explanation: the program had the content already" in rest
    assert keys[3] in rest and keys[5] in rest                    # the alert's evidence, cited by key


def test_a_report_with_nothing_pinned_still_reads(case):
    c, base, cid, alert, keys = case
    empty = c.post("/api/labs/cases", json={"title": "Nothing yet"}).json()["id"]
    html = c.get(f"/api/labs/cases/{empty}/report").text
    page1 = html.split("<div class='pb'></div>")[0]
    assert "<h1>Nothing yet</h1>" in page1 and "Nothing is pinned to this case yet." in page1
    assert "The analyst has not marked any hypothesis yet." in page1


def test_the_timesketch_timeline(case):
    c, base, cid, alert, keys = case
    r = c.get(f"{base}/timesketch.csv")
    assert r.status_code == 200 and cid in r.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert {"message", "datetime", "timestamp_desc"} <= set(rows[0])
    assert all(x["datetime"].endswith("+00:00") and x["message"] and x["timestamp_desc"] for x in rows)
    stamps = [int(x["timestamp"]) for x in rows]
    assert stamps == sorted(stamps)
    descs = {x["timestamp_desc"] for x in rows}
    assert {"Alert raised", "Event recorded", "First seen", "Analyst note written", "Analyst mark set"} <= descs
    assert sum(1 for x in rows if x["event_key"] == keys[2]) == 1          # pinned once, listed once
    j = [json.loads(line) for line in c.get(f"{base}/timesketch.jsonl").text.splitlines()]
    assert [x["message"] for x in j] == [x["message"] for x in rows]


def test_the_stix_bundle(case):
    stix2 = pytest.importorskip("stix2")
    c, base, cid, alert, keys = case
    r = c.get(f"{base}/stix")
    assert r.status_code == 200
    bundle = stix2.parse(r.text, allow_custom=True)                          # a valid STIX 2.1 bundle
    by = {}
    for o in bundle.objects:
        by.setdefault(o.type, []).append(o)
    assert {"identity", "grouping", "indicator", "observed-data", "relationship", "note", "opinion", "file",
            "ipv4-addr", "windows-registry-key", "user-account"} <= set(by)
    patterns = {i.pattern for i in by["indicator"]}
    assert f"[file:hashes.'SHA-256' = '{HASH}']" in patterns and "[ipv4-addr:value = '10.0.2.2']" in patterns
    assert "[windows-registry-key:key = 'HKU\\\\x\\\\Run\\\\it\\'s']" in patterns   # escaped as the pattern grammar wants
    assert {o.opinion for o in by["opinion"]} == {"agree", "disagree"}
    assert by["grouping"][0].name == "Tool <b>case</b>"
    ids = {o.id for o in bundle.objects}
    assert set(by["grouping"][0].object_refs) <= ids
    ip_ind = next(i for i in by["indicator"] if "10.0.2.2" in i.pattern)
    assert any(rel.source_ref == ip_ind.id for rel in by["relationship"])     # linked whatever the pin order
    for rel in by["relationship"]:
        assert rel.relationship_type == "based-on" and rel.source_ref in ids and rel.target_ref in ids


def test_stix_without_the_library_says_so(case, monkeypatch):
    c, base, cid, alert, keys = case
    import builtins
    real = builtins.__import__

    def no_stix(name, *a, **kw):
        if name == "stix2":
            raise ImportError("no stix2")
        return real(name, *a, **kw)
    monkeypatch.setattr(builtins, "__import__", no_stix)
    r = c.get(f"{base}/stix")
    assert r.status_code == 503 and "stix2" in r.json()["detail"]


def test_exports_of_an_unknown_case(case):
    c, base, cid, alert, keys = case
    for tail in ("report", "stix", "timesketch.csv", "timesketch.jsonl"):
        assert c.get(f"/api/labs/cases/c-20990101-000000-abcdef/{tail}").status_code == 404


def test_indicators_only(case):
    """Analyst critique 2026-11-24: an "IOCs only" export the sweep lab accepts (one per line, "#" headings)."""
    c, base, cid, alert, keys = case
    r = c.get(f"{base}/iocs").json()
    found = r["iocs"]
    assert HASH.lower() in found["hash"] and "10.0.2.2" in found["ip"]
    assert any(f.lower().endswith("tool.exe") for f in found["file"])            # from the alert's evidence
    assert not any("run" in k.lower() for k in found["file"])                     # the registry key is left out
    text = c.get(f"{base}/iocs.txt").text
    lines = [x for x in text.splitlines() if x and not x.startswith("#")]
    assert sorted(lines) == sorted(v for vs in found.values() for v in vs) and r["count"] == len(lines)
    from engine.labs import sweep
    if hasattr(sweep, "classify"):                                                 # the sweep lab reads every line
        assert all(sweep.classify(x)[0] for x in lines)


def test_the_report_names_the_run_not_a_placeholder(case):
    c, base, cid, alert, keys = case
    for title, shown, hidden in ((f"S1 \u00b7 Download and run: {alert.title}", "S1 \u00b7 Download and run", "Case: S1"),
                                 ("Untitled case", None, "Case: Untitled")):
        c.patch(base, json={"title": title})
        page1 = c.get(f"{base}/report").text.split("<div class='pb'></div>")[0]
        assert hidden not in page1
        if shown:
            assert shown in page1


def test_in_short_comes_from_the_checklist_above_the_three_lines(case, monkeypatch):
    """PROOF 2026-11-24: the checklist's own "In short" paragraph (engine/labs/_summary.py via checklist.py) on page 1,
    above the three lines, joined as the checklist joins it, without its hover labels or links; none when it fails."""
    c, base, cid, alert, keys = case
    from engine.labs import checklist
    asked = []

    def fake(alert_id):
        asked.append(alert_id)
        return {"summary": [[{"text": "fetch.exe", "status": "fact", "source": "what", "label": "What ran?"},
                             {"text": " started tool.exe <now>.", "status": "fact", "source": "what", "label": "What ran?"}],
                            [{"text": "Of the 5 lines of its story, 4 are proven.", "status": "fact", "source": "sure",
                              "label": "How sure?"}]],
                "words": {"summary": {"title": "In short", "hover": "From: {source}"}}}
    monkeypatch.setattr(checklist, "checklist", fake)
    page1 = c.get(f"{base}/report").text.split("<div class='pb'></div>")[0]
    assert asked == [alert.alert_id]
    i, j = page1.index("<section class='inshort'>"), page1.index("<section class='three'>")
    assert i < j
    assert "fetch.exe started tool.exe &lt;now&gt;. Of the 5 lines of its story, 4 are proven." in page1[i:j]
    assert "What ran?" not in page1 and "From:" not in page1                  # no hover labels in print

    def broken(alert_id):
        raise RuntimeError("no checklist here")
    monkeypatch.setattr(checklist, "checklist", broken)
    assert "<section class='inshort'>" not in c.get(f"{base}/report").text


def test_how_sure_and_in_short_say_the_same_numbers(world, monkeypatch):
    """VISION's final walk 2026-11-25: the report said "4 steps on record" while the checklist said "8 of 10 lines
    proven". Now How sure says the story's own counts in the checklist's own sentence, so the two agree. Real
    report.build on the made-up story; the real checklist (labs.context() pointed at the same story)."""
    from engine import labs
    from engine.labs import _summary
    ctx, alert, keys = world
    monkeypatch.setattr(labs, "context", lambda: ctx)
    app = FastAPI()
    app.include_router(C.router)
    c = TestClient(app)
    base = "/api/labs/cases/" + c.post("/api/labs/cases", json={"title": "x"}).json()["id"]
    c.post(f"{base}/pins", json={"type": "alert", "ref": alert.alert_id})
    page1 = c.get(f"{base}/report").text.split("<div class='pb'></div>")[0]
    short = page1.split("<section class='inshort'>")[1].split("</section>")[0]
    sure = page1.split("<b>How sure</b><p>")[1].split("</p>")[0]
    head = _summary.WORDS["sure"].split("{total}")[0]
    said = short[short.index(head):].split(".")[0]                          # "Of the N lines ..., ... can't be known"
    assert said and said in sure, (said, sure)
