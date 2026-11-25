"""Lab: Alarm track record (engine/labs/receipts.py). Parsers on small fixture texts; the committed v4 results
files (in the repository) for the real numbers; the route with fixture alerts."""

import json
import re

from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine.alerts import Alert, AlertStore
from engine.labs import receipts as R
from nighttools_fixtures import store_with

BANNED = re.compile(r"\b(probably|likely|safe|secure|all clear|all good|no threats?|clean|proven|detected|caught|"
                    r"malicious|attack(?:er)?)\b", re.I)

NORMAL = """# J4
- Active hours: **47.5**

## Raised alerts by rule (the ones an analyst would see)

| source | level | rule | alerts | per active hour | days | programs | where the programs live |
|---|---|---|---:|---:|---:|---:|---|
| beacon | medium | Regular check-in rhythm | 116 | 2.442 | 7 | 12 | Program Files 70, user folders 33 |
| sigma | medium | Whoami.EXE Execution Anomaly | 1,016 | 0.337 | 3 | 1 | Windows 16 |

## Next section
| x | y |
"""
PUBLIC = """- Boots: 1; planned tests: 4; executed: 3 (clean exit: 3)
| technique | test GUID | verdict | without ART-citing rules | exit | timeout | other alerts in window | rules (level) |
|---|---|---|---|---|---|---|---|
| T1007 | 51f17016 | MISSED | MISSED | 0 |  | 1 | - |
| T1012 | 8f7578c4 | DETECTED | MISSED | 1 |  | 1 | 970007b7-ce32-49d0-a4a4-fbef016950bd (medium); b7e2a8d4-74bb-4b78-adc9-3f92af2d4829 (high) |
| T1016 | 8f7578c5 | DETECTED | DETECTED | 0 |  | 0 | 970007b7-ce32-49d0-a4a4-fbef016950bd (medium); analystlab.new_shell_parent (medium) |
| T1018 | 00000000 | NOT EXECUTED | - |  |  |  | - |
"""
BLIND = """## Per run

| scenario | run | records | verdict | expected | found | time to detect (s) | other alerts (rule[level]: n) |
|---|---|---|---|---|---|---|---|
| B16 | 20261114-112402-95c1 | 413 | DETECTED | 4 | 4 | step 3[-] 40.2 | 480421f9-417f-4d3b-9552-fd2728443ec8[medium]: 2, analystlab.x[low]: 1 |
| B15 | 20261114-113011-ee67 | 465 | MISSED | 5 | 2 | - | 480421f9-417f-4d3b-9552-fd2728443ec8[medium]: 3 |
| B10 | 20261114-113835-5a06 | 366 | DETECTED | 3 | 3 | - | - |
"""


def test_parsers_read_the_results_tables():
    n, hours = R.parse_normal(NORMAL)
    assert hours == 47.5 and n["Whoami.EXE Execution Anomaly"]["alerts"] == 1016
    assert n["Regular check-in rhythm"] == {"alerts": 116, "per_hour": 2.442, "days": 7, "programs": 12, "level": "medium"}
    p, executed = R.parse_public([PUBLIC])
    assert executed == 3 and p["970007b7-ce32-49d0-a4a4-fbef016950bd"] == {"tests": 2, "techniques": ["T1012", "T1016"]}
    assert p["analystlab.new_shell_parent"]["tests"] == 1 and "51f17016" not in json.dumps(p)
    b, total = R.parse_blind(BLIND)
    assert total == 3 and b["480421f9-417f-4d3b-9552-fd2728443ec8"] == {"alerts": 5, "runs": 2} and b["analystlab.x"]["runs"] == 1


def test_the_committed_v4_results_give_the_published_numbers():
    d = R.records()
    assert d["hours"] == 47.5 and len(d["normal"]) == 23                  # README section 4 / J4 report
    assert d["normal"]["Regular check-in rhythm"]["alerts"] == 116
    assert d["period"] == "2026-10-23 to 2026-10-29"                       # the week measured is named (critique-2 #10)
    assert d["executed"] == 212 + 150                                    # phase 1 + phase 2 "executed:"
    assert d["blind_runs"] == 24 and d["blind"] == {}                    # v4 raised no "other alerts" in blind runs
    # ...but rounds 4 and 5 name the rule behind three verdicts (analyst critique: "blind_rules 0" looked broken)
    assert sorted(d["blind_verdicts"]) == ["analystlab.create_send_wipe", "analystlab.new_listener"]
    assert all(s["present"] for s in d["sources"])
    # the active hours carry their week, the code that counted them and the file + commit (critique item 5:
    # noise's 82.6 / 75.6 h are other weeks; each page names its own)
    hs = R.hours_source(d)
    assert d["code"] == "the v4 code"
    assert hs["hours"] == 47.5 and hs["period"] == "2026-10-23 to 2026-10-29" and hs["code"] == "the v4 code"
    assert hs["file"] == "docs/results/v4/false-alerts-official-v1runs.md" and hs["commit"]
    said = R.WORDS["hours_source"].format(**hs)
    assert "47.5 h" in said and "2026-10-23 to 2026-10-29" in said and f"at commit {hs['commit']}" in said


def test_the_week_is_named_in_plain_case():
    # critique 3 #8: "laptop TEST week" in capitals read as a shout
    for k in ("hours_label", "hours_source"):
        assert "TEST" not in R.WORDS[k] and "a test of normal use" in R.WORDS[k]


def test_no_hours_source_without_the_file_or_its_number():
    d = {"hours": None, "sources": [{"kind": "normal", "file": "f", "present": True, "commit": "c", "date": "d"}]}
    assert R.hours_source(d) is None
    assert R.hours_source({**d, "hours": 1, "sources": [{**d["sources"][0], "present": False}]}) is None
    assert R.normal_code("by `tools/experiments.py` (v2 code) on TEST data") == "the v2 code" and R.normal_code("") is None


def test_a_rule_with_no_record_is_never_measured_and_one_with_a_record_says_so():
    d = R.records()
    none = R.record_for("00000000-0000-0000-0000-000000000000", "No such rule", d)
    assert none["measured"] is False and none["normal"] is None and none["public"] is None
    beat = R.record_for("beacon", "Regular check-in rhythm", d)
    assert beat["measured"] and beat["normal"]["alerts"] == 116 and beat["normal"]["hours"] == 47.5


def test_route_lists_the_shown_vm_alerts_with_records_and_carries_no_paths(tmp_path):
    from engine import labs
    ev = store_with(str(tmp_path / "events.db"), [{"event_id": 1, "data": {"Image": "C:\\x.exe"}}])
    al = tmp_path / "alerts.db"
    s = AlertStore(str(al))
    s.write([Alert(rule_id="beacon", title="Regular check-in rhythm", source="beacon", level="medium",
                   time="2026-11-01T10:00:00.000Z", host="analystlab-vm", reason="r", evidence=("k1",)),
             Alert(rule_id="beacon", title="Regular check-in rhythm", source="beacon", level="medium",
                   time="2026-11-01T11:00:00.000Z", host="MYLAPTOP", reason="r", evidence=("k2",)),
             Alert(rule_id="zz", title="Never seen rule", source="sigma", level="high",
                   time="2026-11-01T10:05:00.000Z", host="analystlab-vm", reason="r", evidence=("k3",))])
    s.close()
    labs.configure(labs.Context(str(ev), str(al), recordings=str(tmp_path / "rec"), min_level="medium",
                                hosts=("analystlab-vm",)))                     # the dashboard's default
    app = FastAPI()
    app.include_router(R.router)
    body = TestClient(app).get("/api/labs/receipts").json()
    by = {a["title"]: a for a in body["alerts"]}
    assert set(by) == {"Regular check-in rhythm", "Never seen rule"} and len(body["alerts"]) == 2   # laptop alert left out
    assert by["Regular check-in rhythm"]["record"]["normal"]["alerts"] == 116
    assert by["Never seen rule"]["record"]["measured"] is False
    text = json.dumps(body)
    # only rule ids, titles and numbers: no folder categories, no paths, no domains
    assert "Program Files" not in text and "user folders" not in text and "\\\\" not in text
    assert not re.search(r"\b[a-z0-9-]+\.(com|net|org|io)\b", text.replace("lolbas", ""))
    assert body["executed"] == 362 and body["blind_rules"] == 2                  # the two rules rounds 4-5 name


def test_our_words_never_overclaim():
    assert not BANNED.search(json.dumps(R.WORDS)), BANNED.search(json.dumps(R.WORDS))


def test_every_blind_verdict_row_is_still_what_the_committed_round_4_5_file_says():
    """Each BLIND_VERDICTS row quotes the write-up and names the verdict-table cells it relies on: both must still be
    in docs/results/v4/README-with-round5.md, or the row would outlive what the results say."""
    import os
    text = open(os.path.join(R.ROOT, *R.SOURCES["rounds"][0].split("/")), encoding="utf-8").read()
    for v in R.BLIND_VERDICTS:
        assert v["quote"] in text, v["quote"]
        for scenario, cell in v["table"].items():
            row = next((l for l in text.splitlines() if l.startswith(f"| {scenario} |")), None)
            assert row and cell in row.split("|")[4], (scenario, row)       # column 4 = v4 strict
            assert ("innocent" if v["kind"] == "innocent" else "malicious") in row.split("|")[2]


def test_a_rule_with_blind_verdicts_says_them():
    d = R.records()
    r = R.record_for("analystlab.create_send_wipe", "A program created files and deleted them again", d)
    assert r["measured"] and [(x["round"], x["outcome"]) for x in r["blind_verdicts"]] == [(4, "flagged"), (5, "false_alarm")]


def test_the_blind_verdict_table_can_fail():
    import os
    text = open(os.path.join(R.ROOT, *R.SOURCES["rounds"][0].split("/")), encoding="utf-8").read()
    assert "B18 and B20 via **F3 `some_other_rule`**" not in text

