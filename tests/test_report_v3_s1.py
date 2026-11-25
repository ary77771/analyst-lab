"""Report v3 on the REAL practice S1 sample (VM data only): the same invariants as the fixtures, plus
the round-2b findings this sample showed (debate 11). Skipped unless these point at the inputs
(recordings/ is never in the repo):
    ANALYSTLAB_S1_SAMPLE = the practice run's replay store (events.db), see docs/results/report-next/NOTES.md
    ANALYSTLAB_POOL      = the pool of normal rates (pool.json; Layer2 checks its hash)
    ANALYSTLAB_HUBS      = the frozen hub list (its hash is checked against config/frozen.yaml)
Only aggregate checks: nothing from the store is printed.
"""

import hashlib
import os
import re
import sqlite3

import pytest

from engine import config, own_rules, report
from engine import hubs as hubs_mod
from engine.graph import Layer2, build_graph, parse_time
from test_report_v3 import invariants

S1, POOL, HUBS = (os.environ.get(k) for k in ("ANALYSTLAB_S1_SAMPLE", "ANALYSTLAB_POOL", "ANALYSTLAB_HUBS"))
pytestmark = pytest.mark.skipif(not (S1 and POOL and HUBS and all(os.path.exists(p) for p in (S1, POOL, HUBS))),
                                reason="the practice S1 sample is not available here")


@pytest.fixture(scope="module")
def s1():
    rule = config.hub_rule()
    assert hashlib.sha256(open(HUBS, "rb").read()).hexdigest() == str(rule["sha256"]).lower(), "hub list hash"
    con = sqlite3.connect("file:" + os.path.abspath(S1).replace("\\", "/") + "?mode=ro", uri=True)
    (alert,) = own_rules.fetch_write_run(con)
    G = build_graph(con, host=alert.host, hypotheses=Layer2.from_pool_file(POOL))
    hubs = hubs_mod.load(HUBS)
    c = report.build(alert, G, "events.db", hubs=hubs)
    yield con, alert, G, hubs, c
    con.close()


def test_s1_sample_invariants(s1):
    con, alert, G, hubs, c = s1
    invariants(c, alert, report.alert_view(alert, G, hubs)[2])
    assert report.check_citations(c, con) == []


def test_s1_sample_round_2b_findings_are_fixed(s1):
    con, alert, G, hubs, c = s1
    # finding 2: the start of the program that acts is listed above its actions (order, not record ids)
    started = {f["v"]: f for f in c["facts"] if f["kind"] == "started"}
    acting = [f for f in c["facts"] if f["kind"] != "started" and f["u"] in started]
    assert acting and all(started[f["u"]]["order"] < f["order"] for f in acting)
    # times are no longer cut to the second where it matters: two rows of one second keep their order
    precise = [parse_time(t["time_precise"]) for t in c["timeline"] if t["placement"] == "at"]
    assert len({t.replace(microsecond=0) for t in precise}) < len(precise)
    # finding 3: the gap about how a program started is a "Before this" row at the top
    assert c["counts"]["before"] >= 1 and c["timeline"][0]["placement"] == "before"
    # finding 4: no "0.0 s"; the short coincidence line's figure is per_thousand's
    cfg = report.confidence.load_config()
    for h in c["hypotheses"]:
        assert not any("0.0 s" in l["text"] for l in h["plain"])
        if h["chance_short"]:
            assert report.per_thousand(h["p"], cfg) in h["chance_short"]
            assert ("leans toward calling it coincidence" in h["chance_short"]) == (
                h["row"] == "T1" and not h["lead_only"] and h["p1"] >= cfg.band_high)
    assert not any(re.search(r"\b0\.0 s\b", t["offset_text"] or "") for t in c["timeline"])
    # the verdict: numbered fact-only steps; "Not proven" is a suspected link touching the alert's events
    v = c["verdict"]
    assert v["steps"] and v["not_proven"] and v["not_proven"]["id"] in {h["id"] for h in c["hypotheses"]}
