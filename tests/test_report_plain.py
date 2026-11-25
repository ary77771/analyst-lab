"""report-next (docs/vision/debates/10-report.md, "Agreed plan v2"): the report's plain words.

Every test runs on a REAL layer-2 graph (tests/report_fixtures.py: hand-made store, real
engine/graph.py and engine/confidence.py with the frozen config) and asserts on the build() dict;
the rendered HTML is checked only for template-only items (legend, banner position, folded
details). Every number in plain text is recomputed HERE from the stored field it comes from:
K from p, N from n_causes, the window from the config, the time difference from the stored
cause/effect times, the footer from the view's own layer-2 summary.
"""

import dataclasses
import json
import os
import re

import markupsafe
import pytest

from engine import confidence as C
from engine import report
from engine.alerts import declared_note
from engine.graph import parse_time
from report_fixtures import key, rich

WINDOW = C.load_config().window
GLOSS = {"high": "strong link", "medium": "possible link", "low": "weak lead"}
BANNED = ("package j", "burst factor", "sigma-p", "sigma_p", "layer 2", "pool:", "effect rate",
          "hub suppression", "sum of their chances")
DETAILS = re.compile(r"<details\b.*?</details>", re.S)


@pytest.fixture(scope="module")
def rich_report(tmp_path_factory):
    db, alert, G = rich(tmp_path_factory.mktemp("rich"))
    c = report.build(alert, G, "rich.db")
    return db, alert, G, c, report.render(c)


def by_file(c, name):
    (h,) = [h for h in c["hypotheses"] if f" {name} " in f" {h['sentence']} "]
    return h


def outside_details(html):
    return DETAILS.sub("", html)


def plain(h, label):
    found = [l["text"] for l in h["plain"] if l["label"].startswith(label)]
    return found[0] if found else None


def walk(x):
    if isinstance(x, dict):
        for k, v in x.items():
            yield k, v
            yield from walk(v)
    elif isinstance(x, list):
        for v in x:
            yield from walk(v)


# -- the fixture is what the tests below need ------------------------------------------------------
def test_the_rich_fixture_holds_every_case(rich_report):
    _, alert, G, c, _ = rich_report
    hs = c["hypotheses"]
    assert {h["row"] for h in hs} == {"T1", "T2", "T3", "R1"}
    assert {h["lam_source"] for h in hs} >= {"within-life", "pool:program", "pool:lifetime 60-3600 s", "not assessable"}
    assert any((h["n_causes"] or 0) >= 2 for h in hs)
    assert any(h["basis"] == "download marker" for h in hs)
    assert any(h["seconds_apart"] is not None and h["seconds_apart"] < 0 for h in hs)
    assert {h["band"] for h in hs} == {"high", "medium", "low"}
    assert report.check_citations(c, rich_report[0]) == []


# -- M1 ----------------------------------------------------------------------------------------------
def test_m1_no_probably_anywhere_and_every_band_carries_its_gloss(rich_report):
    _, _, _, c, html = rich_report
    assert "probabl" not in json.dumps(c, ensure_ascii=False).lower()
    assert "probabl" not in html.lower()
    assert all("probabl" not in s for s in report.SENTENCES.values())
    for h in c["hypotheses"]:
        assert h["band_label"] == GLOSS[h["band"]]
        assert f'<span class="band {h["band"]}">{h["band"]}</span> <span class="gloss">{GLOSS[h["band"]]}</span>' in html
    assert "Suspected links: may be true, not proven." in html


# -- M2: numbers recomputed from the stored fields ----------------------------------------------------
def test_m2_the_count_is_round_1000p_with_n_causes_and_the_window(rich_report):
    c = rich_report[3]
    timed = [h for h in c["hypotheses"] if h["row"] in report.TIMING_ROWS and h["assessable"]]
    assert len(timed) == 8 and {h["n_causes"] for h in timed} >= {1, 2, 25}
    cfg = C.load_config()
    span = f"{cfg.competing_span_seconds / 60:g} minutes"
    edges = f"({cfg.window_before_seconds:g} s before to {cfg.window_after_seconds:g} s after)"
    assert (span, edges, f"{WINDOW:g}") == ("15 minutes", "(2 s before to 10 s after)", "12")
    for h in timed:
        k = round(1000 * h["p"])
        assert 0 < k and not (9.5 <= 1000 * h["p"] < 10.5 or 99.5 <= 1000 * h["p"] < 100.5)   # no band-edge rounding here
        assert h["chance_text"] == f"{k:,} in 1,000"
        line = next(l["text"] for l in h["plain"] if "by chance" in l["text"])
        assert f"about {k:,} in 1,000 times" in line
        n = h["n_causes"]
        noun = "incoming connection" if h["row"] == "T2" else "connection"
        if n == 1:
            assert line.startswith(f"If this {noun} (the program's only one in the {span} either side) had nothing")
            assert f"in the {WINDOW:g} s window around it {edges}" in line
        else:
            assert line.startswith(f"If this program's {n} {noun}s in the {span} either side of this one had nothing")
            assert f"in the {WINDOW:g} s window {edges} around at least one of them" in line
        # review fix 1: only a T1 figure (x2.5 burst factor) is cautious; a leads-only figure is too low
        if h["lead_only"]:
            assert line.endswith("times (the formula's figure; real use gives more).") and "cautious" not in line
        else:
            assert line.endswith("times (a deliberately cautious estimate).")


def test_m2_the_time_difference_comes_from_the_stored_times_and_agrees_with_the_reason(rich_report):
    c = rich_report[3]
    timed = [h for h in c["hypotheses"] if h["row"] in report.TIMING_ROWS]
    signs = set()
    for h in timed:
        dt = (parse_time(h["effect_time"]) - parse_time(h["cause_time"])).total_seconds()
        assert h["seconds_apart"] == pytest.approx(dt)
        why = plain(h, "Why we think so")
        assert f"{abs(dt):.1f} s {'after' if dt >= 0 else 'before'} it " in why
        frozen = float(re.search(r"([+-]\d+\.\d) s after", h["reason"]).group(1))
        assert frozen == pytest.approx(round(dt, 1))
        signs.add(dt >= 0)
    assert signs == {True, False}                                   # a negative gap is in the fixture
    assert "1.2 s before it connected to 10.0.0.4:443" in plain(by_file(c, "r_out.exe"), "Why")


def test_m2_details_carry_the_frozen_reason_verbatim(rich_report):
    _, _, G, c, html = rich_report
    stored = {d["reason"] for *_, d in G.edges(data=True) if d.get("grade") == "hypothesis"}
    folded = "".join(DETAILS.findall(html))
    for h in c["hypotheses"]:
        assert h["details"][0] == {"label": "Recorded reason (exact)", "text": h["reason"]} and h["reason"] in stored
        assert str(markupsafe.escape(h["reason"])) in folded
        if h["row"] in report.TIMING_ROWS:                          # timing reasons are engineer text: folded only
            assert str(markupsafe.escape(h["reason"])) not in outside_details(html)


def test_m2_measured_from_says_own_or_borrowed(rich_report):
    c = rich_report[3]
    want = {"within-life": "this program's own activity while it ran.",
            "pool:program": "how often programs with the same file name did this on the lab laptop's normal days (borrowed).",
            "pool:lifetime 60-3600 s": "how often programs that run about as long did this on the lab laptop's normal days (borrowed)."}
    seen = set()
    for h in c["hypotheses"]:
        if h["lam_source"] in want:
            assert plain(h, "Measured from") == want[h["lam_source"]]
            seen.add(h["lam_source"])
    assert seen == set(want)


def test_m2_a_link_timing_cannot_assess_prints_no_number(rich_report):
    c, html = rich_report[3], rich_report[4]
    h = by_file(c, "u_out.exe")
    assert h["assessable"] is False and h["p"] == 1.0 and h["chance_text"] is None
    assert not any(re.search(r"in 1,000|%", l["text"]) for l in h["plain"])
    line = plain(h, "How often by coincidence")
    assert f"active {h['life_seconds']:.1f} s, shorter than the {WINDOW:g} s window" in line
    assert plain(h, "Measured from") is None
    sec5 = outside_details(html).split("5. Hypotheses")[1].split("6. What the evidence")[0]
    block = sec5.split(str(markupsafe.escape(h["sentence"])))[1].split('<div class="item')[0]
    assert "in 1,000" not in block
    assert "(timing can't grade it)" not in json.dumps(c["summary_lines"])       # it is not the highest-graded


def test_m2_a_marker_graded_link_says_what_set_the_grade(rich_report):
    h = by_file(rich_report[3], "m.exe")
    assert h["basis"] == "download marker" and h["band"] == "high" and h["timing_band"] == "high"
    grade = plain(h, "What set the grade")
    assert grade.startswith("the program's own download mark (Windows' mark-of-the-web) naming this address and port, "
                            "not the timing")
    assert "own statement, not proof of the source" in grade                # the marker's caveat stays visible
    assert plain(h, "Timing alone (not what set the grade)") is not None
    assert not any(l["label"] == "How often by coincidence" for l in h["plain"])
    # review fix 9: the "+ lookup" basis is spelled out, never shown as the internal label
    looked = report.basis_words("download marker + lookup")
    assert "+" not in looked and "looked up" in looked and "download mark" in looked


def test_m2_leads_only_rows_say_so_without_an_untraceable_number(rich_report):
    c = rich_report[3]
    lead = by_file(c, "child.exe")
    assert lead["row"] in C.load_config().leads_only and lead["lead_only"] is True and lead["band"] == "low"
    assert plain(lead, "Only a lead") == ("measured on the lab laptop, chance coincidences of program starts were more "
                                          "common than even this cautious formula allows, so this link is never graded "
                                          "above 'low'.")
    assert not re.search(r"\d", plain(lead, "Only a lead"))                  # review fix 2: no ratio is quoted
    assert any("formula's figure, too low on real use" in l["label"] for l in lead["plain"])
    assert all(not h["lead_only"] for h in c["hypotheses"] if h["row"] == "T1")


def test_a_provisional_graph_drops_the_cautious_caveat(rich_report):
    _, alert, G, _, _ = rich_report
    H = G.copy()
    for *_, d in H.edges(data=True):
        if d.get("row") in report.TIMING_ROWS:
            d["provisional"] = True                                          # burst factor null: no x2.5
    c = report.build(alert, H)
    for h in c["hypotheses"]:
        for l in h["plain"]:
            assert "cautious" not in l["text"]
    lead = by_file(c, "child.exe")
    assert "more common than the formula allows" in plain(lead, "Only a lead")
    assert plain(lead, "How often by coincidence (the formula's figure").endswith("(the formula's figure; real use gives more).")


def test_m2_t2_is_worded_as_an_incoming_connection_and_a_lead_only(rich_report):
    h = by_file(rich_report[3], "helper.exe")
    assert h["row"] == "T2" and h["kind"] == "remote_command" and h["band"] == "low" and h["lead_only"] is True
    dt = (parse_time(h["effect_time"]) - parse_time(h["cause_time"])).total_seconds()
    assert plain(h, "Why we think so") == f"srv.exe (PID 11) started helper.exe (PID 12) {dt:.1f} s after it accepted a connection from 10.0.0.8."
    line = plain(h, "How often by coincidence (the formula's figure, too low on real use)")
    n = h["n_causes"]
    assert n == 1 and line.startswith("If this incoming connection (the program's only one in the 15 minutes either "
                                      "side) had nothing to do with the programs it starts, a program start")
    assert f"about {round(1000 * h['p'])} in 1,000 times" in line
    assert "(for incoming connections: too few data to say how much)" in plain(h, "Only a lead")
    assert "too few data" not in plain(by_file(rich_report[3], "child.exe"), "Only a lead")


def test_m2_r_rows_keep_their_reason_and_never_claim_truth(rich_report):
    c = rich_report[3]
    (r1,) = [h for h in c["hypotheses"] if h["row"] == "R1"]
    assert r1["plain"] == [{"label": "Why we think so", "text": r1["reason"]},
                           {"label": "Other explanation", "text": r1["alternative"]}]
    texts = [l["text"] for h in c["hypotheses"] for l in h["plain"]] + [l["text"] for l in c["summary_lines"]] + c["limitations"]
    # a truth claim, unless it is the negation the page uses on purpose ("..., not the probability that ...")
    truth = re.compile(r"(?<!not )(?<!not the )(chance|probability|likelihood) (that )?(it|the link|this link|the hypothesis) "
                       r"(is|was) (true|real)", re.I)
    assert not any(truth.search(t) for t in texts)
    assert any("not the probability that the link is true" in t for t in c["limitations"])
    assert not any("this close" in t for t in texts)


@pytest.mark.parametrize("p,text", [(0.034, "34 in 1,000"), (0.9033671657123995, "903 in 1,000"),
                                    (0.0996, "99.6 in 1,000"), (0.00996, "9.96 in 1,000"), (0.0004, "fewer than 1 in 1,000"),
                                    (0.9996, "more than 999 in 1,000"), (0.01, "10 in 1,000"), (0.1, "100 in 1,000")])
def test_per_thousand_examples(p, text):
    assert report.per_thousand(p, C.load_config()) == text


def test_per_thousand_never_contradicts_the_band():
    cfg = C.load_config()
    for i in range(1, 20000):
        p = i / 20000
        text = report.per_thousand(p, cfg)
        if text.startswith(("fewer", "more")):
            continue
        shown = float(text.split()[0].replace(",", ""))
        assert (shown < 1000 * cfg.band_high) == (p < cfg.band_high), (p, text)
        assert (shown < 1000 * cfg.band_medium) == (p < cfg.band_medium), (p, text)


def test_build_is_json_safe_and_never_exports_lam(rich_report):
    c = rich_report[3]
    json.dumps(c, allow_nan=False)
    assert "lam" not in {k for k, _ in walk(c)}


# -- one order: section 5 and the summary --------------------------------------------------------------
def test_hypotheses_order_band_then_p_where_the_formula_graded_then_time_then_sentence(rich_report):
    c, html = rich_report[3], rich_report[4]
    hs = c["hypotheses"]
    # the expected order, written out by hand from the fixture's story (not recomputed with a key):
    # high: r_out (formula, p 0.006) before m.exe (marker: its smaller p never ranks it);
    # medium: a, b (tie: sentence), s_out (larger p), run.exe (R1, no p);
    # low: x_out (T1 by the formula, p 0.108) before the leads child.exe (T3, p 0.009) and helper.exe
    # (T2) whose p is known too low (by time), then u_out (timing can't assess it)
    want = ["r_out.exe", "m.exe", "a.exe", "b.exe", "s_out.exe", "run.exe (PID 22)", "x_out.exe", "child.exe",
            "helper.exe", "u_out.exe"]
    assert [next(w for w in want if f" {w} " in f" {h['sentence']} ") for h in hs] == want
    t1low, t3 = by_file(c, "x_out.exe"), by_file(c, "child.exe")
    assert t1low["band"] == t3["band"] == "low" and t3["p"] < t1low["p"] and t3["lead_only"]   # review fix 3
    marker, formula = by_file(c, "m.exe"), by_file(c, "r_out.exe")
    assert marker["p"] < formula["p"] and hs.index(formula) < hs.index(marker)     # the marker's p never ranks it
    a, b = by_file(c, "a.exe"), by_file(c, "b.exe")
    assert (a["band"], a["p"], a["time"]) == (b["band"], b["p"], b["time"]) and hs.index(a) == hs.index(b) - 1
    # the order never depends on the order the graph hands the edges over (the tie is broken by the sentence)
    assert sorted(list(reversed(hs)), key=report.rank_key) == hs
    pos = [html.index(str(markupsafe.escape(h["sentence"])) + " <span", html.index("5. Hypotheses")) for h in hs]
    assert pos == sorted(pos)


# -- M4 ------------------------------------------------------------------------------------------------
def test_m4_bottom_line_names_the_alerts_own_facts_and_the_highest_graded_link(rich_report):
    _, alert, _, c, html = rich_report
    assert isinstance(c["summary"], str) and "Around it, the recording proves" in c["summary"]
    lines = c["summary_lines"]
    assert [l["label"] for l in lines] == ["Alert", "Proven", "Suspected", "Unknown"]
    assert alert.title in lines[0]["text"] and alert.host in lines[0]["text"] and alert.time in lines[0]["text"]
    proven = lines[1]
    own = [f for f in c["facts"] if any(x["key"] in alert.evidence for x in f["citations"])]
    assert proven["facts"] == sorted(own, key=lambda f: (f["time"], f["sentence"]))[:3]
    for f in proven["facts"]:
        assert f in c["facts"] and f["sentence"] in proven["text"]
    assert f"({len(proven['facts'])} of {len(c['facts'])} facts" in proven["text"]
    assert "explorer.exe (PID 100) started q.exe (PID 77)" in [f["sentence"] for f in c["facts"]]
    assert "q.exe" not in proven["text"]                            # an unrelated earlier fact is not named
    sus = lines[2]
    top = c["hypotheses"][0]
    assert sus["hypothesis"] is top and f"“{top['sentence']}”" in sus["text"]
    assert f"about {round(1000 * top['p'])} in 1,000 by coincidence" in sus["text"] and top["band_label"] in sus["text"]
    for band, gloss in GLOSS.items():
        n = sum(1 for h in c["hypotheses"] if h["band"] == band)
        assert f"{n} {gloss}{'' if n == 1 else 's'}" in sus["text"]
    unk = lines[3]
    assert unk["gap"] is c["gaps"][0] and f"{len(c['gaps'])} thing" in unk["text"] and c["gaps"][0]["where"] in unk["text"]
    for l in lines:
        assert str(markupsafe.escape(l["text"])) in html


def test_m4_proven_dedups_caps_and_says_when_nothing_matches(rich_report):
    _, alert, G, c, _ = rich_report
    db = rich_report[0]
    many = dataclasses.replace(alert, evidence=tuple(key(db, r) for r in (10, 11, 20, 21, 12, 31)))
    p = report.build(many, G)["summary_lines"][1]
    assert len(p["facts"]) == 3 and f"(3 of {len(c['facts'])} facts" in p["text"]
    none = dataclasses.replace(alert, evidence=(key(db, 13),))     # child.exe's end: no fact cites it
    assert report.build(none, G)["summary_lines"][1]["text"] == "no fact cites the alert's own events; see section 4."
    f = {"sentence": "x started y", "time": "t1", "citations": [{"key": "k1"}]}
    twice = report._summary_lines(dataclasses.replace(alert, evidence=("k1", "k2")),
                                  [f, {**f, "citations": [{"key": "k2"}]}], [], [])[1]
    assert twice["facts"] == [f] and twice["text"].count("x started y") == 1


def test_m4_a_marker_graded_top_link_does_not_quote_its_p(rich_report):
    _, alert, G, c, _ = rich_report
    hs = [h for h in c["hypotheses"] if h["basis"] != "formula" or h["band"] != "high"]
    line = report._summary_lines(alert, c["facts"], hs, c["gaps"])[2]
    assert line["hypothesis"]["basis"] == "download marker"
    assert "grade set by the program's own download mark, not the timing" in line["text"] and "in 1,000" not in line["text"]


def test_m4_a_lead_never_becomes_highest_graded_over_a_formula_low(rich_report):
    # review fix 3: among low links, the T3 lead's smaller p is known too low, so the T1 low ranks first
    _, alert, _, c, _ = rich_report
    t1low, t3 = by_file(c, "x_out.exe"), by_file(c, "child.exe")
    assert t3["p"] < t1low["p"]
    for hs in ([t3, t1low], [t1low, t3]):
        ranked = sorted(hs, key=report.rank_key)
        assert ranked == [t1low, t3]
        line = report._summary_lines(alert, c["facts"], ranked, c["gaps"])[2]
        assert line["hypothesis"] is t1low and "x_out.exe" in line["text"]


# -- S4 ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("declared", [None, {"event_id": 4104, "ScriptBlockText": "x"}])
def test_s4_a_declared_alert_gets_the_banner_first(rich_report, declared):
    _, alert, G, _, _ = rich_report
    details = {"derived_from": "command_line", **({"declared": declared} if declared else {})}
    a = dataclasses.replace(alert, details=details)
    c = report.build(a, G)
    html = report.render(c)
    b = c["declared_banner"]
    assert b["note"] == declared_note(a).strip()[1:-1] == "declared on a command line, not recorded"
    assert b["text"] == report.DECLARED_SENTENCES["script" if declared else "registry"] and b["text"] in c["summary"]
    assert html.index('id="declared-banner"') < html.index("1. Summary")
    assert str(markupsafe.escape(b["note"])) in html and str(markupsafe.escape(b["text"])) in html
    assert declared_note(a).strip() in c["summary_lines"][0]["text"]


def test_s4_a_plain_alert_has_no_banner(rich_report):
    c, html = rich_report[3], rich_report[4]
    assert c["declared_banner"] is None and 'id="declared-banner"' not in html and "declared" not in c["summary_lines"][0]["text"]


# -- S1 ------------------------------------------------------------------------------------------------
def test_s1_no_internal_words_outside_the_folded_details(rich_report, tmp_path):
    _, alert, G, c, html = rich_report
    from engine.graph import norm_path
    hubbed = report.build(alert, G, hubs=frozenset({norm_path(r"C:\Windows\explorer.exe")}))
    for content in (c, hubbed):
        page = outside_details(report.render(content)).lower()
        for word in BANNED:
            assert word not in page, word
        visible = json.dumps([content["summary"], [l["text"] for l in content["summary_lines"]], content["limitations"],
                              content["next_steps"],
                              [h["plain"] for h in content["hypotheses"]], [h["sentence"] for h in content["hypotheses"]]],
                             ensure_ascii=False).lower()
        for word in BANNED:
            assert word not in visible, word
    assert "pool:" in "".join(DETAILS.findall(html)).lower()          # the engineer text is still on the page, folded
    assert any("busy common program" in l for l in hubbed["limitations"])


def test_s1_footer_counts_only_timing_links_timing_can_grade(rich_report):
    _, _, G, c, html = rich_report
    seen, total, untimed = set(), 0.0, set()
    for h in c["hypotheses"]:
        if h["row"] in report.TIMING_ROWS and h["p"] is not None:
            effect = (h["row"], h["citations"][-1]["key"])             # the effect is the last citation
            if h["assessable"]:
                if effect not in seen:
                    seen.add(effect)
                    total += h["p"]
            else:
                untimed.add(effect)
    g = c["graph"]
    assert g["timing_graded"] == len(seen) == 8 and g["timing_not_assessable"] == len(untimed) == 1
    assert g["sigma_p_assessable"] == pytest.approx(total)
    assert g["sigma_p"] == pytest.approx(total + 1.0)                 # the not-assessable link's p = 1 is left out
    footer = html.split('id="footer"')[1]
    assert (f"Of the {len(seen)} timing link(s) graded on this page (counting each new file or program once), about "
            f"{total:.2f} would be expected even if nothing here were linked") in footer
    assert f"{g['sigma_p']:.2f}" not in footer and "1 more timing link(s) could not be graded" in footer
    # review fix 5: the sum holds leads-only p values (known too low), and says so; without them it doesn't
    assert any(h["lead_only"] and h["assessable"] for h in c["hypotheses"]) and g["timing_includes_leads"] is True
    assert "linked (fewer than real use gives, for program starts)." in footer
    no_leads = G.copy()
    no_leads.remove_edges_from([(u, v, k) for u, v, k, d in G.edges(keys=True, data=True) if d.get("row") in ("T2", "T3")])
    c2 = report.build(rich_report[1], no_leads)
    assert c2["graph"]["timing_includes_leads"] is False
    assert "fewer than real use gives" not in report.render(c2).split('id="footer"')[1]


def test_s1_a_provisional_grade_is_said_in_plain_words(rich_report):
    _, alert, G, _, _ = rich_report
    H = G.copy()
    for *_, d in H.edges(data=True):
        if d.get("row") == "T1":
            d.update(provisional=True, provisional_reason="the burst factor is still open (package J)")
    c = report.build(alert, H)
    html = report.render(c)
    assert any("provisional" in l for l in c["limitations"])
    page = outside_details(html).lower()
    assert "burst factor" not in page and "package j" not in page
    assert "burst factor" in "".join(DETAILS.findall(html)).lower()


# -- M3 ------------------------------------------------------------------------------------------------
def test_m3_citations_are_named(rich_report):
    c, html = rich_report[3], rich_report[4]
    names = {**{k: f"{v} (Sysmon {k})" for k, v in report.EVENT_NAMES.items()},
             **{k: f"{v} (recorder)" for k, v in report.AGENT_EVENT_NAMES.items()}}
    cites = [x for sec in ("facts", "hypotheses", "gaps") for item in c[sec] for x in item["citations"]]
    assert {x["event"] for x in cites} >= {1, 3, 11, 15}
    for x in cites:
        assert x["text"] == f"{names[x['event']]}, record {x['record']}"
    assert report.event_name(9999) == "event 9999" and report.event_name(None) == "event ?"
    assert report.event_name("FILE_HASH") == "file fingerprint (recorder)"
    assert "network connection (Sysmon 3), record 10" in html
    assert report.check_citations(c, rich_report[0]) == []


# -- S2 ------------------------------------------------------------------------------------------------
def test_s2_the_legend_uses_the_sections_own_classes(rich_report):
    html = rich_report[4]
    legend = html.split('id="legend"')[1].split("1. Summary")[0]
    for cls, word in (("item fact", "Proven"), ("item hyp", "Suspected"), ("item gap", "Unknown")):
        assert f'<div class="{cls}"><strong>{word}</strong>' in legend
        assert f'class="{cls}"' in html.split("1. Summary")[1]          # the sections use the same class
    assert "PID" in legend


# -- S3 ------------------------------------------------------------------------------------------------
def test_s3_next_steps_name_each_strong_or_possible_links_other_explanation(rich_report):
    c = rich_report[3]
    named = [h for h in c["hypotheses"] if h["band"] in ("high", "medium")][:3]
    assert len(named) == 3
    for h in named:
        assert f"Rule out the other explanation for “{h['sentence']}”: {h['alternative']}." in c["next_steps"]
    assert sum(s.startswith("Rule out the other explanation") for s in c["next_steps"]) == 3

