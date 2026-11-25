"""The film rule on the SHAPES of real stories (tests/fixtures/stories/, from the sweep of 2026-11-21).

Each fixture keeps a real lab story's rows, inks, order, rails, links and counts; every id, name, path,
address, title and sentence in it is made up. The biggest story found (1,120 rows on 42 rails) and the
oddest ones are here so the Story screen stays tested on them."""

import copy
import glob
import json
import os
import re

import pytest

from engine.dashboard import film as F

HERE = os.path.dirname(os.path.abspath(__file__))
PATHS = sorted(glob.glob(os.path.join(HERE, "fixtures", "stories", "*.json")))
NAMES = [os.path.basename(p)[:-5] for p in PATHS]


def load(name):
    with open(os.path.join(HERE, "fixtures", "stories", name + ".json"), encoding="utf-8") as f:
        return json.load(f)


def test_the_fixtures_are_there_and_hold_nothing_real():
    assert len(NAMES) >= 10 and "biggest-1120-rows" in NAMES
    for name in NAMES:
        s = load(name)
        assert s["about"].startswith("The SHAPE of a real story") and s["alert"]["host"] == "test-vm"
        text = json.dumps({k: v for k, v in s["report"].items() if k != "declared_banner"}).lower()
        for real in ("c:\\\\", "\\\\users", "analystlab", "powershell", "vbox", "sysmon", "10.0.2.2", "hklm", "hkey", "microsoft"):
            assert real not in text, (name, real)


MADE_UP_NAME = re.compile(r"prog\d+\.exe( \(PID \d+\))?|file\d+x*(\.[a-z0-9]{1,6})?|10\.0\.0\.\d+:\d+|item\d+x*")
REAL = {   # nothing of these may ever be in a fixture (privacy rule 7 holds for test-machine data too)
    "a Windows path or a user's folder": re.compile(r"[A-Za-z]:\\\\|\\\\Users\\\\|/Users/|AppData|%USERPROFILE%|Documents and Settings", re.I),
    "an address that is not one of the made-up ones (10.0.0.x)": re.compile(r"(?<![\d.])(?!10\.0\.0\.\d)(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
    "a domain name": re.compile(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|edu|gov|mil|io|co|uk|de|info|biz|dev|app|cloud|local|lan|internal|home|corp)\b", re.I),
    "one of our run ids": re.compile(r"\b20\d{6}-\d{6}-[0-9a-f]{4}\b"),
    "an alert, edge or record id from a real store": re.compile(r"\b[0-9a-f]{13,}\b"),
    "a Windows record key": re.compile(r"Microsoft-Windows|Sysmon|\{[0-9A-Fa-f-]{30,}\}|\|\d+\|20\d\d-", re.I),
    "the test machine's name": re.compile(r"analystlab", re.I),
}


def not_made_up(story, raw):
    """Everything in one fixture that is not provably made up, as plain sentences (an empty list: clean).
    Two nets. A search of the whole file for things that are real by their form (REAL). And a positive list:
    each name must BE one of the made-up forms, each id one of the made-up ids, each sentence made of those
    names and plain words, so a real file name or user folder cannot be in a fixture even where no pattern
    would know it."""
    out, rep = [], story["report"]
    text = raw.replace(json.dumps(rep["declared_banner"]), "") if rep.get("declared_banner") else raw      # (the engine's own sentence, not a recording's)
    for what, pattern in REAL.items():
        found = pattern.search(text)
        if found:
            out.append(f"{what}: {found.group(0)[:40]!r}")
    if not (story["alert"]["host"] == rep["verdict"]["host"] == "test-vm" and story["alert"]["rule"] == "made-up"
            and story["alert"]["title"] == rep["verdict"]["title"] == "A made-up alert title of the same kind"
            and rep["verdict"]["time"].startswith("2026-01-01T00:00:00")):
        out.append("the alert's host, rule, title or time is not the made-up one")
    for n in rep["layout"]["nodes"]:
        if not (MADE_UP_NAME.fullmatch(n["short"]) and n["label"] == n["short"] and re.fullmatch(r"n\d+", n["id"])):
            out.append(f"a thing's name or id: {n['short'][:40]!r}")
    for lane in rep["layout"]["lanes"]:
        if not (lane["short"] == "" or MADE_UP_NAME.fullmatch(lane["short"])):
            out.append(f"a rail's name: {lane['short'][:40]!r}")
    for e in rep["layout"]["edges"]:
        if not (re.fullmatch(r"e\d+", e["id"]) and re.fullmatch(r"n\d+", e["u"]) and re.fullmatch(r"n\d+", e["v"]) and e["short"] == ""):
            out.append(f"a link's id or text: {e['id'][:20]!r}")
    names = sorted({n["short"] for n in rep["layout"]["nodes"]}, key=len, reverse=True)
    for row in rep["timeline"]:
        left = row["short"]
        for nm in names:                                                # a row's sentence: made-up names and the kind's plain words, nothing else
            left = left.replace(nm, "")
        if not (re.fullmatch(r"[eg]\d+", row["id"]) and row["text"] == "" and re.fullmatch(r"[A-Za-z :'()\-]*", left)):
            out.append(f"a row's id or sentence: {row['short'][:60]!r}")
    for kind in ("facts", "hypotheses", "gaps"):
        for x in rep[kind]:
            if not (x["time"] == "" and all(re.fullmatch(r"k\d+", c["key"]) and c["time"] == "" and c["text"] == "rec" for c in x["citations"])):
                out.append(f"a record key, time or text in {kind}")
    if not all(re.fullmatch(r"k\d+", c["key"]) for c in rep["alert"]["citations"]):
        out.append("one of the alert's own record keys")
    return out


def raw_of(name):
    with open(os.path.join(HERE, "fixtures", "stories", name + ".json"), encoding="utf-8") as f:
        return f.read()


@pytest.mark.parametrize("name", NAMES)
def test_every_name_id_address_and_time_in_a_fixture_is_a_made_up_one(name):
    assert not_made_up(load(name), raw_of(name)) == []


def test_the_scan_notices_each_kind_of_real_thing():
    """The scan must be able to fail. One real thing of each kind is put into a copy of a fixture (never
    into the file): the test machine's name, a user's folder, an address that is not a made-up one, a
    domain, one of our run ids, a real-looking record id, and a plain real program name no pattern knows."""
    name = "two-alerts-same-second"
    clean, raw = load(name), raw_of(name)
    assert not_made_up(clean, raw) == []
    first = clean["report"]["layout"]["nodes"][0]["short"]
    put_in = {
        "the test machine's name": "analystlab-vm",
        "a Windows path or a user's folder": "C:\\\\Users\\\\someone\\\\Downloads\\\\x.exe",
        "an address that is not one of the made-up ones (10.0.0.x)": "192.168.1.20:443",
        "the lab's real address": "10.0.2.2:18765",
        "a domain name": "updates.some-vendor.com",
        "one of our run ids": "20261121-105311-0f84",
        "an alert, edge or record id from a real store": "c4ebb08feb256a92",
        "a real program name": "notepad.exe",
    }
    for what, real in put_in.items():
        tampered = raw.replace(json.dumps(first)[1:-1], real)
        found = not_made_up(json.loads(tampered), tampered)
        assert found, f"{what} ({real}) was not noticed"
    # each of these is caught by its form alone, wherever it stands (here: in a field the positive list does not read)
    for what in ("the test machine's name", "a Windows path or a user's folder", "an address that is not one of the made-up ones (10.0.0.x)",
                 "a domain name", "one of our run ids", "an alert, edge or record id from a real store"):
        tampered = raw.replace('"about":"', '"about":"' + put_in[what] + " ", 1)
        assert any(p.startswith(what) for p in not_made_up(json.loads(tampered), tampered)), what
    lab = raw.replace('"about":"', '"about":"10.0.2.2 ', 1)
    assert any("address" in p for p in not_made_up(json.loads(lab), lab))
    assert not REAL["an address that is not one of the made-up ones (10.0.0.x)"].search("10.0.0.7:8007") and not REAL["a domain name"].search("prog01.exe file003xx.ps1 item002")


@pytest.mark.parametrize("name", NAMES)
def test_the_stored_film_is_what_the_rule_gives_today(name):
    s = load(name)
    assert s["film"] == F.film_of(s["report"]), "the film rule changed: run python tests/fixtures/refresh_story_films.py and look at the difference"


@pytest.mark.parametrize("name", NAMES)
def test_the_film_only_ever_takes_rows_of_the_story_in_its_order_and_keeps_every_step(name):
    rep = load(name)["report"]
    f = F.film_of(rep)
    order = [r["id"] for r in rep["timeline"]]
    assert f["total"] == len(order) and f["rows"] == len(f["ids"]) and len(set(f["ids"])) == len(f["ids"])
    assert f["ids"] == [i for i in order if i in set(f["ids"])]                    # a subset, never reordered, nothing invented
    steps = [e["id"] for e in rep["layout"]["edges"] if e["in_chain"]]
    assert set(steps) <= set(f["ids"])                                             # every numbered step is filmed
    assert sum(f["story_counts"].values()) == len(order) and sum(f["counts"].values()) == f["rows"]
    assert f["story_counts"] == {"fact": rep["counts"]["facts"], "hypothesis": rep["counts"]["hypotheses"], "gap": rep["counts"]["gaps"]}
    if f["whole"]:
        assert f["ids"] == order and f["note"] is None and f["layout"] == rep["layout"]
    else:
        assert f["rows"] < len(order) and str(len(order)) in f["note"] and "report below" in f["note"]
        used = {n for e in f["layout"]["edges"] for n in (e["u"], e["v"])} | {g["node_id"] for g in rep["gaps"] if g["id"] in set(f["ids"])}
        assert {n["id"] for n in f["layout"]["nodes"]} == used                      # the film's map holds the film's things, no others
        assert sorted(l["lane"] for l in f["layout"]["lanes"]) == list(range(len(f["layout"]["lanes"])))
        full = {n["id"]: n for n in rep["layout"]["nodes"]}
        assert all(n["order"] == full[n["id"]]["order"] and n["short"] == full[n["id"]]["short"] for n in f["layout"]["nodes"])


@pytest.mark.parametrize("name", NAMES)
def test_the_choice_does_not_change_when_every_name_does(name):
    rep = load(name)["report"]
    plain = F.film_of(rep)["ids"]
    other = copy.deepcopy(rep)
    for n in other["layout"]["nodes"]:
        n["short"] = n["label"] = "same-name.exe"
    for l in other["layout"]["lanes"]:
        l["short"] = "same-name.exe"
    for r in other["timeline"]:
        r["short"] = r["text"] = "x"
    assert F.film_of(other)["ids"] == plain


def test_what_the_big_and_odd_stories_come_to():
    """Sizes seen on the real stories. Bounds, not exact numbers: they say what "the film is the chain" means."""
    big = F.film_of(load("biggest-1120-rows")["report"])
    assert big["total"] == 1120 and big["whole"] is False and 2 <= big["rows"] <= 12 and len(big["layout"]["lanes"]) <= 6
    rails = F.film_of(load("most-rails-55")["report"])
    # 55 rails in the report. Its one step starts a shell that itself started some 25 programs: those are the
    # step's program's own children, so they are filmed (28 rows); the other rails are other programs' and are not
    assert rails["whole"] is False and rails["rows"] == len(rails["layout"]["lanes"]) == 28 and rails["total"] == 125
    step = next(e for e in load("most-rails-55")["report"]["layout"]["edges"] if e["in_chain"])
    assert sum(1 for e in rails["layout"]["edges"] if e["kind"] == "started" and e["u"] == step["v"]) >= 20
    nostep = load("no-step-116-rows")["report"]
    f = F.film_of(nostep)
    assert nostep["counts"]["steps"] == 0 and f["whole"] is False and f["rows"] <= 20 and f["note"].startswith(F.WORDS["note_none"].format(rows=116))
    about = {g["id"] for g in nostep["gaps"] if {c["key"] for c in g["citations"]} & {c["key"] for c in nostep["alert"]["citations"]}}
    assert about and about <= set(f["ids"])                                         # the row the alert's own record is about is in it
    churn = F.film_of(load("ninety-nine-steps-one-rail")["report"])
    assert churn["whole"] is True and churn["rows"] == 99                           # every row is a numbered step: nothing to leave out
    assert F.film_of(load("smallest-2-rows")["report"])["whole"] is True
    live = F.film_of(load("live-s1-44-rows")["report"])
    assert live["rows"] == 6 and live["counts"] == {"fact": 5, "hypothesis": 1, "gap": 0} and "the 4 steps" in live["note"]
    again = F.film_of(load("longest-cut-film")["report"])
    assert again["whole"] is False and len(again["layout"]["nodes"]) <= 4            # long because the same things are linked again and again
