"""Which rows the Story screen's film tells (engine/dashboard/film.py).

A long live story is filmed as the alert's own chain; the report keeps every row. The choice is made in
Python from the story's own data (ids, kinds, grades, the chain mark), never from a program's name."""

from fastapi.testclient import TestClient

from engine import report as report_mod
from engine.alerts import AlertStore
from engine.dashboard import film as F
from engine.dashboard.app import create_app
from tests.test_report import s1_like


def story(helpers=8, chain=True, names=None):
    """A made-up report content shaped like the real live run of 2026-11-20: a starter program starts
    `helpers` programs that do a little housekeeping each, then another program that IS the alert's chain
    (connects out, creates a file, starts it), with one suspected link inside the chain and one outside."""
    name = names or (lambda n: n)
    lanes, nodes, edges, timeline, gaps = [], [], [], [], []
    order = [0]

    def lane(owner):
        lanes.append({"lane": len(lanes), "node_id": owner, "short": name(owner)})
        return len(lanes) - 1

    def node(i, kind, ln):
        nodes.append({"id": i, "short": name(i), "label": name(i), "kind": kind, "icon": "x", "lane": ln, "order": order[0]})

    def link(i, u, v, kind, ln, grade="fact", in_chain=False):
        order[0] += 1
        edges.append({"id": i, "u": u, "v": v, "kind": kind, "grade": grade, "band": "low" if grade == "hypothesis" else None,
                      "lane": ln, "order": order[0], "icon": "x", "short": i, "in_chain": in_chain})
        timeline.append({"id": i, "ink": grade, "grade": grade, "order": order[0], "short": i, "text": i, "in_chain": in_chain})

    def gap(i, node_id, before=False):
        order[0] += 1
        gaps.append({"id": i, "node_id": node_id, "placement": "before" if before else "at"})
        timeline.append({"id": i, "ink": "gap", "grade": "gap", "order": order[0], "short": i, "text": i, "in_chain": False})

    top = lane("starter")
    node("starter", "process", top)
    gap("g-starter", "starter", before=True)                       # which program started the starter: can't be known
    for k in range(helpers):
        ln = lane(f"helper{k}")
        node(f"helper{k}", "process", ln)
        link(f"start-helper{k}", "starter", f"helper{k}", "started", top)
        node(f"note{k}", "file", ln)
        link(f"write{k}", f"helper{k}", f"note{k}", "created", ln)
        if k % 4 == 0:
            gap(f"g-note{k}", f"note{k}")
    a, b = lane("fetch"), lane("payload")
    node("fetch", "process", a)
    link("start-fetch", "starter", "fetch", "started", top)
    node("server", "endpoint", a)
    link("c1", "fetch", "server", "connected_to", a, in_chain=chain)
    node("folder", "file", a)
    link("mkdir", "fetch", "folder", "created", a)                 # the chain's program did it, but it is not a step
    node("dropped", "file", a)
    link("c2", "fetch", "dropped", "created", a, in_chain=chain)
    link("h-inside", "server", "dropped", "content_from", a, grade="hypothesis")
    gap("g-dropped", "dropped")
    node("payload", "process", b)
    link("c3", "fetch", "payload", "started", a, in_chain=chain)
    link("c4", "payload", "dropped", "ran_from", b, in_chain=chain)
    node("other", "endpoint", top)
    link("phone-home", "starter", "other", "connected_to", top)
    link("h-outside", "other", "helper0", "started_after", top, grade="hypothesis")
    return {"timeline": timeline, "gaps": gaps, "counts": {"steps": 4 if chain else 0},
            "layout": {"lanes": lanes, "nodes": nodes, "edges": edges, "t0": "t", "offset_from": "step 1"}}


CHAIN_FILM = ["g-starter", "start-fetch", "c1", "c2", "h-inside", "g-dropped", "c3", "c4"]


def test_a_long_story_is_filmed_as_the_alerts_chain_and_what_links_it():
    c = story()
    assert len(c["timeline"]) > F.FILM_WHOLE_ROWS
    f = F.film_of(c)
    assert f["whole"] is False and f["ids"] == CHAIN_FILM and f["rows"] == 8 and f["total"] == len(c["timeline"])
    # in the report's own order, and only rows the report has
    order = [r["id"] for r in c["timeline"]]
    assert f["ids"] == [i for i in order if i in set(f["ids"])]
    # the four steps; the program that started the chain's program and why its own start is unknown; the
    # suspected link and the unknown inside the chain. Not: the helpers, a non-step action of the chain's
    # program on another thing, or anything on the starter's own side.
    for left_out in ("start-helper0", "write0", "g-note0", "mkdir", "phone-home", "h-outside"):
        assert left_out not in f["ids"]


def launcher_story(others=20):
    """The shape of the public attack tests in the lab VM (2026-11-21 sweep): a launcher starts twenty
    programs; the alert's ONE step is "launcher started tool". The tool then starts a child of its own."""
    lanes, nodes, edges, timeline, gaps = [], [], [], [], []
    n = [0]

    def prog(i):
        lanes.append({"lane": len(lanes), "node_id": i, "short": i})
        nodes.append({"id": i, "short": i, "label": i, "kind": "process", "icon": "x", "lane": len(lanes) - 1, "order": n[0]})

    def started(i, u, v, in_chain=False):
        n[0] += 1
        edges.append({"id": i, "u": u, "v": v, "kind": "started", "grade": "fact", "band": None, "lane": 0, "order": n[0], "icon": "x", "short": i, "in_chain": in_chain})
        timeline.append({"id": i, "ink": "fact", "grade": "fact", "order": n[0], "short": i, "text": i, "in_chain": in_chain})

    for p in ("shell", "launcher"):
        prog(p)
    gaps.append({"id": "g-shell", "node_id": "shell"})
    timeline.append({"id": "g-shell", "ink": "gap", "grade": "gap", "order": 0, "short": "g", "text": "g", "in_chain": False})
    started("shell>launcher", "shell", "launcher")
    for k in range(others):
        prog(f"other{k}")
        started(f"launcher>other{k}", "launcher", f"other{k}")
        if k == others // 2:
            prog("tool")
            started("launcher>tool", "launcher", "tool", in_chain=True)
            prog("child")
            started("tool>child", "tool", "child")
            prog("grandchild")
            started("child>grandchild", "child", "grandchild")
    return {"timeline": timeline, "gaps": gaps, "counts": {"steps": 1}, "layout": {"lanes": lanes, "nodes": nodes, "edges": edges}}


def test_a_step_that_is_only_a_start_does_not_pull_in_the_parents_other_children():
    c = launcher_story()
    assert len(c["timeline"]) > F.FILM_WHOLE_ROWS
    f = F.film_of(c)
    # who started the launcher, the step itself, and what the started program went on to start: its own child
    assert f["ids"] == ["g-shell", "shell>launcher", "launcher>tool", "tool>child"]      # and why the first one's own start is unknown
    assert not any(i.startswith("launcher>other") for i in f["ids"])        # the brothers and sisters stay in the report
    assert "child>grandchild" not in f["ids"]                                # one link out, not the whole family tree
    assert f["note"] == F.WORDS["note_one"].format(rows=len(c["timeline"])) and f["counts"] == {"fact": 3, "hypothesis": 0, "gap": 1}
    assert [n["id"] for n in f["layout"]["nodes"]] == ["shell", "launcher", "tool", "child"]
    assert len(F.film_of(c)["layout"]["lanes"]) == 4 and len(c["layout"]["lanes"]) == 25


def test_the_two_sets_of_counts_are_separate_and_named():
    c = story()
    f = F.film_of(c)
    assert f["counts"] == {"fact": 5, "hypothesis": 1, "gap": 2}
    whole = {"fact": 0, "hypothesis": 0, "gap": 0}
    for r in c["timeline"]:
        whole[r["ink"]] += 1
    assert f["story_counts"] == whole and sum(whole.values()) == f["total"] and f["counts"] != f["story_counts"]
    assert f["labels"] == {"film": "in the film", "story": "in the whole story"}
    # the line under the film says both numbers, from this story's own data
    assert f["note"] == F.WORDS["note"].format(n=4, rows=len(c["timeline"]))
    assert "the 4 steps" in f["note"] and f"All {len(c['timeline'])} recorded rows" in f["note"] and "report below" in f["note"]


def test_the_choice_never_depends_on_a_programs_name():
    plain = F.film_of(story())["ids"]
    for rename in (lambda n: "VBoxControl.exe", lambda n: n.upper(), lambda n: ""):
        assert F.film_of(story(names=rename))["ids"] == plain
    import inspect
    src = inspect.getsource(F)
    code = "\n".join(line.split("#")[0] for line in src.split('"""')[2::2] for line in line.splitlines())
    for word in ("VBox", ".exe", "powershell", "conhost", '"short"', '"label"'):
        assert word not in code, word                               # no name, and no name field, is ever looked at


def test_a_short_story_is_filmed_whole_and_so_is_a_long_one_without_a_chain():
    short = story(helpers=2)
    assert len(short["timeline"]) <= F.FILM_WHOLE_ROWS
    f = F.film_of(short)
    assert f["whole"] is True and f["ids"] == [r["id"] for r in short["timeline"]] and f["note"] is None
    assert f["layout"] is short["layout"] and f["counts"] == f["story_counts"]
    nochain = story(chain=False)                                    # no step, and nothing that says what the alert is about
    f = F.film_of(nochain)
    assert f["whole"] is True and f["rows"] == f["total"] == len(nochain["timeline"]) and f["note"] is None


def test_an_alert_with_no_numbered_step_is_filmed_from_what_its_own_records_are_about():
    """The real case (2026-11-21): a shell whose parent was not recorded. No fact is the alert's step; its one
    record is cited by the can't-be-known row about that shell. 44 to 116 rows were filmed whole."""
    c = story(chain=False)
    c["alert"] = {"citations": [{"key": "k-own"}]}
    c["facts"] = [{"id": e["id"], "citations": [{"key": "k-" + e["id"]}]} for e in c["layout"]["edges"] if e["grade"] == "fact"]
    c["hypotheses"] = [{"id": e["id"], "citations": [{"key": "k-" + e["id"]}]} for e in c["layout"]["edges"] if e["grade"] == "hypothesis"]
    for g in c["gaps"]:
        g["citations"] = [{"key": "k-own"}] if g["id"] == "g-starter" else []
    f = F.film_of(c)
    # the starter (the thing the alert's record is about), every program it started, and the rows among them
    assert f["whole"] is False and f["ids"][0] == "g-starter" and "start-fetch" in f["ids"] and "start-helper0" in f["ids"]
    for left_out in ("write0", "g-note0", "c1", "c2", "mkdir", "phone-home", "h-inside", "h-outside"):
        assert left_out not in f["ids"]
    order = [r["id"] for r in c["timeline"]]
    assert f["ids"] == [i for i in order if i in set(f["ids"])]
    assert f["note"] == F.WORDS["note_none"].format(rows=len(c["timeline"])) and "what this alert is about" in f["note"]
    # still never by name, and a record nothing cites chooses nothing (whole film, no invented centre)
    assert F.film_of(dict(c, alert={"citations": [{"key": "k-nobody"}]}))["whole"] is True
    assert F.film_of(dict(c, alert={}))["whole"] is True


def test_the_films_map_is_the_reports_layout_cut_down_never_rearranged():
    c = story()
    f = F.film_of(c)
    lay = f["layout"]
    things = {"starter", "fetch", "server", "dropped", "payload"}
    assert {n["id"] for n in lay["nodes"]} == things
    assert {e["id"] for e in lay["edges"]} == set(CHAIN_FILM) - {"g-starter", "g-dropped"}
    assert [l["lane"] for l in lay["lanes"]] == [0, 1, 2] and [l["node_id"] for l in lay["lanes"]] == ["starter", "fetch", "payload"]
    full = {n["id"]: n for n in c["layout"]["nodes"]}
    for n in lay["nodes"]:                                          # same order number, same words; only the rail number closes up
        assert n["order"] == full[n["id"]]["order"] and n["short"] == full[n["id"]]["short"]
    lane_of = {n["id"]: n["lane"] for n in lay["nodes"]}
    assert lane_of["starter"] < lane_of["fetch"] < lane_of["payload"] and lane_of["server"] == lane_of["fetch"]
    assert lay["t0"] == "t" and lay["offset_from"] == "step 1"
    assert len(c["layout"]["nodes"]) > len(lay["nodes"])            # the report's own layout was not touched
    assert c["layout"]["lanes"][-1]["lane"] == len(c["layout"]["lanes"]) - 1


def test_a_story_with_no_rows_says_so_instead_of_showing_an_empty_film():
    f = F.film_of({"timeline": [], "gaps": [], "counts": {"steps": 0}, "layout": {"lanes": [], "nodes": [], "edges": []}})
    assert f["whole"] is True and f["rows"] == 0 and f["ids"] == [] and f["note"] == F.WORDS["empty"]
    assert "no story to tell" in f["note"] and f["counts"] == f["story_counts"] == {"fact": 0, "hypothesis": 0, "gap": 0}


def test_all_n_rows_never_reads_as_everything_when_the_story_was_cut_at_its_size_limit():
    c = story()
    plain = F.film_of(c)["note"]
    c["graph"] = {"truncated": True}
    assert F.film_of(c)["note"] == plain + F.WORDS["bounded"] and "size limit" in F.film_of(c)["note"]
    c["graph"] = {"truncated": False}
    assert F.film_of(c)["note"] == plain


def test_one_step_has_its_own_sentence():
    c = story()
    c["counts"]["steps"] = 1
    assert F.film_of(c)["note"] == F.WORDS["note_one"].format(rows=len(c["timeline"]))


def test_the_recorded_s1_story_is_filmed_whole_and_the_report_route_is_untouched(tmp_path):
    con, alert, G = s1_like(tmp_path)
    con.close()
    content = report_mod.build(alert, G)
    f = F.film_of(content)
    assert f["whole"] is True and f["ids"] == [r["id"] for r in content["timeline"]] and f["note"] is None
    s = AlertStore(str(tmp_path / "alerts.db"))
    s.write([alert])
    s.close()
    c = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "alerts.db"), recordings=str(tmp_path / "rec")))
    api = c.get(f"/api/alerts/{alert.alert_id}/film").json()
    inv = c.get(f"/api/alerts/{alert.alert_id}").json()
    assert api["whole"] is True and api["ids"] == [r["id"] for r in inv["report"]["timeline"]]
    assert api["story_counts"] == {"fact": inv["report"]["counts"]["facts"], "hypothesis": inv["report"]["counts"]["hypotheses"],
                                   "gap": inv["report"]["counts"]["gaps"]}
    assert "film" not in inv                                        # the story's own answer is as it was: every row
    assert c.get("/api/alerts/nope/film").status_code == 404
