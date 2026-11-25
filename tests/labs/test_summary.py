"""The incident in one paragraph (engine/labs/_summary.py): built by templates from the checklist's own answers;
every part names its source, and no part is ever stronger than the answer it summarises."""

from engine.labs import _summary as sm
from engine.labs import checklist

H = "vm"
FETCH, PAY, LAUNCH = f"proc:{H}:{{F}}", f"proc:{H}:{{P}}", f"proc:{H}:{{L}}"
FILE = f"file:{H}:c:\\t\\payload\\pay.exe|ABCD"
FOLDER = f"file:{H}:c:\\t\\payload"
NET = f"net:{H}:10.0.2.2:18765"


def fact(i, kind, u, v, sentence, t):
    return {"id": i, "kind": kind, "u": u, "v": v, "sentence": sentence, "time_precise": t, "citations": []}


CONTENT = {
    "facts": [
        fact("f0", "started", LAUNCH, FETCH, "powershell.exe started fetch.exe", "2026-10-30T20:01:31.582000Z"),
        fact("f1", "connected_to", FETCH, NET, "fetch.exe connected to 10.0.2.2:18765", "2026-10-30T20:01:31.754000Z"),
        fact("f2", "created", FETCH, FILE, "fetch.exe created pay.exe", "2026-10-30T20:01:31.757000Z"),
        fact("f3", "created", FETCH, FOLDER, "fetch.exe created payload", "2026-10-30T20:01:31.757000Z"),
        fact("f4", "started", FETCH, PAY, "fetch.exe started pay.exe", "2026-10-30T20:01:41.825000Z"),
        fact("f5", "ran_as", FILE, PAY, "pay.exe ran from the file pay.exe", "2026-10-30T20:01:41.825000Z"),
        fact("f6", "connected_to", LAUNCH, f"net:{H}:10.0.2.2:8770", "powershell.exe connected to 10.0.2.2:8770",
             "2026-10-30T20:01:48.370000Z")],
    "hypotheses": [{"id": "h1", "kind": "content_from", "u": NET, "v": FILE, "band": "low",
                    "sentence": "the content of pay.exe may have come from 10.0.2.2:18765", "citations": []}],
    "gaps": [{"id": "g1", "kind": "origin_unknown", "node_id": LAUNCH, "placement": "before", "plain": "how powershell.exe was started"}],
    "counts": {"facts": 7, "hypotheses": 1, "gaps": 1},
}
NAMES = {FETCH: "fetch.exe", PAY: "pay.exe", LAUNCH: "powershell.exe"}
EXTRA = {"harness": {"f6"}, "launcher": {"f0"}, "folders": {"c:\\t\\payload"}, "edge": 1,
         "fingerprints": {"h1": {"programs": [{"image": "C:\\t\\fetch.exe"}]}},
         "sweep": {"rows": [{"verdict": "seen", "other_runs": 0}, {"verdict": "not_seen", "other_runs": 0},
                            {"verdict": "cant_tell", "other_runs": 0}]}}


def questions():
    """The checklist's real answers for this story, with the "How sure" step it took over from triage."""
    out = checklist.answer(CONTENT, {"{F}"}, machinery_nodes=set())
    return checklist.with_triage(out["questions"], [{"key": "sure", "status": "mixed", "line": "L", "lab": "claim"}]), out


def text(para):
    return ["".join(p["text"] for p in s) for s in para]


def test_the_paragraph_on_an_s1_like_story():
    qs, out = questions()
    para = sm.summary(qs, CONTENT, NAMES, out["scope"], EXTRA)
    assert text(para) == [
        "fetch.exe, started by the lab's own test launcher, connected to 10.0.2.2:18765, wrote pay.exe, and started that "
        "same file 10.1 s later.",
        "Of the 9 lines of its story, 7 are proven by a record, 1 suspected and 1 can't be known (only how a program that "
        "was already running when this recording began was started).",
        "Likely but not proven: the content of pay.exe may have come from 10.0.2.2:18765 (the written file has exactly "
        "the fingerprint fetch.exe was told to fetch).",
        "No autostart change or file deletion is in its story; this recorder sees only some of these.",
        "None of its 2 things that this recorder can see (programs, files, addresses, fingerprints) shows up anywhere "
        "else in this recording (1 more can't be checked here).",
    ]
    assert "8770" not in " ".join(text(para))                 # the test machinery's own line is not the alert's
    assert "payload" not in text(para)[0].replace("pay.exe", "")   # a folder is not "wrote"


def test_no_part_is_stronger_than_the_answer_it_summarises():
    qs, out = questions()
    by = {q["key"]: q for q in qs}
    para = sm.summary(qs, CONTENT, NAMES, out["scope"], EXTRA)
    checked = 0
    for s in para:
        for p in s:
            if p["source"] in by:
                assert sm.RANK[p["status"]] <= sm.RANK[by[p["source"]]["status"]], (p, by[p["source"]]["status"])
                checked += 1
    assert checked >= 7


def test_a_part_whose_question_is_not_proven_is_left_out():
    qs, out = questions()
    weaker = [dict(q, status="none") if q["key"] == "network" else q for q in qs]
    first = text(sm.summary(weaker, CONTENT, NAMES, out["scope"], EXTRA))[0]
    assert "connected" not in first and "wrote pay.exe" in first
    no_what = [dict(q, status="none") if q["key"] in ("what", "network", "files") else q for q in qs]
    assert not text(sm.summary(no_what, CONTENT, NAMES, out["scope"], EXTRA))[0].startswith("fetch.exe")


def test_absence_is_never_said_as_didnt_happen_and_spread_is_said_when_seen():
    w = sm.WORDS
    assert "in its story" in w["not_in_story"] and "only some" in w["not_in_story"]
    away = sm.where_else({"rows": [{"verdict": "seen", "other_runs": 2}, {"verdict": "not_seen", "other_runs": 0}]})
    assert away[0]["text"] == "1 of its 2 things also show up in another run on this machine." and away[0]["status"] == "fact"
    common = sm.where_else({"rows": [{"verdict": "seen", "other_runs": 5, "common": True}]})
    assert common is None                                      # Windows' own helpers say nothing about THIS alert
    assert sm.where_else(None) is None and sm.not_in_story({}) is None


def test_names_come_from_records_or_the_node_itself_never_guessed():
    assert sm.name_of(FILE, {}) == "pay.exe" and sm.name_of(NET, {}) == "10.0.2.2:18765"
    assert sm.name_of(FETCH, {}) is None                       # a program without its start record has no name here
    assert sm.what_happened({}, CONTENT, {}, [FETCH, PAY]) is None


def test_suspected_links_about_the_test_machinery_are_left_out_and_counted():
    content = dict(CONTENT, hypotheses=CONTENT["hypotheses"] + [
        {"id": "h2", "kind": "content_from", "u": f"net:{H}:10.0.2.2:8770", "v": f"file:{H}:c:\\b\\barrier.txt",
         "sentence": "the content of barrier.txt may have come from 10.0.2.2:8770"}])
    qs, out = questions()
    lines = text(sm.summary(qs, content, NAMES, out["scope"], dict(EXTRA, machinery={f"net:{H}:10.0.2.2:8770"})))
    assert not any("barrier" in l for l in lines)
    assert "Left out here: suspected links about the lab's own test machinery: 1." in lines

