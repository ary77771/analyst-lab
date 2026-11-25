"""Status app (statusapp/): numbers-only statistics, the self-test's matching, and what the
window shows. The privacy tests plant recognisable names, paths, addresses and domains in a
recording and prove none of them reaches the exported file."""

import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from agent.control import request_pause, utc_text
from statusapp import app, selftest, stats

T0 = datetime(2026, 10, 20, 9, 0, 0, tzinfo=timezone.utc)
CH = "Microsoft-Windows-Sysmon/Operational"
SECRETS = [r"C:\Users\Secret Person\Documents\diary.exe", "very-private-site.example", "203.0.113.77",
           "--password hunter2", "secret-person"]


def rec(rid, eid, minute, origin="normal", **extra):
    t = utc_text(T0 + timedelta(minutes=minute))
    r = {"host": "secret-person", "label": "host", "session": "s1", "source": "sysmon", "channel": CH,
         "record_id": rid, "event_id": eid, "time": t, "origin": origin,
         "data": {"Image": SECRETS[0], "QueryName": SECRETS[1], "DestinationIp": SECRETS[2],
                  "CommandLine": SECRETS[0] + " " + SECRETS[3]}}
    r.update(extra)
    return r


def write_day(folder, day, rows, tail=b""):
    folder.mkdir(parents=True, exist_ok=True)
    p = folder / f"{day}.jsonl"
    p.write_bytes("".join(json.dumps(r) + "\n" for r in rows).encode() + tail)
    return p


def sample_rows():
    rows = [rec(i, 1 if i % 2 else 3, i // 3) for i in range(1, 61)]            # minutes 0-20: 21 active
    rows += [rec(100 + i, 22, 70 + i) for i in range(5)]                          # next hour: 5 lookups
    rows.append(rec(61, 1, 5, origin="project"))                                  # our own tools
    rows.append(rec(62, 3, 6, paused=True, data={}))                              # during a pause
    rows.append({"host": "h", "session": "s1", "source": "agent", "seq": 1, "type": "PAUSE_START",
                 "time": utc_text(T0), "data": {"requested": utc_text(T0), "until": utc_text(T0 + timedelta(minutes=30))}})
    return rows


# -- statistics ----------------------------------------------------------------------------------
def test_ranges_track_numbers_and_missing():
    r = stats.Ranges()
    for n in [1, 2, 3, 7, 5, 6, 3, 10]:
        r.add(n)
    assert r.runs == [[1, 3], [5, 7], [10, 10]] and r.count() == 7 and r.missing() == 3
    r.add(4)
    assert r.runs == [[1, 7], [10, 10]]
    other = stats.Ranges([[8, 9], [20, 25]])
    r.update(other)
    assert r.runs == [[1, 10], [20, 25]] and r.missing() == 9


def test_summary_counts_and_leaves_out(tmp_path):
    write_day(tmp_path / "host", "2026-10-20", sample_rows())
    s = stats.summarize(stats.collect(str(tmp_path)), now=T0 + timedelta(days=1))
    assert s["events"] == {"process starts": 30, "network connections": 30, "DNS lookups": 5}
    assert s["active_hours"] == round(26 / 60, 1) and s["days_recorded"] == 1
    assert s["left_out"] == {"our own lab tools": 1, "while paused (counted only)": 1}
    assert s["paused_minutes"] == 30
    assert s["health"]["sysmon_records"] == 67 and s["health"]["sysmon_records_missing"] == 37      # 63-99
    assert [h["active_minutes"] for h in s["hours"]] == [21, 5]
    assert s["hours"][1]["events"] == {"22": 5}


def test_export_contains_no_names_paths_addresses_or_times(tmp_path):
    write_day(tmp_path / "host", "2026-10-20", sample_rows())
    path = app.export(str(tmp_path), "host", str(tmp_path / ".state" / "host"), folder=str(tmp_path),
                      now=datetime(2026, 10, 27))
    text = open(path, encoding="utf-8").read()
    for secret in SECRETS + ["2026-10-20", "09:0"]:
        assert secret.lower() not in text.lower(), secret
    assert "Made on: 2026-10-27" in text and "process starts" in text
    assert stats.read_export(text)["events"]["DNS lookups"] == 5               # Yousif reads it back


def test_the_guard_checks_the_exact_layout():
    s = stats.summarize({})
    stats.check_summary(s)
    good = json.loads(json.dumps(s))
    good["events"] = {"process starts": 5}
    good["events_per_active_hour"] = {"process starts": 1.0}
    good["hours"] = [{"active_minutes": 3, "events": {"1": 5}}]
    stats.check_summary(good)
    poisons = [
        lambda d: d["events"].update({SECRETS[0]: 1}),                         # a path as a label
        lambda d: d["hours"][0]["events"].update({"443": 1}),                  # a port as a key
        lambda d: d["hours"][0]["events"].update({"1": 3405803777}),           # an address as a number
        lambda d: d["health"].update({"note": 1}),                             # an extra key
        lambda d: d["health"].pop("damaged_lines"),                            # a missing key
        lambda d: d["self_test"].update({"last_passed": "yes"}),               # text instead of a value
        lambda d: d["left_out"].update({"our own lab tools": -1}),
        lambda d: d["events"].update({"process starts": True}),
        lambda d: d.update({"active_hours": "1"}),
        lambda d: d["hours"].append({"active_minutes": 61, "events": {}}),
        lambda d: d.update({"extra": 1}),
    ]
    for poison in poisons:
        bad = json.loads(json.dumps(good))
        poison(bad)
        with pytest.raises(stats.NotNumbersOnly):
            stats.export_text(bad, "2026-10-27")
    with pytest.raises(stats.NotNumbersOnly):
        stats.export_text(good, "C:\\Users")


def test_a_re_delivered_event_is_counted_once():
    day = stats.DayStats()
    r = rec(5, 1, 0)
    day.feed(r)
    day.feed(dict(r, session="s2"))                  # the agent re-sent its last batch after a restart
    s = stats.summarize({"d": day})
    assert s["events"] == {"process starts": 1} and s["health"]["re_delivered_skipped"] == 1


def test_reading_in_chunks_never_splits_a_line(tmp_path, monkeypatch):
    monkeypatch.setattr(stats, "CHUNK", 37)          # far smaller than one line
    rows = sample_rows()
    write_day(tmp_path / "host", "2026-10-20", rows)
    whole = stats.DayStats()
    for r in rows:
        whole.feed(r)
    got = stats.collect(str(tmp_path))["2026-10-20"]
    assert got.counts == whole.counts and got.bad_lines == 0 and got.minutes == whole.minutes


def test_a_running_pause_counts_only_up_to_now():
    p = {utc_text(T0): utc_text(T0 + timedelta(minutes=60))}
    assert stats.paused_minutes(p, now=T0 + timedelta(minutes=10)) == 10
    assert stats.paused_minutes(p, now=T0 + timedelta(hours=5)) == 60


def test_unknown_event_types_are_not_exported():
    day = stats.DayStats()
    day.feed(rec(1, 255, 0))
    stats.check_summary(stats.summarize({"d": day}))

def test_today_is_read_on_and_a_half_written_line_waits(tmp_path):
    folder = tmp_path / "host"
    rows = sample_rows()
    half = json.dumps(rows[10]).encode()
    p = write_day(folder, "2026-10-20", rows[:10], tail=half[:20])
    first = stats.collect(str(tmp_path))["2026-10-20"]
    assert sum(first.counts.values()) == 10
    with open(p, "ab") as f:                                                     # the agent finishes it
        f.write(half[20:] + b"\n" + "".join(json.dumps(r) + "\n" for r in rows[11:]).encode())
    again = stats.collect(str(tmp_path))["2026-10-20"]
    full = stats.DayStats()
    for r in rows:
        full.feed(r)
    assert again.counts == full.counts and again.bad_lines == 0 and again.minutes == full.minutes


def test_cache_matches_a_fresh_count_and_survives_compression(tmp_path):
    import gzip
    folder = tmp_path / "host"
    p = write_day(folder, "2026-10-20", sample_rows())
    a = stats.summarize(stats.collect(str(tmp_path)))
    (folder / "2026-10-20.jsonl.gz").write_bytes(gzip.compress(p.read_bytes()))
    os.remove(p)
    b = stats.summarize(stats.collect(str(tmp_path)))
    os.remove(tmp_path / ".state" / "host" / "stats-cache.json")
    c = stats.summarize(stats.collect(str(tmp_path)))
    assert a == b == c


def test_damaged_cache_is_ignored(tmp_path):
    write_day(tmp_path / "host", "2026-10-20", sample_rows())
    (tmp_path / ".state" / "host").mkdir(parents=True)
    (tmp_path / ".state" / "host" / "stats-cache.json").write_text("{broken")
    assert stats.summarize(stats.collect(str(tmp_path)))["events"]["DNS lookups"] == 5


# -- self-test -----------------------------------------------------------------------------------
EXP = {"tag": "t", "pid": 4242, "file": "analystlab-selftest-t.cmd", "name": "analystlab-selftest-t.invalid",
       "server_port": 50001, "client_port": 50002}


def proof_rows(skip=()):
    def s(eid, **data):
        return {"source": "sysmon", "event_id": eid, "data": data}
    rows = {"program_start": s(1, ProcessId="4242", Image=r"C:\Windows\System32\cmd.exe", ProcessGuid="{G}"),
            "program_end": s(5, ProcessId=4242, Image=r"C:\Windows\System32\CMD.EXE"),
            "file_created": s(11, TargetFilename=r"C:\Users\x\AppData\Local\Temp\ANALYSTLAB-SELFTEST-T.cmd"),
            "file_deleted": s(26, TargetFilename=r"C:\Users\x\AppData\Local\Temp\analystlab-selftest-t.cmd"),
            "lookup": s(22, QueryName="analystlab-selftest-t.invalid"),
            "connection": s(3, SourcePort=50002, DestinationPort=50001)}
    return [r for k, r in rows.items() if k not in skip]


def test_selftest_matching_needs_every_part():
    found = {}
    for r in proof_rows():
        selftest.match(r, EXP, found)
    assert all(ok for _, _, ok, _ in selftest.verdict(found))
    found = {}
    for r in proof_rows(skip=("file_deleted",)):
        selftest.match(r, EXP, found)
    v = {k: (ok, d) for k, _, ok, d in selftest.verdict(found)}
    assert v["file"] == (False, "not recorded: file deleted") and v["program"][0] and v["connection"][0]


def test_selftest_ignores_lookalikes_and_paused_skeletons():
    found = {}
    look = [{"source": "sysmon", "event_id": 1, "data": {"ProcessId": 4242, "Image": r"C:\x\notcmd.exe"}},
            {"source": "sysmon", "event_id": 22, "data": {"QueryName": "other.invalid"}},
            {"source": "sysmon", "event_id": 3, "data": {"SourcePort": 50002, "DestinationPort": 443}},
            {"source": "sysmon", "event_id": 1, "paused": True, "data": {}}]
    for r in look:
        selftest.match(r, EXP, found)
    assert found == {}


def _fake_recorder(folder, rows, delay=0.3):
    def write():
        time.sleep(delay)
        with open(folder / "2026-10-20.jsonl", "a", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
    threading.Thread(target=write, daemon=True).start()


def test_selftest_run_passes_when_the_recorder_writes_the_proof(tmp_path):
    folder = tmp_path / "host"
    write_day(folder, "2026-10-20", [rec(1, 1, 0)] + proof_rows())    # OLD proof before the test: ignored
    def actions(tag):
        _fake_recorder(folder, proof_rows())
        return EXP
    r = selftest.run(str(tmp_path), timeout=10, poll=0.1, actions=actions)
    assert r["passed"] is True
    assert selftest.history(str(tmp_path / ".state" / "host"))["runs"] == 1


def test_selftest_does_not_reuse_old_lines_and_fails_with_a_next_step(tmp_path):
    folder = tmp_path / "host"
    write_day(folder, "2026-10-20", proof_rows())                     # everything is there, but OLD
    def actions(tag):
        _fake_recorder(folder, proof_rows(skip=("lookup",)))
        return EXP
    r = selftest.run(str(tmp_path), timeout=1.5, poll=0.1, actions=actions)
    assert r["passed"] is False and r["message"] == selftest.NEXT_STEP
    assert [c["key"] for c in r["checks"] if not c["ok"]] == ["lookup"]
    h = selftest.history(str(tmp_path / ".state" / "host"))
    assert h["runs"] == 1 and h["last_passed"] is False


def test_selftest_under_someone_elses_sysmon_says_not_covered(tmp_path):
    folder = tmp_path / "host"
    write_day(folder, "2026-10-20", [])
    def actions(tag):
        _fake_recorder(folder, proof_rows(skip=("lookup",)))
        return EXP
    r = selftest.run(str(tmp_path), timeout=1.5, poll=0.1, actions=actions, foreign_sysmon=True)
    assert r["passed"] is False and r["message"] == selftest.FOREIGN_NOTE
    assert [c["detail"] for c in r["checks"] if not c["ok"]] == ["not covered by this laptop's own Sysmon settings"]


def test_selftest_while_paused_says_resume_first(tmp_path):
    request_pause(str(tmp_path / ".state" / "host"))
    r = selftest.run(str(tmp_path), timeout=1, actions=lambda tag: pytest.fail("must not act while paused"))
    assert r["paused"] is True and "Resume" in r["message"]


# -- the window's decisions ----------------------------------------------------------------------
NOW = datetime(2026, 10, 25, 15, 0, 0, tzinfo=timezone.utc)


def status(age_s=3, errors=0):
    return {"updated": utc_text(NOW - timedelta(seconds=age_s)), "errors": errors, "events_written": 5,
            "last_record_id": 9, "cpu_percent_of_machine": 0.1, "memory_mb": 11}


def summary(days=3, hours=12.5):
    s = stats.summarize({})
    s.update(days_recorded=days, active_hours=hours)
    return s


@pytest.mark.parametrize("st,pause,headline,pause_button", [
    (None, None, "The recorder has not started yet", "Pause for 1 hour"),
    (status(age_s=600), None, "The recorder is not running", "Pause for 1 hour"),
    (status(errors=2), None, "Collecting, with a problem", "Pause for 1 hour"),
    (status(), (utc_text(NOW - timedelta(minutes=5)), utc_text(NOW + timedelta(minutes=55))), "Paused until", "Resume now"),
    (status(), (utc_text(NOW - timedelta(hours=2)), utc_text(NOW - timedelta(hours=1))), "Collecting. You don't", "Pause for 1 hour"),
    (status(), None, "Collecting. You don't need to do anything.", "Pause for 1 hour"),
])
def test_view_headlines(st, pause, headline, pause_button):
    v = app.view(st, NOW, summary(), pause)
    assert v["headline"].startswith(headline) and v["pause_button"] == pause_button
    assert v["pause_enabled"] == ("not" not in v["headline"])        # no pause button without a recorder


def test_view_progress_and_lab_lines():
    v = app.view(status(), NOW, summary(days=3, hours=12.46))
    assert v["progress"] == "Day 3 of 7  ·  12.5 active hours" and abs(v["progress_fraction"] - 3 / 7) < 1e-9
    v = app.view(status(), NOW, summary(days=9))
    assert v["progress_fraction"] == 1.0 and "Done! Export" in v["progress"] and "Day 7 of 7" in v["progress"]
    assert app.view(status(), NOW, None)["progress"].startswith("Counting")
    assert app.view(status(), NOW, summary())["lab"] == []
    assert any("missing 0" in line for line in app.view(status(), NOW, summary(), mode="lab")["lab"])


def test_window_opens_and_draws(tmp_path):
    tk = pytest.importorskip("tkinter")
    write_day(tmp_path / "host", "2026-10-20", sample_rows())
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display")
    root.withdraw()
    try:
        w = app.StatusWindow(root, str(tmp_path), "host", "lab")
        deadline = time.time() + 10
        while w.summary is None and time.time() < deadline:
            root.update()
            time.sleep(0.05)
        assert w.summary is not None and w.headline.cget("text") == "The recorder has not started yet"
        assert str(w.b_pause.cget("state")) == "disabled"
        while w.busy and time.time() < deadline:      # let background jobs finish before closing
            root.update()
            time.sleep(0.05)
    finally:
        root.destroy()
