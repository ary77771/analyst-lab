"""Package B: Analyst Lab rules Sigma can't express (engine/own_rules.py)."""

import sqlite3

import pytest

from engine import own_rules
from engine.store import EventStore
from tests.test_detect import ev, store

W = r"C:\Users\u\Downloads\tool.exe"


def chain(t_conn=0.0, t_write=2.0, t_start=5.0, writer="{AAAA}", started=W, ip="10.0.2.2", initiated="true", **kw):
    return [ev(3, t_conn, ProcessGuid=writer, Initiated=initiated, DestinationIp=ip, DestinationPort=80, **kw),
            ev(11, t_write, ProcessGuid=writer, TargetFilename=W),
            ev(1, t_start, ProcessGuid="{CCCC}", ParentProcessGuid="{EEEE}", Image=started)]


def fire(tmp_path, records, **kw):
    con = sqlite3.connect(store(tmp_path, records))
    try:
        return own_rules.fetch_write_run(con, **kw)
    finally:
        con.close()


def test_fires_once_with_all_three_events(tmp_path):
    recs = chain()
    alerts = fire(tmp_path, recs)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_id == "analystlab.fetch_write_run" and a.source == "analystlab" and a.level == "medium"
    assert a.evidence == tuple(EventStore.dedup_key(r) for r in recs)
    assert a.time == "2026-10-22T10:00:05.000Z" and a.details["seconds_connect_to_start"] == 5.0
    assert "10.0.2.2" not in a.reason                         # addresses stay in details, not the sentence


@pytest.mark.parametrize("case", [
    dict(t_start=61.0),                       # whole chain longer than 60 s
    dict(t_conn=3.0),                         # connected only after writing
    dict(t_start=1.0),                        # started before it was written
    dict(started=r"C:\Users\u\Downloads\other.exe"),   # a different file was started
    dict(ip="127.0.0.1"),                     # talking to itself
    dict(ip="::1"),
    dict(initiated="false"),                  # an incoming connection
])
def test_near_misses_do_not_fire(tmp_path, case):
    assert fire(tmp_path, chain(**case)) == []


def test_boundaries_and_case(tmp_path):
    assert len(fire(tmp_path, chain(t_start=60.0))) == 1              # exactly 60 s is inside
    assert len(fire(tmp_path, chain(started=W.upper()))) == 1         # Windows paths ignore case
    assert len(fire(tmp_path, chain(t_start=20.0), window=30)) == 1
    assert fire(tmp_path, chain(t_start=40.0), window=30) == []


def test_connection_must_be_by_the_writer(tmp_path):
    recs = chain()
    recs[0] = ev(3, 0.0, ProcessGuid="{BBBB}", Initiated="true", DestinationIp="10.0.2.2", DestinationPort=80)
    assert fire(tmp_path, recs) == []


def test_uses_when_it_happened(tmp_path):
    recs = chain()
    recs[0] = ev(3, 9.0, happened=0.0, ProcessGuid="{AAAA}", Initiated="true", DestinationIp="10.0.2.2", DestinationPort=80)
    assert len(fire(tmp_path, recs)) == 1                             # logged late, happened first


def test_own_tools_and_other_hosts_excluded(tmp_path):
    recs = chain()
    recs[2] = dict(recs[2], origin="project")
    assert fire(tmp_path, recs) == []
    recs = chain()
    recs[2] = dict(recs[2], host="h2")                                 # started on another computer
    assert fire(tmp_path, recs) == []


def churn(n_new=30, n_del=30, spread=50.0, guid="{AAAA}", start=0.0, host="h1"):
    out = []
    for i in range(n_new):
        out.append(ev(11, start + spread * i / max(n_new + n_del - 1, 1), host=host, ProcessGuid=guid, TargetFilename=fr"C:\AnalystLab\n{i}.txt"))
    for i in range(n_del):
        out.append(ev(26, start + spread * (n_new + i) / max(n_new + n_del - 1, 1), host=host, ProcessGuid=guid, TargetFilename=fr"C:\AnalystLab\o{i}.txt"))
    return out


def churn_alerts(tmp_path, records, **kw):
    con = sqlite3.connect(store(tmp_path, records))
    try:
        return own_rules.file_churn(con, **kw)
    finally:
        con.close()


def test_churn_fires_once_with_every_event(tmp_path):
    recs = churn()
    alerts = churn_alerts(tmp_path, recs)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_id == "analystlab.file_churn" and a.details["created"] == 30 and a.details["deleted"] == 30
    assert set(a.evidence) == {EventStore.dedup_key(r) for r in recs}
    assert a.time == "2026-10-22T10:00:50.000Z"                      # when the 30th deletion arrived


@pytest.mark.parametrize("case", [
    dict(n_new=29), dict(n_del=29),                                   # one short of either kind
    dict(spread=61.0),                                                # too slow
    dict(n_new=60, n_del=0),                                          # only creating (e.g. unzip)
])
def test_churn_near_misses(tmp_path, case):
    assert churn_alerts(tmp_path, churn(**case)) == []


def test_churn_bursts_programs_and_computers(tmp_path):
    long = churn(60, 60, spread=55.0)
    alerts = churn_alerts(tmp_path, long)
    assert len(alerts) == 1 and len(alerts[0].evidence) == 120          # one long burst, one alert
    two = churn() + churn(start=200.0)
    assert len(churn_alerts(tmp_path, two)) == 2                        # two bursts minutes apart
    split = churn(30, 0, guid="{A}") + churn(0, 30, guid="{B}")
    assert churn_alerts(tmp_path, split) == []                          # two programs, half each
    hosts = churn(30, 0) + churn(0, 30, host="h2")
    assert churn_alerts(tmp_path, hosts) == []                          # same id on two computers
    assert len(churn_alerts(tmp_path, churn(10, 10, spread=5.0), created=10, deleted=10)) == 1


def test_run_all_passes_parameters(tmp_path):
    con = sqlite3.connect(store(tmp_path, chain(t_start=40.0)))
    assert own_rules.run_all(con) and own_rules.run_all(con, {"analystlab.fetch_write_run": {"window": 30}}) == []


def test_a_later_write_by_another_program_does_not_hide_the_download(tmp_path):
    recs = chain() + [ev(11, 3.0, ProcessGuid="{DDDD}", TargetFilename=W)]     # e.g. a scanner touches it
    alerts = fire(tmp_path, recs)
    assert len(alerts) == 1 and alerts[0].evidence[1] == EventStore.dedup_key(recs[1])


@pytest.mark.parametrize("ip", ["::ffff:127.0.0.1", "::ffff:7f00:1", "0000:0000:0000:0000:0000:0000:0000:0001", "127.5.6.7"])
def test_every_loopback_spelling(tmp_path, ip):
    assert fire(tmp_path, chain(ip=ip)) == []
    assert own_rules.is_loopback(ip) and not own_rules.is_loopback("10.0.2.2") and not own_rules.is_loopback("garbage")


def test_write_to_start_boundary(tmp_path):
    # connection at the write itself: exactly 60 s from write to start is inside, 60.001 s is not
    assert len(fire(tmp_path, chain(t_conn=2.0, t_write=2.0, t_start=62.0))) == 1
    assert fire(tmp_path, chain(t_conn=2.0, t_write=2.0, t_start=62.001)) == []


def test_connection_on_another_computer_does_not_count(tmp_path):
    recs = chain()
    recs[0] = dict(recs[0], host="h2")                 # same program id, but on another machine
    assert fire(tmp_path, recs) == []


def test_churn_time_is_when_it_first_qualified(tmp_path):
    recs = churn(30, 30, spread=50.0) + churn(30, 30, spread=40.0, start=51.0)   # keeps going after qualifying
    alerts = churn_alerts(tmp_path, recs)
    assert len(alerts) == 1 and alerts[0].time == "2026-10-22T10:00:50.000Z"
    assert len(alerts[0].evidence) == 120


def test_growing_alerts_keep_one_identity(tmp_path):
    first = churn(30, 30, spread=50.0)
    small = churn_alerts(tmp_path, first)
    big = churn_alerts(tmp_path, first + churn(30, 30, spread=40.0, start=51.0))   # same events + more
    assert small[0].alert_id == big[0].alert_id and set(small[0].evidence) < set(big[0].evidence)


# --- lookalike_name (version 2, B1) ---

SVC = r"C:\Windows\System32\svchost.exe"


def started(*images, host="h1", t0=0.0):
    return [ev(1, t0 + i, host=host, ProcessGuid=f"{{P{i}}}", Image=img) for i, img in enumerate(images)]


def lookalikes(tmp_path, records, **kw):
    con = sqlite3.connect(store(tmp_path, records))
    try:
        return own_rules.lookalike_name(con, **kw)
    finally:
        con.close()


@pytest.mark.parametrize("name, ref", [
    ("scvhost.exe", "svchost"),              # two neighbours swapped (the classic, Schoenfeld 2021)
    ("svhost.exe", "svchost"),               # one letter missing
    ("svchostt.exe", "svchost"),             # one letter added
    ("svch0st.exe", "svchost"),              # one letter replaced
    ("SCVHOST.EXE", "svchost"),              # case does not matter
])
def test_one_edit_from_a_running_windows_program_fires(tmp_path, name, ref):
    recs = started(SVC, rf"C:\Users\u\AppData\Roaming\{name}")
    alerts = lookalikes(tmp_path, recs)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_id == "analystlab.lookalike_name" and a.level == "medium" and a.source == "analystlab"
    assert a.details == {"program": name.lower(), "looks_like": ref, "edits": 1}
    assert a.evidence == (EventStore.dedup_key(recs[1]),) and a.time == "2026-10-22T10:00:01.000Z"
    assert "AppData" not in a.reason and "appdata" not in a.reason      # paths stay out of the sentence


@pytest.mark.parametrize("image", [
    r"C:\Users\u\AppData\Roaming\svchost.exe",       # exact Windows name elsewhere: SigmaHQ's rules
    r"C:\Users\u\AppData\Roaming\scvhots.exe",       # two edits
    r"C:\Users\u\AppData\Roaming\notepad.exe",       # unrelated
    r"C:\Windows\System32\wbem\scvhost.exe",         # inside the Windows folder (not a writable part): not this rule
])
def test_lookalike_near_misses_do_not_fire(tmp_path, image):
    assert lookalikes(tmp_path, started(SVC, image)) == []


def test_reference_is_what_runs_on_the_same_machine(tmp_path):
    odd = r"C:\Users\u\Downloads\scvhost.exe"
    assert lookalikes(tmp_path, started(odd)) == []                             # svchost never ran here
    assert lookalikes(tmp_path, started(SVC, host="h2") + started(odd, t0=5)) == []   # it ran on another machine


def test_short_windows_names_are_not_references(tmp_path):
    recs = started(r"C:\Windows\System32\cmd.exe", r"C:\Windows\System32\lsass.exe",
                   r"C:\Users\u\cmdd.exe", r"C:\Users\u\lsas.exe")
    assert [a.details["looks_like"] for a in lookalikes(tmp_path, recs)] == ["lsass"]    # cmd has 3 letters
    assert lookalikes(tmp_path, recs, min_length=6) == []


def test_one_alert_per_program_file_at_its_first_start(tmp_path):
    odd = r"C:\Users\u\Downloads\scvhost.exe"
    recs = started(SVC, odd, odd, odd.upper())
    alerts = lookalikes(tmp_path, recs)
    assert len(alerts) == 1 and alerts[0].evidence == (EventStore.dedup_key(recs[1]),)
    again = lookalikes(tmp_path, recs + started(odd, t0=50))
    assert [a.alert_id for a in again] == [alerts[0].alert_id]                  # stable for the live loop


def test_lookalike_skips_our_tools_and_paused_rows(tmp_path):
    odd = r"C:\Users\u\Downloads\scvhost.exe"
    assert lookalikes(tmp_path, [ev(1, 0, Image=SVC), ev(1, 1, origin="project", Image=odd)]) == []
    assert lookalikes(tmp_path, [ev(1, 0, Image=SVC), ev(1, 1, paused=True, Image=odd)]) == []


def test_two_edits_when_asked(tmp_path):
    recs = started(SVC, r"C:\Users\u\scvhots.exe")
    assert lookalikes(tmp_path, recs) == []
    assert [a.details["edits"] for a in lookalikes(tmp_path, recs, edits=2)] == [2]


def test_run_all_reads_its_settings_from_the_frozen_config(tmp_path):
    from engine.config import own_rule_params
    p = dict(own_rule_params()["analystlab.lookalike_name"])
    assert len(p.pop("extra_references")) == 55                                # v3 1.7: SigmaHQ e4a6b256's list
    assert p == {"edits": 1, "min_length": 5, "level": "medium"}
    con = sqlite3.connect(store(tmp_path, started(SVC, r"C:\Users\u\scvhost.exe")))
    try:
        assert [a.rule_id for a in own_rules.run_all(con)] == ["analystlab.lookalike_name"]
    finally:
        con.close()

def test_earliest_start_is_the_evidence_whatever_the_loading_order(tmp_path):
    odd = r"C:\Users\u\Downloads\scvhost.exe"
    late, early = ev(1, 30, Image=odd), ev(1, 5, Image=odd)
    first = lookalikes(tmp_path, [ev(1, 0, Image=SVC), late])
    both = lookalikes(tmp_path, [ev(1, 0, Image=SVC), late, early])          # the earlier start arrives last
    assert both[0].evidence == (EventStore.dedup_key(early),) and both[0].time == "2026-10-22T10:00:05.000Z"
    assert first[0].alert_id == both[0].alert_id                              # still ONE alert (incident = the file)


def test_lookalike_uses_when_it_happened(tmp_path):
    odd = r"C:\Users\u\Downloads\scvhost.exe"
    a = lookalikes(tmp_path, [ev(1, 0, Image=SVC), ev(1, 40, happened=12, Image=odd)])
    assert a[0].time == "2026-10-22T10:00:12.000Z"


def test_length_filter_lets_two_deletions_through(tmp_path):
    recs = started(SVC, r"C:\Users\u\svcho.exe")                              # two letters shorter
    assert lookalikes(tmp_path, recs) == []
    assert [a.details["edits"] for a in lookalikes(tmp_path, recs, edits=2)] == [2]


def test_nearest_reference_wins(tmp_path):
    recs = started(r"C:\Windows\System32\services.exe", r"C:\Windows\System32\svchost.exe",
                   r"C:\Users\u\servicse.exe")
    a = lookalikes(tmp_path, recs, edits=2)
    assert [(x.details["looks_like"], x.details["edits"]) for x in a] == [("services", 1)]


def test_our_tools_and_paused_rows_are_not_references(tmp_path):
    odd = r"C:\Users\u\Downloads\scvhost.exe"
    assert lookalikes(tmp_path, [ev(1, 0, origin="project", Image=SVC), ev(1, 1, Image=odd)]) == []
    assert lookalikes(tmp_path, [ev(1, 0, paused=True, Image=SVC), ev(1, 1, Image=odd)]) == []


@pytest.mark.parametrize("folder", [r"C:\Windows\Temp", r"C:\Windows\Tasks", r"C:\Windows\System32\spool\drivers\color"])
def test_user_writable_windows_folders_count_as_outside(tmp_path, folder):
    assert len(lookalikes(tmp_path, started(SVC, folder + r"\scvhost.exe"))) == 1     # checked like any other
    recs = started(folder + r"\installer.exe", r"C:\Users\u\installe.exe")
    assert lookalikes(tmp_path, recs) == []                                    # and never a reference


def test_bad_rows_do_not_stop_the_rule(tmp_path):
    odd = r"C:\Users\u\Downloads\scvhost.exe"
    recs = [ev(1, 0, Image=SVC), ev(1, 1, Image=""), ev(1, 2, Image="   "), ev(1, 3, Image=odd)]
    assert len(lookalikes(tmp_path, recs)) == 1