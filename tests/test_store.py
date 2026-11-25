"""Stage 4: event store and loader."""

import json

from engine.load import load_files
from engine.store import SYSMON_FIELDS, EventStore


def sysmon(record_id, time, event_id=1, host="PC", session="s1", **data):
    return {"host": host, "label": "host", "session": session, "source": "sysmon",
            "channel": "Microsoft-Windows-Sysmon/Operational", "record_id": record_id,
            "event_id": event_id, "provider": "Microsoft-Windows-Sysmon", "time": time,
            "origin": "normal", "data": data}


def test_schema_has_flat_sysmon_columns(tmp_path):
    store = EventStore(str(tmp_path / "t.db"))
    for field in SYSMON_FIELDS + ["time", "event_id", "origin", "parse_error", "raw_xml"]:
        assert store.columns[field.lower()] == field


def test_fields_land_in_their_own_columns(tmp_path):
    store = EventStore(str(tmp_path / "t.db"))
    store.insert([sysmon(1, "2026-10-16T14:00:00.0000000Z", Image=r"C:\Windows\notepad.exe",
                         ProcessGuid="{A}", ParentImage=r"C:\Windows\explorer.exe")])
    row = store.db.execute('SELECT Image, ProcessGuid, ParentImage, event_id FROM events').fetchone()
    assert row == (r"C:\Windows\notepad.exe", "{A}", r"C:\Windows\explorer.exe", 1)


def test_redelivered_event_is_a_duplicate_even_from_a_new_session(tmp_path):
    store = EventStore(str(tmp_path / "t.db"))
    first = sysmon(42, "2026-10-16T14:00:00.1000000Z", session="s1", Image="a.exe")
    again = sysmon(42, "2026-10-16T14:00:00.1000000Z", session="s2", Image="a.exe")
    assert store.insert([first]) == (1, 0)
    assert store.insert([again]) == (0, 1)
    assert store.count() == 1


def test_snapshot_rewind_same_record_number_different_time_kept(tmp_path):
    store = EventStore(str(tmp_path / "t.db"))
    run1 = sysmon(500, "2026-10-20T10:00:00.0000000Z", host="VM", session="run1")
    run2 = sysmon(500, "2026-10-20T11:30:00.0000000Z", host="VM", session="run2")
    assert store.insert([run1, run2]) == (2, 0)


def test_agent_events_dedup_by_session_and_seq(tmp_path):
    store = EventStore(str(tmp_path / "t.db"))
    port = {"host": "PC", "session": "s1", "source": "agent", "seq": 1, "type": "PORT_LISTEN_START",
            "time": "2026-10-16T14:00:00Z", "origin": "normal",
            "data": {"LocalIp": "127.0.0.1", "LocalPort": 5000, "ProcessId": 10, "Image": "x.exe"}}
    assert store.insert([port, dict(port)]) == (1, 1)
    # port and process-id columns are NUMERIC (so range comparisons work); other fields are TEXT
    assert store.db.execute("SELECT type, LocalPort, LocalIp FROM events").fetchone() == ("PORT_LISTEN_START", 5000, "127.0.0.1")


def test_unknown_field_becomes_a_new_column(tmp_path):
    store = EventStore(str(tmp_path / "t.db"))
    store.insert([sysmon(1, "2026-10-16T14:00:00Z", BrandNewField="x")])
    assert store.db.execute('SELECT "BrandNewField" FROM events').fetchone() == ("x",)


def file_hash_record(seq=1, time="2026-10-16T14:00:05.0000000Z", size=2490368):
    # exactly the shape agent/main.py _process_hash_queue emits
    return {"host": "PC", "label": "vm", "session": "s1", "source": "agent", "seq": seq,
            "type": "FILE_HASH", "time": time, "origin": "normal",
            "data": {"TargetFilename": r"C:\AnalystLab\scenarios\s1\payload\s1_payload.exe",
                     "ProcessGuid": "{F}", "hash_status": "ok", "sha256": "AB12", "size": size,
                     "ref_record_id": 7, "ref_time": "2026-10-16T14:00:00.0000000Z"}}


def test_file_hash_record_lands_in_typed_columns(tmp_path):
    store = EventStore(str(tmp_path / "t.db"))
    store.insert([file_hash_record()])
    row = store.db.execute("SELECT type, TargetFilename, hash_status, sha256, size, ref_record_id "
                           "FROM events").fetchone()
    assert row == ("FILE_HASH", r"C:\AnalystLab\scenarios\s1\payload\s1_payload.exe", "ok", "AB12", 2490368, 7)
    assert store.count("size > 1000") == 1                  # numeric, not text
    assert store.count("ref_record_id = 7") == 1


def test_agent_records_with_same_seq_but_different_time_are_both_kept(tmp_path):
    # a live VM snapshot restored with the agent running replays the same session + seq numbers
    store = EventStore(str(tmp_path / "t.db"))
    assert store.insert([file_hash_record(time="2026-10-20T10:00:00.0000000Z"),
                         file_hash_record(time="2026-10-20T11:30:00.0000000Z")]) == (2, 0)
    assert store.insert([file_hash_record(time="2026-10-20T10:00:00.0000000Z")]) == (0, 1)


def test_list_values_are_stored_as_text(tmp_path):
    store = EventStore(str(tmp_path / "t.db"))
    rec2 = {"host": "PC", "source": "windows", "channel": "Application", "record_id": 9,
            "event_id": 1000, "time": "2026-10-16T14:00:00Z", "origin": "normal",
            "data": {"values": ["one", "two"]}}
    store.insert([rec2])
    assert store.db.execute('SELECT "values" FROM events WHERE record_id=9').fetchone() == ("['one', 'two']",)


def test_loader_reads_jsonl_and_reports_duplicates(tmp_path):
    path = tmp_path / "2026-10-16.jsonl"
    rows = [sysmon(i, f"2026-10-16T14:00:{i:02d}Z", Image=f"p{i}.exe") for i in range(10)]
    rows.append(rows[3])                                   # a re-delivered line
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")

    store = EventStore(str(tmp_path / "t.db"))
    totals = load_files(store, [str(path)], batch_size=4)
    assert {k: v for k, v in totals.items() if k != "retagged"} == {"read": 11, "inserted": 10, "duplicates": 1, "bad_lines": 0}
    # loading the same file again inserts nothing
    assert load_files(store, [str(path)])["inserted"] == 0


def test_field_names_that_differ_only_in_case_do_not_crash(tmp_path):
    store = EventStore(str(tmp_path / "t.db"))
    # Sysmon error events carry an "ID" field (clashes with our id column); "Time"/"Type" clash
    # with core columns; "image" vs "Image" is the same SQLite column name.
    store.insert([sysmon(1, "2026-10-16T14:00:00Z", event_id=255, ID="x", Time="t", Type="y")])
    store.insert([sysmon(2, "2026-10-16T14:00:01Z", image="lower.exe")])
    store.insert([sysmon(3, "2026-10-16T14:00:02Z", Foo="a", foo="b")])
    assert store.count() == 3
    assert store.db.execute('SELECT data_ID, data_Time, data_Type FROM events WHERE record_id=1').fetchone() == ("x", "t", "y")
    assert store.db.execute('SELECT Image FROM events WHERE record_id=2').fetchone() == ("lower.exe",)
    assert store.db.execute('SELECT Foo, dup_foo FROM events WHERE record_id=3').fetchone() == ("a", "b")


def test_unreadable_events_are_all_kept_with_their_error(tmp_path):
    store = EventStore(str(tmp_path / "t.db"))
    bad = [{"host": "PC", "session": "s1", "source": "sysmon", "channel": "c", "record_id": None,
            "event_id": None, "time": None, "origin": "normal", "data": {},
            "parse_error": f"ValueError: broken {i}", "raw_xml": None} for i in range(3)]
    assert store.insert(bad) == (3, 0)
    assert store.insert([dict(bad[0])]) == (0, 1)          # the same one re-delivered
    assert store.db.execute("SELECT COUNT(*) FROM events WHERE parse_error LIKE 'ValueError%'").fetchone() == (3,)


def test_numeric_fields_compare_as_numbers(tmp_path):
    store = EventStore(str(tmp_path / "t.db"))
    store.insert([sysmon(1, "2026-10-16T14:00:00Z", event_id=3, DestinationPort="8080"),
                  sysmon(2, "2026-10-16T14:00:01Z", event_id=3, DestinationPort="443")])
    q = lambda where: [r[0] for r in store.db.execute(f"SELECT record_id FROM events WHERE {where} ORDER BY record_id")]
    assert q("DestinationPort > 900") == [1]                 # as text, '443' > '900' would be wrong
    assert q("DestinationPort = 443") == [2]
    assert q("DestinationPort = '443'") == [2]               # Sigma may compare with a string


def test_loader_skips_a_partial_line(tmp_path):
    path = tmp_path / "2026-10-16.jsonl"
    path.write_text(json.dumps(sysmon(1, "2026-10-16T14:00:00Z")) + '\n{"half": \n'
                    + json.dumps(sysmon(2, "2026-10-16T14:00:01Z")) + "\n", encoding="utf-8")
    totals = load_files(EventStore(str(tmp_path / "t.db")), [str(path)])
    assert {k: v for k, v in totals.items() if k != "retagged"} == {"read": 2, "inserted": 2, "duplicates": 0, "bad_lines": 1}


def test_loader_survives_a_utf8_character_cut_by_a_crash(tmp_path):
    # e.g. an Arabic folder name cut in the middle of a 2-byte character
    good1 = json.dumps(sysmon(1, "2026-10-16T14:00:00Z", TargetFilename="C:\\بيانات\\a.exe"), ensure_ascii=False)
    good2 = json.dumps(sysmon(2, "2026-10-16T14:00:01Z"), ensure_ascii=False)
    cut = good1.encode("utf-8")[: good1.encode("utf-8").index("بيانات".encode("utf-8")) + 1]
    path = tmp_path / "2026-10-16.jsonl"
    path.write_bytes(good1.encode("utf-8") + b"\n" + cut + b"\n" + good2.encode("utf-8") + b"\n")
    totals = load_files(EventStore(str(tmp_path / "t.db")), [str(path)])
    assert totals["inserted"] == 2 and totals["bad_lines"] == 1


def test_indexes_exist(tmp_path):
    store = EventStore(str(tmp_path / "t.db"))
    names = {r[1] for r in store.db.execute("PRAGMA index_list(events)")}
    assert {"idx_events_time", "idx_events_ProcessGuid", "idx_events_TargetFilename"} <= names
