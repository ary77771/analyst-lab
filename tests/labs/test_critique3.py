"""VISION's critique-3 (2026-11-24) on night-explain's labs: the landing page's first screen is light, the first
answer isn't cryptic, and "word for word" keeps Windows' words apart from the recorder's own notes."""

from engine.labs import _triage, _wordforword, checklist

HASH = "5277F0EFBFBC90BB27768D3CD1E9F36A84DA43DB5CD6C2F4B9282B720CA94BE2"


def test_a_command_line_first_shows_its_telling_part_with_the_fingerprint_cut():
    s = checklist.short_cmd(f'"D:\\s1\\s1_fetch.exe" -server http://10.0.2.2:18765 -sha256 {HASH}')
    assert s == "-server http://10.0.2.2:18765 -sha256 5277F0EF\u2026"
    assert checklist.short_cmd(r"C:\\t\\a.exe") is None                       # nothing beyond the program: no line
    assert len(checklist.short_cmd("a.exe " + "x" * 200)) == 90
    assert checklist.short_cmd(None) is None
    assert HASH[:9] not in (checklist.short_cmd("a.exe " + HASH.lower()) or "").upper()   # cut in any case


def test_q1_says_alarm_raised_and_what_re_checked_would_mean():
    assert checklist.WORDS["status"]["raised"] == "Alarm raised" == _triage.WORDS["status"]["raised"]
    q = checklist.with_triage([], [{"key": "fired", "status": "raised", "line": "L", "lab": "why"}])[0]
    assert q["note"] == checklist.WORDS["raised_note"] and "re-check" in q["note"]
    q = checklist.with_triage([], [{"key": "fired", "status": "fact", "line": "L", "lab": "why"}])[0]
    assert q["note"] is None


def test_word_for_word_keeps_the_recorders_notes_apart_from_windows_fields():
    rec = {"host": "vm", "channel": "Microsoft-Windows-Sysmon/Operational", "provider": "Microsoft-Windows-Sysmon",
           "record_id": 12, "event_id": 1, "time": "T", "source": "sysmon", "origin": "normal", "origin_recorded": "normal",
           "session": "s", "label": "vm", "Image": r"C:\\a.exe", "UtcTime": "U", "raw_xml": "<x/>"}
    v = _wordforword.record_view("k", rec)
    windows = {k for k, _ in v["header"]} | {k for k, _ in v["fields"]}
    ours = {k for k, _ in v["notes"]}
    assert ours == {"source", "origin", "origin_recorded", "session", "label"}
    assert not ours & windows and {"Image", "UtcTime", "record_id", "provider"} <= windows and "raw_xml" not in windows
    assert v["by"] == "windows"
    assert _wordforword.record_view("k", dict(rec, source="agent", type="FILE_HASH"))["by"] == "recorder"
    assert "not from Windows" in _wordforword.WORDS["recorder_notes"]
