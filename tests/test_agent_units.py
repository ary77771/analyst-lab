"""Stage 3 unit tests: parsing, origin tagging, file hashing, port diffs, atomic state."""

import hashlib
import os

from agent.enrich import OriginTagger, file_to_hash, hash_when_closed
from agent.parse import parse_event_xml
from agent.ports import diff, listening_ports
from agent.state import atomic_write_text, read_text
from tests.conftest import TCP_STATE_BROKEN

# Real structure of a classic Application event (as rendered by EvtRender).
APPLICATION_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='AnalystLabTest'/><EventID Qualifiers='0'>1000</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2026-10-16T14:10:02.1234567Z'/><EventRecordID>118040</EventRecordID><Correlation/><Execution ProcessID='0' ThreadID='0'/><Channel>Application</Channel><Computer>TEST-PC</Computer><Security/></System><EventData><Data>analyst lab write test</Data></EventData></Event>"""

# Structure of a Sysmon event with named fields (values shortened, machine-specific parts replaced).
SYSMON_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-10-16T13:56:55.4585541Z'/><EventRecordID>199</EventRecordID><Correlation/><Execution ProcessID='4321' ThreadID='1234'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>TEST-PC</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-10-16 13:56:55.457</Data><Data Name='ProcessGuid'>{11111111-2222-3333-4444-555555555555}</Data><Data Name='ProcessId'>9876</Data><Data Name='Image'>C:\\Windows\\System32\\notepad.exe</Data><Data Name='CommandLine'>notepad.exe</Data><Data Name='ParentProcessGuid'>{66666666-7777-8888-9999-000000000000}</Data><Data Name='ParentImage'>C:\\Example\\python.exe</Data><Data Name='Hashes'>SHA256=ABC123</Data><Data Name='Description'></Data></EventData></Event>"""


def test_parse_classic_event():
    e = parse_event_xml(APPLICATION_XML)
    assert e["provider"] == "AnalystLabTest"
    assert e["event_id"] == 1000
    assert e["record_id"] == 118040
    assert e["channel"] == "Application"
    assert e["time"] == "2026-10-16T14:10:02.1234567Z"
    assert e["data"]["values"] == ["analyst lab write test"]


def test_parse_sysmon_named_fields():
    e = parse_event_xml(SYSMON_XML)
    assert e["provider"] == "Microsoft-Windows-Sysmon"
    assert e["event_id"] == 1
    assert e["record_id"] == 199
    assert e["data"]["Image"] == "C:\\Windows\\System32\\notepad.exe"
    assert e["data"]["ProcessGuid"] == "{11111111-2222-3333-4444-555555555555}"
    assert e["data"]["Description"] == ""          # empty field kept, not dropped
    assert "values" not in e["data"]


def make_event(event_id, **data):
    return {"event_id": event_id, "data": data}


def test_origin_tagging(tmp_path):
    project = str(tmp_path / "project")
    t = OriginTagger(project, extra_prefixes=[r"C:\Program Files\Oracle\VirtualBox"])

    assert t.tag(make_event(1, ProcessGuid="{A}", Image=r"C:\Windows\notepad.exe", CommandLine="notepad")) == "normal"
    assert t.tag(make_event(1, ProcessGuid="{B}", Image=os.path.join(project, ".venv", "python.exe"))) == "project"
    # child of a project process is project activity, even from a system program
    assert t.tag(make_event(1, ProcessGuid="{C}", ParentProcessGuid="{B}", Image=r"C:\Windows\cmd.exe")) == "project"
    # other events by a project process
    assert t.tag(make_event(3, ProcessGuid="{C}", Image=r"C:\Windows\cmd.exe")) == "project"
    # command line pointing into the project (e.g. node running a project script)
    assert t.tag(make_event(1, ProcessGuid="{D}", Image=r"C:\Program Files\nodejs\node.exe",
                            CommandLine=f'node "{project}\\dashboard\\x.js"')) == "project"
    # VirtualBox
    assert t.tag(make_event(1, ProcessGuid="{E}", Image=r"C:\Program Files\Oracle\VirtualBox\VirtualBoxVM.exe")) == "project"
    # case-insensitive paths
    assert t.tag(make_event(1, ProcessGuid="{F}", Image=project.upper() + r"\X.EXE")) == "project"
    # git running in the project folder (program lives elsewhere; working folder is the project)
    assert t.tag(make_event(1, ProcessGuid="{G}", Image=r"C:\Users\u\scoop\apps\git\git.exe",
                            CommandLine="git status", CurrentDirectory=project + "\\")) == "project"
    # git started by git (child of project activity)
    assert t.tag(make_event(1, ProcessGuid="{H}", ParentProcessGuid="{G}", Image=r"C:\x\git.exe",
                            CurrentDirectory="C:\\")) == "project"
    # anything started by Claude, and Claude itself
    assert t.tag(make_event(1, ProcessGuid="{I}", Image=r"C:\Windows\conhost.exe",
                            ParentImage=r"C:\Users\u\AppData\Local\AnthropicClaude\claude.exe")) == "project"
    # git in some other folder, not started by project activity, stays normal
    assert t.tag(make_event(1, ProcessGuid="{J}", Image=r"C:\x\git.exe", CurrentDirectory=r"D:\other\repo")) == "normal"


def test_origin_tagging_avoids_false_positives(tmp_path):
    project = str(tmp_path / "programming project")
    t = OriginTagger(project)
    claude = r"C:\Users\u\AppData\Local\AnthropicClaude\claude.exe"

    # a sibling folder whose name merely starts with the project's name
    assert t.tag(make_event(1, ProcessGuid="{1}", Image=project + r"2\tool.exe")) == "normal"
    assert t.tag(make_event(1, ProcessGuid="{2}", Image=r"C:\x\app.exe",
                            CommandLine=f'app.exe "{project}-old\\file.txt"')) == "normal"
    # a browser opened from a link in the Claude app is normal use, and so are its children
    assert t.tag(make_event(1, ProcessGuid="{CL}", Image=claude)) == "project"
    assert t.tag(make_event(1, ProcessGuid="{BR}", ParentProcessGuid="{CL}", ParentImage=claude,
                            Image=r"C:\Program Files\Google\Chrome\chrome.exe")) == "normal"
    assert t.tag(make_event(1, ProcessGuid="{BR2}", ParentProcessGuid="{BR}",
                            Image=r"C:\Program Files\Google\Chrome\chrome.exe")) == "normal"
    # while a shell started by Claude, and its children, are project work
    assert t.tag(make_event(1, ProcessGuid="{SH}", ParentProcessGuid="{CL}", ParentImage=claude,
                            Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")) == "project"
    assert t.tag(make_event(1, ProcessGuid="{N}", ParentProcessGuid="{SH}", Image=r"C:\Windows\notepad.exe")) == "project"
    # command line pointing at the project folder itself (end of text / quote) still counts
    assert t.tag(make_event(1, ProcessGuid="{3}", Image=r"C:\x\code.exe", CommandLine=f'code "{project}"')) == "project"


def test_hash_finished_executable(tmp_path):
    path = tmp_path / "tool.exe"
    path.write_bytes(b"not really an exe")
    assert file_to_hash(make_event(11, TargetFilename=str(path))) == str(path)
    status, digest, size, final = hash_when_closed(str(path))
    assert (status, size) == ("ok", 17) and final.lower() == str(path).lower()
    assert digest == hashlib.sha256(b"not really an exe").hexdigest().upper()


def test_hash_waits_while_the_file_is_still_being_written(tmp_path):
    # The race the independent review found: Sysmon reports a new file at creation, before
    # its content is written. Hashing then would fingerprint a partial file.
    path = tmp_path / "download.exe"
    writer = open(path, "wb")
    writer.write(b"first half ")
    writer.flush()
    assert hash_when_closed(str(path)) == ("busy", None, None, None)
    writer.write(b"second half")
    writer.close()
    status, digest, size, _ = hash_when_closed(str(path))
    assert status == "ok"
    assert digest == hashlib.sha256(b"first half second half").hexdigest().upper()


def test_hash_skips_non_executables_and_handles_missing(tmp_path):
    assert file_to_hash(make_event(11, TargetFilename=str(tmp_path / "notes.txt"))) is None
    assert file_to_hash(make_event(1, TargetFilename=str(tmp_path / "x.exe"))) is None
    assert hash_when_closed(str(tmp_path / "deleted.exe")) == ("gone", None, None, None)


def test_port_diff():
    before = {("0.0.0.0", 80): 100, ("127.0.0.1", 5000): 200}
    after = {("0.0.0.0", 80): 100, ("127.0.0.1", 6000): 300}
    started, stopped = diff(before, after)
    assert started == [("127.0.0.1", 6000, 300)]
    assert stopped == [("127.0.0.1", 5000, 200)]


@TCP_STATE_BROKEN
def test_port_snapshot_sees_a_new_listener():
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    try:
        port = s.getsockname()[1]
        snap = listening_ports()
        assert ("127.0.0.1", port) in snap
        assert snap[("127.0.0.1", port)] == os.getpid()
    finally:
        s.close()


def test_atomic_write_replaces_whole_file(tmp_path):
    path = str(tmp_path / "state" / "bookmark.xml")
    atomic_write_text(path, "first")
    atomic_write_text(path, "second")
    assert read_text(path) == "second"
    assert read_text(str(tmp_path / "missing.xml")) is None
    assert [p.name for p in (tmp_path / "state").iterdir()] == ["bookmark.xml"]   # no temp files left
