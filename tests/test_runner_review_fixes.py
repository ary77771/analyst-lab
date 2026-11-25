"""Tests for the independent review of the one-command VM runner (2026-10-18), the findings that
live outside tools/run_in_vm.py (those are in test_run_in_vm.py)."""

import os
import re

from agent.enrich import OriginTagger, file_to_hash
from agent.main import VIRTUALBOX_DIR
from tests.test_review3_fixes import quiet_agent

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VM_PROJECT = r"C:\LabTools"            # where the VM's agent lives = its "project" folder
RUN = "20261018-101500-0a1b"


def launcher_command_line():
    """The launcher's command line as vm_guest_setup.ps1 registers it."""
    with open(os.path.join(PROJECT_ROOT, "tools", "vm", "vm_guest_setup.ps1"), encoding="utf-8") as f:
        setup = f.read()
    folder = re.search(r"\$launcherDir = '([^']+)'", setup).group(1)
    name = re.search(r"\$launcher = Join-Path \$launcherDir '([^']+)'", setup).group(1)
    assert "-WorkingDirectory $launcherDir" in setup
    return folder, f'powershell.exe -NoProfile -File "{folder}\\{name}"'


def story(launcher_dir, command_line):
    """Sysmon events of one automated S1 run, launcher first (started by Task Scheduler)."""
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    fetch, payload = r"D:\s1\s1_fetch.exe", r"C:\AnalystLab\scenarios\s1\payload\s1_payload.exe"
    barrier = rf"C:\AnalystLab\scenarios\_runner\barrier-{RUN}-ok.txt"
    ev = lambda eid, **d: {"event_id": eid, "data": d}
    return [
        ev(1, Image=ps, ProcessGuid="{L}", ParentProcessGuid="{SVCHOST}", ParentImage=r"C:\Windows\System32\svchost.exe",
           CommandLine=command_line, CurrentDirectory=launcher_dir + "\\"),
        ev(1, Image=ps, ProcessGuid="{R}", ParentProcessGuid="{L}", ParentImage=ps,
           CommandLine=f'powershell.exe -NoProfile -File "D:\\run_scenario.ps1" -Scenario s1 -RunId {RUN}',
           CurrentDirectory=launcher_dir + "\\"),
        ev(1, Image=fetch, ProcessGuid="{F}", ParentProcessGuid="{R}", ParentImage=ps,
           CommandLine=f"{fetch} -server http://10.0.2.2:8765", CurrentDirectory=launcher_dir + "\\"),
        ev(11, Image=fetch, ProcessGuid="{F}", TargetFilename=payload),
        ev(1, Image=payload, ProcessGuid="{P}", ParentProcessGuid="{F}", ParentImage=fetch, CommandLine=payload,
           CurrentDirectory=launcher_dir + "\\"),
        ev(11, Image=ps, ProcessGuid="{L}", TargetFilename=barrier),
    ]


def tags(events):
    tagger = OriginTagger(VM_PROJECT, extra_prefixes=[VIRTUALBOX_DIR])
    return [tagger.tag(e) for e in events]


def test_automated_run_is_normal_use_so_payload_and_barrier_get_fingerprinted():
    folder, cmd = launcher_command_line()
    events = story(folder, cmd)
    assert tags(events) == ["normal"] * len(events)
    created = [e for e in events if e["event_id"] == 11]
    assert all(file_to_hash(e) for e in created)       # both new files qualify for a FILE_HASH


def test_control_a_launcher_inside_labtools_would_be_project_work():
    # the reviewed bug: this is what the first version did (proves the test above can fail)
    folder = VM_PROJECT + r"\tools"
    cmd = f'powershell.exe -NoProfile -File "{folder}\\scenario_launcher.ps1"'
    assert set(tags(story(folder, cmd))) == {"project"}


def test_file_hashes_wait_while_an_event_batch_is_unsent(tmp_path):
    a = quiet_agent(tmp_path)
    sent = []
    a.sink.write_batch = lambda records: sent.append(list(records))
    a._pending_agent = [{"type": "FILE_HASH"}]
    a._pending = (["event"], [{"record_id": 1}])      # a batch that failed to send
    a._flush_agent_records()
    assert sent == [] and len(a._pending_agent) == 1   # the hash must not overtake its event
    a._pending = None                                  # the batch went through
    a._flush_agent_records()
    assert sent == [[{"type": "FILE_HASH"}]] and a._pending_agent == []


def test_final_flush_writes_hashes_even_with_an_unsent_batch(tmp_path):
    a = quiet_agent(tmp_path)
    sent = []
    a.sink.write_batch = lambda records: sent.append(list(records))
    a._pending_agent = [{"type": "FILE_HASH"}]
    a._pending = (["event"], [{"record_id": 1}])
    a._flush_agent_records(final=True)
    assert sent == [[{"type": "FILE_HASH"}]]
