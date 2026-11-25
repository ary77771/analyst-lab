"""A small hand-made event store for the night-hunt Labs tests (no real recordings).

The story on host "lab-vm" (all times UTC, newest event 2026-11-01 12:00:00):
- evil.exe runs from Downloads (no publisher), checks in to 10.0.2.2:18765 every 30 s
  (12 times), writes a Run key, listens on 0.0.0.0:4444, and is deleted by a cmd.exe it started;
- winword.exe starts powershell.exe;
- C:\\Temp\\svc.exe is certutil.exe renamed;
- a file lands in the Startup folder; schtasks.exe /create runs;
- the lab's own python.exe (origin 'project') runs from Downloads (must be left out);
- normal noise: svchost/chrome many times, notepad three days earlier;
- gaps: a start with an all-zero parent, a connection by a process whose start was never
  recorded, 5 missing Sysmon record numbers, a 2-hour silence, a Sysmon error (255), an
  unreadable event, an unreadable file fingerprint, a paused row.
"""

from datetime import datetime, timedelta, timezone

from engine.store import EventStore

SYSMON = "Microsoft-Windows-Sysmon/Operational"
HOST = "analystlab-vm"                 # the lab VM (engine.dashboard.demo_mode.VM_HOSTS)
LAPTOP = "made-up-laptop"              # another machine: shown only by a dashboard started with --labs-all-hosts
LAPTOP_PROGRAM = "C:\\Users\\someone\\Downloads\\private.exe"
ZERO = "{00000000-0000-0000-0000-000000000000}"
T_END = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)
EVIL = "C:\\Users\\analyst\\Downloads\\evil.exe"
RUN_KEY = "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"


def use_store(monkeypatch, path, hosts=(HOST,)):
    """Make `path` the running dashboard's event store, as engine/dashboard/app.py does through
    labs.Context (hosts=None = a dashboard started with --labs-all-hosts). The labs read nothing else."""
    from engine import labs
    monkeypatch.setattr(labs, "_current", labs.Context(str(path), None, hosts=hosts))
    return path


def ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond:06d}0Z"


def guid(n):
    return "{0d5356cf-0000-0000-%04x-000000000200}" % n


class Builder:
    def __init__(self):
        self.records, self.rid, self.seq = [], 0, 0

    def sysmon(self, event_id, when, origin="normal", skip=0, **data):
        self.rid += 1 + skip
        r = {"host": HOST, "label": "vm", "session": "s1", "source": "sysmon", "channel": SYSMON,
             "record_id": self.rid, "event_id": event_id, "time": ts(when), "origin": origin,
             "data": {"UtcTime": ts(when)[:23].replace("T", " "), **data}}
        self.records.append(r)
        return r

    def agent(self, typ, when, **data):
        self.seq += 1
        self.records.append({"host": HOST, "label": "vm", "session": "a1", "source": "agent", "seq": self.seq,
                             "type": typ, "time": ts(when), "origin": "normal", "data": data})

    def start(self, when, g, image, parent_g, parent_image, cmd=None, company=None, original=None, origin="normal"):
        return self.sysmon(1, when, origin=origin, ProcessGuid=g, Image=image, ParentProcessGuid=parent_g,
                           ParentImage=parent_image, CommandLine=cmd or f'"{image}"', Company=company,
                           OriginalFileName=original or image.rsplit("\\", 1)[-1])

    def connect(self, when, g, image, ip, port):
        return self.sysmon(3, when, ProcessGuid=g, Image=image, Initiated="true", DestinationIp=ip,
                           DestinationPort=port, Protocol="tcp")


def build(path, with_registry=True):
    b = Builder()
    t = T_END - timedelta(hours=3)                                     # 09:00
    b.sysmon(4, t - timedelta(minutes=1), State="Started")
    # three days earlier: notepad (outside the 24 h window)
    b.start(T_END - timedelta(days=3), guid(90), "C:\\Windows\\System32\\notepad.exe", guid(1),
            "C:\\Windows\\explorer.exe", company="Microsoft Corporation")
    # normal noise
    for i in range(20):
        b.start(t + timedelta(seconds=i), guid(200 + i), "C:\\Windows\\System32\\svchost.exe", guid(2),
                "C:\\Windows\\System32\\services.exe", company="Microsoft Corporation")
    for i in range(15):
        b.connect(t + timedelta(seconds=30 + i * 7), guid(3), "C:\\Program Files\\Google\\Chrome\\chrome.exe",
                  f"142.250.0.{i % 5 + 1}", 443)
    b.start(t + timedelta(seconds=40), guid(3), "C:\\Program Files\\Google\\Chrome\\chrome.exe", guid(1),
            "C:\\Windows\\explorer.exe", company="Google LLC")
    # the planted story
    t1 = t + timedelta(minutes=10)
    b.start(t1, guid(10), EVIL, guid(1), "C:\\Windows\\explorer.exe")             # no publisher
    for i in range(12):
        b.connect(t1 + timedelta(seconds=5 + 30 * i), guid(10), EVIL, "10.0.2.2", 18765)
    if with_registry:
        b.sysmon(13, t1 + timedelta(seconds=20), ProcessGuid=guid(10), Image=EVIL, EventType="SetValue",
                 TargetObject=RUN_KEY, Details=f'"{EVIL}" --quiet',
                 RuleName="technique_id=T1547.001,technique_name=Registry Run Keys / Startup Folder")
    b.agent("PORT_LISTEN_START", t1 + timedelta(seconds=25), Image=EVIL, ProcessId=4242, LocalIp="0.0.0.0", LocalPort=4444)
    b.agent("PORT_LISTEN_START", t1 + timedelta(seconds=26), Image="C:\\Windows\\System32\\svchost.exe", ProcessId=8,
            LocalIp="127.0.0.1", LocalPort=7680)
    b.start(t1 + timedelta(minutes=7), guid(11), "C:\\Windows\\System32\\cmd.exe", guid(10), EVIL,
            cmd=f'cmd.exe /c ping -n 2 127.0.0.1 & del "{EVIL}"', company="Microsoft Corporation", original="Cmd.Exe")
    b.sysmon(26, t1 + timedelta(minutes=7, seconds=3), ProcessGuid=guid(11), Image="C:\\Windows\\System32\\cmd.exe",
             TargetFilename=EVIL, IsExecutable="true")
    # Office starts PowerShell
    t2 = t + timedelta(minutes=30)
    b.start(t2, guid(20), "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", guid(1),
            "C:\\Windows\\explorer.exe", company="Microsoft Corporation")
    b.start(t2 + timedelta(seconds=4), guid(21), "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            guid(20), "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            cmd="powershell.exe -enc AAAA", company="Microsoft Corporation", original="PowerShell.EXE")
    # explorer starting powershell is normal: not listed
    b.start(t2 + timedelta(seconds=9), guid(22), "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            guid(1), "C:\\Windows\\explorer.exe", company="Microsoft Corporation", original="PowerShell.EXE")
    # renamed certutil
    b.start(t2 + timedelta(minutes=1), guid(30), "C:\\Temp\\svc.exe", guid(21),
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", company="Microsoft Corporation",
            original="CertUtil.exe")
    # Startup folder + scheduled task
    b.sysmon(11, t2 + timedelta(minutes=2), ProcessGuid=guid(21),
             Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
             TargetFilename="C:\\Users\\analyst\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\upd.lnk")
    b.start(t2 + timedelta(minutes=3), guid(31), "C:\\Windows\\System32\\schtasks.exe", guid(21),
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            cmd='schtasks.exe /create /tn Upd /tr "C:\\Temp\\svc.exe" /sc onlogon', company="Microsoft Corporation")
    # the lab's own program: must be left out
    b.start(t2 + timedelta(minutes=4), guid(40), "C:\\Users\\analyst\\Downloads\\python.exe", guid(1),
            "C:\\Windows\\explorer.exe", origin="project")
    # gaps
    b.start(t2 + timedelta(minutes=5), guid(50), "C:\\Windows\\System32\\lsass.exe", ZERO, None,
            company="Microsoft Corporation")
    b.connect(t2 + timedelta(minutes=6), guid(51), "C:\\Windows\\System32\\svchost.exe", "10.0.2.3", 53)
    b.sysmon(255, t2 + timedelta(minutes=7), skip=5, Description="Failed to open service configuration")
    b.records.append({"host": HOST, "label": "vm", "session": "s1", "source": "sysmon", "channel": SYSMON,
                      "record_id": b.rid + 1, "time": ts(t2 + timedelta(minutes=8)), "parse_error": "bad xml",
                      "raw_xml": "<Event>"})
    b.rid += 1
    b.agent("FILE_HASH", t2 + timedelta(minutes=8), TargetFilename="C:\\Temp\\locked.dll", hash_status="unreadable",
            ProcessGuid=guid(21))
    b.records.append({"host": HOST, "label": "vm", "session": "a1", "source": "agent", "seq": 999, "type": "PAUSED",
                      "time": ts(t2 + timedelta(minutes=9)), "paused": 1})
    # silence 09:40 -> 11:40, then the last events
    t3 = T_END - timedelta(minutes=20)
    b.start(t3, guid(60), "C:\\Windows\\System32\\svchost.exe", guid(2), "C:\\Windows\\System32\\services.exe",
            company="Microsoft Corporation")
    b.connect(T_END, guid(3), "C:\\Program Files\\Google\\Chrome\\chrome.exe", "142.250.0.1", 443)
    # another machine in the same store, its newest event a day after the VM's: never shown by default
    for i, (eid, when, data) in enumerate([
            (1, T_END - timedelta(hours=1), {"ProcessGuid": guid(500), "Image": LAPTOP_PROGRAM, "ParentProcessGuid": ZERO,
                                             "OriginalFileName": "certutil.exe", "CommandLine": "private.exe"}),
            (3, T_END - timedelta(minutes=50), {"ProcessGuid": guid(500), "Image": LAPTOP_PROGRAM, "Initiated": "true",
                                                "DestinationIp": "203.0.113.9", "DestinationPort": 443}),
            (1, T_END + timedelta(days=1), {"ProcessGuid": guid(501), "Image": "C:\\Windows\\notepad.exe",
                                            "ParentProcessGuid": guid(502)})]):
        b.records.append({"host": LAPTOP, "label": "host", "session": "l1", "source": "sysmon", "channel": SYSMON,
                          "record_id": 1 + i * 7, "event_id": eid, "time": ts(when), "origin": "normal", "data": data})
    s = EventStore(str(path))
    s.insert(b.records)
    s.close()
    return str(path)
