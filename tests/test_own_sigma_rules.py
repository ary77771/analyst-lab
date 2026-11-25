"""v4: our own Sigma rules (rules/analystlab/*.yml) on hand-made records: each fires on its
behaviour and stays quiet on near misses."""
import os

from engine import detect
from tests.test_detect import ev, store

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CMD, PING = r"C:\Windows\System32\cmd.exe", r"C:\Windows\System32\PING.EXE"


def own_alerts(tmp_path, records, rule_id):
    rules, _, failures = detect.load_rules([os.path.join(ROOT, "rules", "analystlab")], "analystlab")
    assert not failures, failures
    rules = [r for r in rules if r.rule_id == rule_id]
    assert len(rules) == 1, f"{rule_id} not loaded"
    con = detect.open_store(store(tmp_path, records))
    try:
        return detect.detect(con, rules)
    finally:
        con.close()


def ping(cl, parent_cl, parent=CMD, s=0):
    return ev(1, s, Image=PING, CommandLine=cl, ParentImage=parent, ParentCommandLine=parent_cl)


def test_ping_delay_chained(tmp_path):
    chained = 'cmd.exe /c "ping -n 31 127.0.0.1 >nul & start "" C:\\x\\stage2.exe --resume"'
    hits = [ping("ping  -n 31 127.0.0.1", chained, s=0),
            ping("PING.EXE /n 5 localhost", 'cmd /c ping /n 5 localhost & del x.exe', s=1),
            ping('ping 127.0.0.1 -n 9', 'cmd /c ping 127.0.0.1 -n 9 >nul || run.exe', s=6),          # count after, ||
            ping('ping -n 9 "127.0.0.1"', 'cmd /c ping -n 9 "127.0.0.1" && run.exe', s=7)]          # quoted address
    misses = [ping("ping -n 31 127.0.0.1", 'cmd.exe /c "C:\\scripts\\wait.bat"', s=2),           # a batch "sleep": no chain
              ping("ping -n 4 10.0.2.2", 'cmd /c ping -n 4 10.0.2.2 & echo done', s=3),         # a real network test
              ping("ping 127.0.0.1", 'cmd /c ping 127.0.0.1 & echo x', s=4),                     # no count
              ping("ping -n 31 127.0.0.1", "powershell -c ping -n 31 127.0.0.1; x",
                   parent=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", s=5)]     # not cmd
    alerts = own_alerts(tmp_path, hits + misses, "analystlab.ping_delay_chained")
    from engine.store import EventStore
    assert sorted(k for a in alerts for k in a.evidence) == sorted(EventStore.dedup_key(r) for r in hits)
    assert {a.level for a in alerts} == {"medium"}
