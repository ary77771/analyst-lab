"""v4 (found 2026-11-17 while measuring F7b): Sigma's registry_add / registry_delete categories carry an
EventType condition in SigmaHQ's own Sysmon pipeline (pySigma-pipeline-sysmon,
sysmon_generic_logsource_additional_conditions: registry_add -> EventType CreateKey; registry_delete ->
DeleteKey or DeleteValue). Ours mapped both to event 12 only, so a "key deleted" rule could fire on a key
being CREATED (event 12 holds both) and the reverse. Recorded and declared events alike."""
import pytest

from engine import detect
from tests.test_detect import ev, rules_from, store

DELETE = r"""
title: Contoso Key Removed
id: 33333333-2222-3333-4444-555555555555
logsource: {product: windows, category: registry_delete}
detection:
  sel: {TargetObject|endswith: '\Contoso\App'}
  condition: sel
level: high
"""
ADD = DELETE.replace("registry_delete", "registry_add").replace("Removed", "Added").replace("33333333", "44444444")
KEY = r"HKLM\SOFTWARE\Contoso\App"


def alerts(tmp_path, text, records, **kw):
    con = detect.open_store(store(tmp_path, records))
    try:
        return detect.detect(con, rules_from(tmp_path, text), declared=False, **kw)
    finally:
        con.close()


@pytest.mark.parametrize("event_type, delete_fires, add_fires", [
    ("CreateKey", False, True), ("DeleteKey", True, False), ("DeleteValue", True, False)])
def test_recorded_event_12_by_event_type(tmp_path, event_type, delete_fires, add_fires):
    rec = [ev(12, 0, EventType=event_type, TargetObject=KEY, Image=r"C:\x\y.exe", ProcessGuid="{g}")]
    assert len(alerts(tmp_path, DELETE, rec)) == int(delete_fires)
    assert len(alerts(tmp_path, ADD, rec)) == int(add_fires)


def test_declared_rows_follow_the_same_conditions(tmp_path):
    """A bare `reg add KEY` declares CreateKey: before the fix the DELETE rule fired on it."""
    rec = [ev(1, 0, Image=r"C:\Windows\System32\reg.exe", OriginalFileName="reg.exe", ProcessGuid="{r}",
              CommandLine=f"reg add {KEY} /f")]
    con = detect.open_store(store(tmp_path, rec))
    try:
        assert detect.detect(con, rules_from(tmp_path, DELETE), declared={"registry"}) == []
        assert len(detect.detect(con, rules_from(tmp_path, ADD, name="a.yml"), declared={"registry"})) == 1
    finally:
        con.close()


def test_the_query_carries_the_condition(tmp_path):
    (rule,) = rules_from(tmp_path, DELETE)
    assert "EventType='DeleteKey'" in rule.queries[0] and "EventType='DeleteValue'" in rule.queries[0]
    (rule,) = rules_from(tmp_path, ADD, name="a.yml")
    assert "EventType='CreateKey'" in rule.queries[0]
