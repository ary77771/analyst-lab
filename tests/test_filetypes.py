"""The shared file-type list (agent/filetypes.py) must say exactly what the Sysmon config says."""

import os
import xml.etree.ElementTree as ET

from agent.filetypes import KEEP_EXTENSIONS, KEEP_FOLDERS, is_recorded, should_hash

CONFIG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "tools", "sysmon", "sysmon-config.xml")


def config_rules(event_tag):
    root = ET.parse(CONFIG).getroot()
    ends, contains = set(), set()
    for el in root.iter(event_tag):
        assert el.get("onmatch") == "include"
        for rule in el:
            assert rule.tag == "TargetFilename"
            (ends if rule.get("condition") == "end with" else contains).add(rule.text.lower())
    return ends, contains


def test_config_and_module_agree_for_file_create_and_delete():
    for tag in ("FileCreate", "FileDeleteDetected"):
        ends, contains = config_rules(tag)
        assert ends == {e.lower() for e in KEEP_EXTENSIONS}, tag
        assert contains == {f.lower() for f in KEEP_FOLDERS}, tag


def test_is_recorded_and_should_hash():
    assert is_recorded(r"C:\x\tool.EXE") and should_hash(r"C:\x\tool.EXE")
    assert is_recorded(r"C:\Users\u\Downloads\report.pdf") and not should_hash(r"C:\Users\u\Downloads\report.pdf")
    assert is_recorded(r"C:\AnalystLab\s5\file.txt") and should_hash(r"C:\AnalystLab\s5\file.txt")
    assert not is_recorded(r"C:\Temp\notes.txt") and not should_hash(r"C:\Temp\notes.txt")
    # every extension the config records is also fingerprinted (the review found 8 that weren't)
    for ext in KEEP_EXTENSIONS:
        assert should_hash(r"C:\anywhere\x" + ext), ext
