"""v4 F3: tools/build_learn_store.py keeps only events 1/3/11/26 up to the given day, never overwrites."""
import json
import os
import sqlite3
import sys

import pytest

from tests.test_detect import ev

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
import build_learn_store  # noqa: E402


def test_keeps_four_event_types_up_to_the_day(tmp_path):
    vm = tmp_path / "rec" / "vm"
    vm.mkdir(parents=True)
    day1 = [ev(e, i, Image=r"C:\x\a.exe") for i, e in enumerate((1, 3, 5, 11, 13, 22, 26))]
    day2 = [ev(1, 100, Image=r"C:\x\b.exe")]
    for name, recs in (("2026-11-14.jsonl", day1), ("2026-11-15.jsonl", day2)):
        (vm / name).write_text("".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")
    out = str(tmp_path / "learn.db")
    nfiles, counts = build_learn_store.build(str(tmp_path / "rec"), "vm", "2026-11-14", out)
    assert nfiles == 1 and counts == {1: 1, 3: 1, 11: 1, 26: 1}
    con = sqlite3.connect(out)
    assert sorted(e for (e,) in con.execute("SELECT event_id FROM events")) == [1, 3, 11, 26]
    con.close()
    with pytest.raises(FileExistsError):
        build_learn_store.build(str(tmp_path / "rec"), "vm", "2026-11-14", out)
