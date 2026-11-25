"""tools/friend_stats.py: plain-words health verdict per friend's statistics file, refusal of edited
files, and the combined table from each friend's newest file."""

import json
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
import friend_stats  # noqa: E402
from statusapp import stats  # noqa: E402


def summary(hours=12.0, days=3, starts=4800, conns=36000, records=900000, missing=0, passed=True, sessions=3):
    s = stats.summarize({})
    s.update(days_recorded=days, active_hours=hours)
    s["events"] = {"process starts": starts, "network connections": conns}
    s["events_per_active_hour"] = {k: round(v / hours, 1) for k, v in s["events"].items()}
    s["health"].update(sysmon_records=records, sysmon_records_missing=missing, recorder_sessions=sessions)
    s["self_test"] = {"runs": 1, "last_passed": passed}
    return s


def write(folder, name, s, made="2026-10-21"):
    os.makedirs(folder, exist_ok=True)
    p = os.path.join(folder, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(stats.export_text(s, made))
    return p


def test_a_healthy_laptop_is_ok(tmp_path, capsys):
    write(tmp_path / "ali", "a.txt", summary())
    assert friend_stats.main(["--root", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "[OK] ali" in out and "This laptop records properly." in out


def test_a_failed_self_test_is_a_problem_with_advice(tmp_path, capsys):
    write(tmp_path / "ali", "a.txt", summary(passed=False))
    assert friend_stats.main(["--root", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "[PROBLEM] ali" in out and "self-test FAILED" in out and "tell them:" in out


def test_lost_events_are_judged_by_their_share(tmp_path, capsys):
    write(tmp_path / "big", "a.txt", summary(missing=5000))        # 0.56 %: lost data
    write(tmp_path / "small", "a.txt", summary(missing=3))          # a restart's worth
    assert friend_stats.main(["--root", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "[PROBLEM] big" in out and "[NOTE] small" in out


def test_no_program_starts_means_the_setup_is_wrong(tmp_path, capsys):
    s = summary()
    s["events"] = {"network connections": 100}
    s["events_per_active_hour"] = {"network connections": 8.3}
    write(tmp_path / "x", "a.txt", s)
    assert friend_stats.main(["--root", str(tmp_path)]) == 1
    assert "no program starts recorded" in capsys.readouterr().out


def test_an_edited_file_is_refused(tmp_path, capsys):
    p = write(tmp_path / "ali", "a.txt", summary())
    text = open(p, encoding="utf-8").read().replace('"process starts"', '"chrome.exe"')
    open(p, "w", encoding="utf-8").write(text)
    assert friend_stats.main(["--root", str(tmp_path)]) == 1
    assert "[REFUSED] ali" in capsys.readouterr().out


def test_the_combined_table_uses_each_friends_newest_file(tmp_path, capsys):
    write(tmp_path / "ali", "day1.txt", summary(hours=2.0, days=1, starts=800), made="2026-10-21")
    write(tmp_path / "ali", "day7.txt", summary(hours=20.0, days=7, starts=8000), made="2026-10-27")
    write(tmp_path / "sara", "day7.txt", summary(hours=10.0, days=7, starts=2000), made="2026-10-27")
    assert friend_stats.main(["--root", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    together = next(l for l in out.splitlines() if l.startswith("together"))
    assert "30.0" in together and "333.3" in together                 # (8000 + 2000) / 30 h
    assert "Active hours so far: 30.0 of the 75 planned (40 %)" in out


def test_no_files_says_where_to_put_them(tmp_path, capsys):
    assert friend_stats.main(["--root", str(tmp_path)]) == 1
    assert "Put each friend's files in" in capsys.readouterr().out


def test_with_one_friend_together_equals_that_friend(tmp_path, capsys):
    s = summary(hours=37.4, starts=42024)       # rate 1123.6 from exact hours; the file rounds hours
    s["events_per_active_hour"]["process starts"] = 1123.6
    write(tmp_path / "solo", "a.txt", s)
    friend_stats.main(["--root", str(tmp_path)])
    lines = capsys.readouterr().out.splitlines()
    solo = next(l for l in lines if l.startswith("solo"))
    together = next(l for l in lines if l.startswith("together"))
    assert "1,123.6" in solo and "1,123.6" in together


# -- review 2026-10-20 ------------------------------------------------------------------------------
def test_a_file_without_a_date_never_counts_as_newest(tmp_path, capsys):
    p = write(tmp_path / "ali", "day1.txt", summary(hours=2.0, days=1))
    open(p, "w", encoding="utf-8").write(open(p, encoding="utf-8").read().replace("Made on: 2026-10-21", "Made on: ?"))
    write(tmp_path / "ali", "day7.txt", summary(hours=20.0, days=7), made="2026-10-27")
    friend_stats.main(["--root", str(tmp_path)])
    ali = next(l for l in capsys.readouterr().out.splitlines() if l.startswith("ali "))
    assert " 20.0" in ali


def test_on_the_same_day_the_file_with_more_recording_wins(tmp_path, capsys):
    write(tmp_path / "ali", "b-morning.txt", summary(hours=20.0, days=7), made="2026-10-27")
    write(tmp_path / "ali", "z-evening-copy.txt", summary(hours=2.0, days=1), made="2026-10-27")
    friend_stats.main(["--root", str(tmp_path)])
    ali = next(l for l in capsys.readouterr().out.splitlines() if l.startswith("ali "))
    assert " 20.0" in ali


def test_same_named_exports_of_two_friends_stay_two_friends(tmp_path, capsys):
    # every export is called AnalystLab-statistics-<date>.txt
    a = write(tmp_path / "elsewhere" / "ali", "AnalystLab-statistics-2026-10-27.txt", summary(hours=10.0))
    b = write(tmp_path / "elsewhere" / "sara", "AnalystLab-statistics-2026-10-27.txt", summary(hours=30.0))
    friend_stats.main([a, b, "--root", str(tmp_path / "friends")])
    out = capsys.readouterr().out
    assert "Active hours so far: 40.0" in out


def test_friend_option_names_loose_files(tmp_path, capsys):
    a = write(tmp_path, "AnalystLab-statistics-2026-10-21.txt", summary(hours=2.0, days=1), made="2026-10-21")
    b = write(tmp_path, "AnalystLab-statistics-2026-10-27.txt", summary(hours=20.0, days=7), made="2026-10-27")
    friend_stats.main([a, b, "--friend", "omar", "--root", str(tmp_path / "friends")])
    out = capsys.readouterr().out
    assert "[OK] omar" in out and "Active hours so far: 20.0" in out     # one friend, newest file
