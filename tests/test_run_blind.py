"""tools/run_blind.py (blind scenarios B1/B2) with a DUMMY blind folder made here and a fake VirtualBox
(no VM): the run CD's content, blindness (nothing printed or written into the project names the
blind programs or the answer sheet before the flush barrier), the sheet copied and the checkers
called with --sheet only after it, the safety refusals, official mode, and the checkers' --sheet
giving the same result as their default sheet on our own S1 (golden). The VM side's
tools/vm/run_scenario.ps1 is run for real (powershell.exe, -ResolveOnly: it only prints what it
would start) against a run CD built by run_blind.build_cd and a fake S1 CD, and its scenario.json
rules are compared with the laptop's on the same cases (parity)."""

import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from types import SimpleNamespace

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
import run_blind  # noqa: E402
from engine.evaluation import FREEZE_TAG as _FREEZE_TAG  # noqa: E402
import run_series  # noqa: E402
from tests.test_run_in_vm import FAST, FakeVBox, append  # noqa: E402

EXE_BYTES = b"MZ fake program bytes, never run"


def make_blind(root, sid="B1", exe="bin\\zq_secretprog.exe", out="C:\\AnalystLab\\scenarios\\b1\\work",
               args=("-server", "http://10.0.2.2:18765/")):
    """A dummy blind folder: a fake program (a unique, 'secret' name), a helper file, a source file
    and an answer sheet carrying a secret marker. Returns (folder, marker, program name)."""
    marker = "SECRET-" + uuid.uuid4().hex
    prog = f"zq_{uuid.uuid4().hex[:10]}.exe"
    exe = exe.replace("zq_secretprog.exe", prog)
    folder = root / "AnalystLab-blind" / sid.lower()
    (folder / "bin" / "data").mkdir(parents=True)
    (folder / "src").mkdir()
    (folder / exe.replace("\\", os.sep)).parent.mkdir(parents=True, exist_ok=True)
    (folder / exe.replace("\\", os.sep)).write_bytes(EXE_BYTES)
    (folder / "bin" / "data" / "helper.txt").write_text("helper", encoding="ascii")
    (folder / "src" / "main.go").write_text(f"// {marker} source of {prog}\n", encoding="utf-8")
    (folder / "ground_truth.yaml").write_text(
        f"# {marker}\nscenario: {sid}\ntitle: {marker}\nprograms:\n  main: {prog}\nsteps: []\n", encoding="utf-8")
    (folder / "scenario.json").write_text(json.dumps(
        {"id": sid, "title": f"title {marker}", "exe": exe, "args": list(args), "out": out}), encoding="utf-8")
    return folder, marker, prog


@pytest.fixture
def lab(tmp_path, monkeypatch):
    """A fake project (holding the recordings) and a staging folder, both separate from the blind folder."""
    project = tmp_path / "project"
    (project / "recordings").mkdir(parents=True)
    monkeypatch.setattr(run_blind, "PROJECT_ROOT", str(project))
    return {"project": project, "recordings": project / "recordings", "stage": tmp_path / "stage", "tmp": tmp_path}


def files_text(folder):
    """Every file under `folder` as (path, bytes)."""
    out = []
    for dirpath, _, names in os.walk(folder):
        for n in names:
            p = os.path.join(dirpath, n)
            with open(p, "rb") as f:
                out.append((p, f.read()))
    return out


def leaks(folder, *secrets):
    """Files under `folder` whose path or content contains any secret."""
    return [p for p, data in files_text(folder)
            if any(s.lower() in p.lower() or s.encode() in data for s in secrets)]


class WatchedVBox(FakeVBox):
    """The fake VM; just before it 'runs' (sends the run record and the barrier) a hook looks at
    everything printed and written so far."""

    def __init__(self, recordings, before_run, **kw):
        super().__init__(recordings, **kw)
        self.before_run = before_run

    def start(self, headless=False):
        self.before_run()
        super().start(headless)


def make_runner(lab, folder, label="practice", tools=None, **fake_kw):
    rec = str(lab["recordings"])
    blind = run_blind.validate(str(folder), str(lab["stage"]))
    said = []
    calls = tools if tools is not None else []

    def run_tool(tool, args):
        calls.append((tool, list(args), r.sheet_copy))
        return 0

    fake = WatchedVBox(rec, fake_kw.pop("before_run", lambda: None), **fake_kw)
    r = run_blind.BlindRunner(blind, label=label, stage_root=str(lab["stage"]), run_tool=run_tool, vbox=fake,
                              recordings=rec, servers=lambda: (0, "ok"), timeouts=FAST, poll=0.01, say=said.append)
    fake.run_id = r.run_id
    return r, fake, said, calls


def summary(lab, run_id):
    with open(lab["recordings"] / "scenario_runs" / f"{run_id}.json", encoding="utf-8") as f:
        return json.load(f)


# (a) the run CD ---------------------------------------------------------------------------------
def test_cd_carries_the_programs_and_the_generic_entry_but_never_the_sheet_or_sources(lab):
    folder, marker, prog = make_blind(lab["tmp"])
    blind = run_blind.validate(str(folder), str(lab["stage"]))
    rid = "20261030-120000-abcd"
    m = run_blind.cd_content_map(blind, rid, str(lab["stage"]))
    assert m[f"/blind/b1/bin/{prog}"] == os.path.join(str(folder), "bin", prog)
    assert "/blind/b1/bin/data/helper.txt" in m
    for k in ("/AUTORUN_SCENARIO.txt", "/scenario_launcher.ps1", "/run_scenario.ps1", "/blind/b1/scenario.json"):
        assert k in m and os.path.isfile(m[k])
    assert not any("ground_truth" in k or "/src/" in k for k in m)
    with open(m["/AUTORUN_SCENARIO.txt"], encoding="ascii") as f:
        assert f.read().split() == ["scenario=b1", f"run_id={rid}"]
    with open(m["/blind/b1/scenario.json"], encoding="ascii") as f:
        sj = json.load(f)
    assert sj == {"exe": f"bin\\{prog}", "args": ["-server", "http://10.0.2.2:18765/"],
                  "out": "C:\\AnalystLab\\scenarios\\b1\\work"}          # title (and anything else) left out

    code, out = run_blind.build_cd(blind, rid, str(lab["stage"]))
    assert code == 0 and prog not in out
    with open(lab["stage"] / "cd" / "blind" / "b1" / "bin" / prog, "rb") as f:
        assert f.read() == EXE_BYTES                                     # a frozen copy, not a link
    viso = (lab["stage"] / run_blind.VISO_NAME).read_text(encoding="ascii")
    assert viso.startswith("--iprt-iso-maker-file-marker-bourne-sh ") and f"'/blind/b1/bin/{prog}=" in viso
    assert str(lab["stage"] / "cd") in viso and str(folder) not in viso   # points at the frozen copies
    assert not leaks(lab["stage"], marker)                                # the sheet never reaches the CD


def test_vm_scripts_know_blind_ids_and_the_generic_entry():
    with open(os.path.join(PROJECT_ROOT, "tools", "vm", "scenario_launcher.ps1"), encoding="utf-8") as f:
        launcher = f.read()
    assert "'^[scb]\\d+[a-z]?$'" in launcher and "'^([scb]\\d+[a-z]?):" in launcher
    with open(os.path.join(PROJECT_ROOT, "tools", "vm", "run_scenario.ps1"), encoding="utf-8") as f:
        rs = f.read()
    assert "'^b[1-9][0-9]?$'" in rs and "blind\\$s" in rs and "'scenario.json'" in rs
    for text in (launcher, rs):
        assert "Bypass" not in text                       # the VM has RemoteSigned now (2026-10-24)


# (b) + (c) blindness and the sheet after the barrier -------------------------------------------
def test_nothing_secret_before_the_barrier_then_sheet_copied_and_checked_with_sheet(lab):
    folder, marker, prog = make_blind(lab["tmp"])
    seen = {}

    def look(when):                                      # everything printed and written so far
        seen[when] = {"said": list(said), "blind_dir": (lab["recordings"] / "blind").exists(),
                      "leaks": leaks(lab["project"], marker, prog) + leaks(os.path.join(PROJECT_ROOT, "build"), marker, prog)}

    r, fake, said, calls = make_runner(lab, folder, before_run=lambda: look("vm start"))
    real_on_barrier = r.on_barrier
    r.on_barrier = lambda item: (look("barrier"), real_on_barrier(item))   # the moment the barrier is taken
    assert r.run() == 0
    for when in ("vm start", "barrier"):                 # up to the barrier: nothing secret anywhere
        assert seen[when]["leaks"] == [] and seen[when]["blind_dir"] is False, when
        assert not any(marker in s or prog in s for s in seen[when]["said"]), when
    assert len(seen["barrier"]["said"]) > len(seen["vm start"]["said"])
    assert seen["vm start"]["said"][0].startswith("Scenario B1 · run id ")
    assert not any(marker in s for s in said)            # the runner itself never prints the sheet
    assert fake.calls[1] == ("insert_cd", run_blind.VISO_NAME)            # the blind CD, outside the project
    assert r.run_cd == os.path.join(str(lab["stage"]), run_blind.VISO_NAME)

    sheet = lab["recordings"] / "blind" / "b1" / r.run_id / "ground_truth.yaml"
    assert sheet.read_bytes() == (folder / "ground_truth.yaml").read_bytes()
    assert [c[0] for c in calls] == ["check_scenario.py", "check_graph_scenario.py", "check_alerts.py"]
    for tool, args, copy in calls:
        assert args[:3] == ["b1", "--run-id", r.run_id]
        assert args[args.index("--sheet") + 1] == str(sheet) and copy == str(sheet)
        assert args[args.index("--recordings") + 1] == str(lab["recordings"])
    s = summary(lab, r.run_id)
    assert s["result"] == "PASS" and s["label"] == "practice" and s["detection"] == "NONE EXPECTED"
    b = s["blind"]
    assert b["sheet_opened_utc"] >= b["barrier_arrived_utc"]
    assert b["sheet_copy"].replace("\\", "/") == f"blind/b1/{r.run_id}/ground_truth.yaml" and len(b["sheet_sha256"]) == 64
    assert b["first_opened"] == {"first_opened_utc": b["sheet_opened_utc"], "run_id": r.run_id,
                                 "barrier_arrived_utc": b["barrier_arrived_utc"], "sheet_sha256": b["sheet_sha256"]}
    assert b["run_cd"]["files"] == 6 and len(b["run_cd"]["sha256"]) == 64
    assert prog not in json.dumps(s)


def test_first_opened_record_is_write_once(lab):
    folder, _, _ = make_blind(lab["tmp"])
    r1, *_ = make_runner(lab, folder)
    assert r1.run() == 0
    record = lab["recordings"] / "blind" / "b1" / "first_opened.json"
    before = record.read_bytes()
    r2, *_ = make_runner(lab, folder)
    assert r2.run() == 0
    assert record.read_bytes() == before                                  # the second run didn't overwrite it
    s1, s2 = summary(lab, r1.run_id)["blind"], summary(lab, r2.run_id)["blind"]
    assert s2["first_opened"]["run_id"] == r1.run_id and s2["sheet_opened_utc"] > s1["sheet_opened_utc"]


def test_barrier_found_in_the_recovery_path_is_noted_before_the_sheet(lab):
    """run_in_vm's recovery path (a step failed, but the record and barrier did arrive) also calls
    on_barrier, so barrier_arrived_utc exists and precedes sheet_opened_utc."""
    folder, _, _ = make_blind(lab["tmp"])
    r, fake, said, calls = make_runner(lab, folder, barrier=None)

    def failing_collect(runs, vm, item=None, first=True):
        r._guest_progress()                              # picks up the run record
        append(str(lab["recordings"]), "vm", {"type": "FILE_HASH", "data": {
            "TargetFilename": rf"C:\AnalystLab\scenarios\_runner\barrier-{r.run_id}-ok.txt"}})
        raise run_blind.StepFailed("timed out (simulated) just as the barrier came in")
    r.collect = failing_collect
    assert r.run() == 3                                  # still a failed VM step
    b = summary(lab, r.run_id)["blind"]
    assert [c[0] for c in calls] == ["check_scenario.py", "check_graph_scenario.py", "check_alerts.py"]
    assert b["barrier_arrived_utc"] <= b["sheet_opened_utc"]


def test_failed_run_never_opens_the_sheet_and_writes_nothing_secret(lab):
    folder, marker, prog = make_blind(lab["tmp"])
    r, fake, said, calls = make_runner(lab, folder, barrier=None)     # the barrier never arrives
    assert r.run() == 3
    assert calls == [] and not (lab["recordings"] / "blind").exists()
    assert "sheet_opened_utc" not in summary(lab, r.run_id)["blind"]
    assert leaks(lab["project"], marker, prog) == [] and not any(marker in s or prog in s for s in said)


def test_not_started_writes_nothing_secret(lab):
    folder, marker, prog = make_blind(lab["tmp"])
    r, fake, said, calls = make_runner(lab, folder, state="running")
    assert r.run() == 2 and fake.calls == [] and calls == []
    assert leaks(lab["project"], marker, prog) == []


def test_sheet_is_not_opened_without_run_record_and_barrier(lab):
    folder, _, _ = make_blind(lab["tmp"])
    r, *_ = make_runner(lab, folder)
    with pytest.raises(run_blind.StepFailed):
        r.open_sheet()
    r.items[0]["run_record"] = {}
    with pytest.raises(run_blind.StepFailed):
        r.open_sheet()
    assert not (lab["recordings"] / "blind").exists()


def test_detection_outcome_from_the_copied_sheet(lab):
    folder, _, _ = make_blind(lab["tmp"])
    with open(folder / "ground_truth.yaml", "a", encoding="utf-8") as f:
        f.write("alert_expected:\n  check:\n    - {rule_id: x, level: high, involves: main}\n")
    r, fake, said, calls = make_runner(lab, folder)
    r.run_tool = lambda tool, args: 1 if tool == "check_alerts.py" else 0
    assert r.run() == 0 and summary(lab, r.run_id)["detection"] == "MISSED"


# (d) refusals -------------------------------------------------------------------------------------
def refused(lab, folder, match):
    with pytest.raises(run_blind.Refused, match=match):
        run_blind.validate(str(folder), str(lab["stage"]))


def test_folder_inside_the_project_is_refused(lab):
    folder, _, _ = make_blind(lab["project"])
    refused(lab, folder, "inside the project")


def test_real_project_and_main_checkout_count_as_the_project(monkeypatch):
    monkeypatch.setattr(run_blind, "PROJECT_ROOT", PROJECT_ROOT)
    roots = [os.path.normcase(os.path.realpath(r)) for r in run_blind.project_roots()]
    assert os.path.normcase(os.path.realpath(PROJECT_ROOT)) in roots
    if os.sep + os.path.join(".claude", "worktrees") + os.sep in PROJECT_ROOT:   # a worktree: the main checkout too
        main = PROJECT_ROOT.split(os.sep + os.path.join(".claude", "worktrees") + os.sep)[0]
        assert os.path.normcase(os.path.realpath(main)) in roots


def test_staging_inside_the_project_is_refused(lab):
    folder, _, _ = make_blind(lab["tmp"])
    with pytest.raises(run_blind.Refused, match="staging"):
        run_blind.validate(str(folder), str(lab["project"] / "build"))


def set_json(folder, **kw):
    sj = json.loads((folder / "scenario.json").read_text(encoding="utf-8"))
    sj.update(kw)
    (folder / "scenario.json").write_text(json.dumps(sj), encoding="utf-8")


def fresh(lab):
    return make_blind(lab["tmp"] / uuid.uuid4().hex[:6])


def test_exe_outside_the_folder_or_bin_is_refused(lab):
    (lab["tmp"] / "elsewhere.exe").write_bytes(b"x")
    for exe in ("..\\..\\elsewhere.exe", str(lab["tmp"] / "elsewhere.exe"), "C:elsewhere.exe", "bin\\missing.exe",
                "bin\\..\\..\\elsewhere.exe", "helper.exe", "bin/zq.exe", "", 5):
        folder, _, _ = fresh(lab)
        (folder / "helper.exe").write_bytes(b"x")                      # a real file, but not under bin\
        set_json(folder, exe=exe)
        refused(lab, folder, "exe")


# the sheet and the sources must not reach the CD under another name (review 2026-10-30)
ALIASES = ["ground_truth.yaml", "ground_truth.yaml.", "ground_truth.yaml::$DATA", "GROUND~1.YAM", "src\\main.go",
           "src.\\main.go", "bin\\..\\ground_truth.yaml", "bin\\..\\src\\main.go", "bin\\x.exe.", "bin\\x.exe ",
           "bin\\ x.exe", "bin\\.x", "bin\\x*.exe", "bin\\x?.exe", "bin\\x[1].exe", "bin\\a:b.exe", "bin\\a~1.exe",
           "bin\\\\x.exe", "bin\\", "bin\\x'.exe", "bin\\x=y.exe", "bin\\x..exe", "bin\\K.exe", "bin\\café.exe",
           "bin\\x.exe\n"]


@pytest.mark.parametrize("exe", ALIASES)
def test_exe_aliases_of_the_sheet_or_sources_are_refused(lab, exe):
    folder, _, _ = fresh(lab)
    set_json(folder, exe=exe)
    refused(lab, folder, "exe")


def test_hard_link_to_the_sheet_or_a_source_is_refused(lab):
    for target in ("ground_truth.yaml", os.path.join("src", "main.go"), "scenario.json"):
        folder, _, _ = fresh(lab)
        os.link(folder / target, folder / "bin" / "innocent.txt")
        refused(lab, folder, "under another name")


def test_junctions_under_bin_are_refused(lab):
    import _winapi
    for target in ("src", ".", "outside"):
        folder, _, _ = fresh(lab)
        dest = lab["tmp"] / "outside" if target == "outside" else folder / target
        dest.mkdir(exist_ok=True)
        _winapi.CreateJunction(str(dest), str(folder / "bin" / "j"))  # no admin needed
        refused(lab, folder, "links or junctions")
    folder, _, _ = fresh(lab)                                         # bin\ itself a junction
    os.rename(folder / "bin", folder / "realbin")
    _winapi.CreateJunction(str(folder / "realbin"), str(folder / "bin"))
    refused(lab, folder, "real bin")


def test_odd_names_under_bin_are_refused(lab):
    for name in ("a~1.txt", "x.", "x ", "it's.txt", "a=b.txt", "caf\u00e9.txt"):
        folder, _, _ = fresh(lab)
        try:
            (folder / "bin" / name).write_bytes(b"x")
        except OSError:
            continue
        if not any(n == name for n in os.listdir(folder / "bin")):   # Windows dropped the trailing . or space
            continue
        refused(lab, folder, "names under bin")


def test_cd_file_caps(lab, monkeypatch):
    folder, _, _ = fresh(lab)
    for i in range(run_blind.MAX_CD_FILES):
        (folder / "bin" / "data" / f"f{i}.txt").write_bytes(b"x")
    refused(lab, folder, "at most 100 files")
    folder, _, _ = fresh(lab)
    monkeypatch.setattr(run_blind, "MAX_CD_BYTES", 10)
    refused(lab, folder, "at most")


def test_oversize_file_is_refused_without_naming_it(lab):
    folder, _, prog = make_blind(lab["tmp"])
    with open(folder / "bin" / prog, "r+b") as f:
        f.truncate(run_blind.MAX_BYTES + 1)              # sparse: no 50 MB written
    with pytest.raises(run_blind.Refused, match="larger than 50 MB") as e:
        run_blind.validate(str(folder), str(lab["stage"]))
    assert prog not in str(e.value)


def test_unreadable_folder_is_refused_without_a_path(lab, monkeypatch):
    folder, _, prog = make_blind(lab["tmp"])
    real_stat = os.stat

    def stat(p, *a, **k):
        if prog in str(p):
            raise PermissionError(13, "denied", str(p))
        return real_stat(p, *a, **k)
    monkeypatch.setattr(run_blind.os, "stat", stat)
    with pytest.raises(run_blind.Refused, match="could not read") as e:
        run_blind.validate(str(folder), str(lab["stage"]))
    assert prog not in str(e.value) and str(folder) not in str(e.value)
    monkeypatch.undo()
    with pytest.raises(run_blind.Refused, match="could not read everything"):
        list(run_blind._walk(str(lab["tmp"] / "no-such-dir")))       # os.walk would skip it silently


def test_files_are_checked_again_when_the_cd_is_built(lab):
    folder, _, prog = make_blind(lab["tmp"])
    blind = run_blind.validate(str(folder), str(lab["stage"]))
    os.remove(folder / "bin" / prog)
    os.link(folder / "ground_truth.yaml", folder / "bin" / prog)         # swapped for the sheet after validate
    code, out = run_blind.build_cd(blind, "20261030-120000-abcd", str(lab["stage"]))
    assert code == 1 and "another name" in out and prog not in out
    assert not (lab["stage"] / run_blind.VISO_NAME).exists()
    folder, _, prog = fresh(lab)
    blind = run_blind.validate(str(folder), str(lab["stage"]))
    with open(folder / "bin" / prog, "r+b") as f:
        f.truncate(run_blind.MAX_BYTES + 1)                               # grew after validate
    code, out = run_blind.build_cd(blind, "20261030-120000-abcd", str(lab["stage"]))
    assert code == 1 and "50 MB" in out and prog not in out


@pytest.mark.parametrize("sid", ["S1", "B0", "B100", "B01", "b", "X1", 1, None])
def test_bad_id_is_refused(lab, sid):
    folder, _, _ = make_blind(lab["tmp"])
    set_json(folder, id=sid)
    refused(lab, folder, "B1..B99")


BAD_OUT = ["C:\\Users", "C:\\AnalystLab\\scenarios\\b2\\work", "C:\\AnalystLab\\scenarios\\b1\\",
           "C:\\AnalystLab\\scenarios\\b1", "C:\\AnalystLab\\scenarios\\b1\\..\\..\\x", "C:\\AnalystLab\\scenarios\\b1\\\\x",
           "C:\\AnalystLab\\scenarios\\b1\\w*", "C:\\AnalystLab\\scenarios\\b1\\w?", "C:\\AnalystLab\\scenarios\\b1\\[w]",
           "C:\\AnalystLab\\scenarios\\b1\\a:b", "C:\\AnalystLab\\scenarios\\b1\\work.", "C:\\AnalystLab\\scenarios\\b1\\work\\",
           "C:\\AnalystLab\\scenarios\\b1\\x..y", "C:/AnalystLab/scenarios/b1/work", "D:\\AnalystLab\\scenarios\\b1\\w",
           "C:\\AnalystLab\\scenarios\\b1\\\u212a", "C:\\AnalystLab\\scenarios\\b1\\w\n", 5]
GOOD_OUT = [None, "C:\\AnalystLab\\scenarios\\b1\\work", "c:\\analystlab\\scenarios\\b1\\work\\sub dir"]


def test_out_folder_must_be_the_scenarios_own(lab):
    for out in BAD_OUT:
        folder, _, _ = fresh(lab)
        set_json(folder, out=out)
        refused(lab, folder, "out")
    for out in GOOD_OUT:
        folder, _, _ = fresh(lab)
        set_json(folder, out=out)
        assert run_blind.validate(str(folder), str(lab["stage"])).out == out


BAD_ARGS = [[""], ['say "hi"'], ["b c\\"], ["tab\there\\"], ["caf\u00e9"], ["a\nb"], [5], "not a list", [None]]
GOOD_ARGS = [[], None, ["-a", "b c", "C:\\x\\", "http://10.0.2.2:18765/"]]


def test_args_powershell_would_change_are_refused(lab):
    for args in BAD_ARGS:
        folder, _, _ = fresh(lab)
        set_json(folder, args=args)
        refused(lab, folder, "args")
    for args in GOOD_ARGS:
        folder, _, _ = fresh(lab)
        set_json(folder, args=args)
        assert run_blind.validate(str(folder), str(lab["stage"])).args == (args or [])


def test_folder_containing_the_project_is_refused(lab):
    refused(lab, lab["tmp"], "contains it")


def test_project_roots_fail_closed_without_git(monkeypatch):
    wt = os.path.join("C:\\", "x", "proj", ".claude", "worktrees", "wt1")
    monkeypatch.setattr(run_blind, "PROJECT_ROOT", wt)

    def no_git(*a, **k):
        raise OSError("git not found")
    monkeypatch.setattr(run_blind.subprocess, "run", no_git)
    assert run_blind.project_roots() == [wt, os.path.join("C:\\", "x", "proj")]


def test_missing_parts_are_refused(lab):
    folder, _, _ = make_blind(lab["tmp"] / "a")
    (folder / "scenario.json").unlink()
    refused(lab, folder, "scenario.json is missing")
    folder, _, _ = make_blind(lab["tmp"] / "b")
    (folder / "ground_truth.yaml").unlink()
    refused(lab, folder, "answer sheet")
    folder, _, _ = make_blind(lab["tmp"] / "c")
    (folder / "scenario.json").write_text("{not json", encoding="utf-8")
    refused(lab, folder, "not valid JSON")
    refused(lab, lab["tmp"] / "nope", "no such folder")


def test_main_refuses_with_exit_2_and_touches_nothing(lab, monkeypatch, capsys):
    folder, marker, prog = make_blind(lab["project"])                # inside the (fake) project
    monkeypatch.setattr(run_blind, "BlindRunner", lambda *a, **k: pytest.fail("must not run"))
    assert run_blind.main([str(folder)]) == 2
    out = capsys.readouterr().out
    assert "REFUSED" in out and marker not in out and prog not in out


# (f) official mode --------------------------------------------------------------------------------
def test_official_needs_the_freeze_tag(lab, monkeypatch, capsys):
    folder, _, _ = make_blind(lab["tmp"])
    monkeypatch.setattr(run_blind, "STAGE_ROOT", str(lab["stage"]))
    started = []
    monkeypatch.setattr(run_blind, "BlindRunner", lambda blind, **k: started.append(k) or type("R", (), {"run": lambda s: 0})())
    monkeypatch.setattr(run_blind, "has_freeze_tag", lambda: False)
    assert run_blind.main([str(folder), "--label", "official"]) == 2 and started == []
    assert _FREEZE_TAG in capsys.readouterr().out
    monkeypatch.setenv("ANALYSTLAB_OFFICIAL", "1")                     # the env alone means official too
    assert run_blind.main([str(folder)]) == 2 and started == []
    assert run_blind.main([str(folder), "--label", "practice"]) == 2   # a contradiction is refused
    monkeypatch.setattr(run_blind, "has_freeze_tag", lambda: True)
    assert run_blind.main([str(folder)]) == 0 and started[-1]["label"] == "official"
    monkeypatch.delenv("ANALYSTLAB_OFFICIAL")
    assert run_blind.main([str(folder)]) == 0 and started[-1]["label"] == "practice"


def test_official_label_reaches_the_summary_and_the_checkers(lab, monkeypatch):
    folder, _, _ = make_blind(lab["tmp"])
    r, *_ = make_runner(lab, folder, label="official")
    assert r.run() == 0 and summary(lab, r.run_id)["label"] == "official"
    assert summary(lab, r.run_id)["freeze"] == _FREEZE_TAG   # each version's runs stay apart
    p, *_ = make_runner(lab, folder, label="practice")
    assert p.run() == 0 and "freeze" not in summary(lab, p.run_id)


def test_dry_run_builds_the_cd_only(lab, monkeypatch, capsys):
    folder, marker, prog = make_blind(lab["tmp"])
    monkeypatch.setattr(run_blind, "STAGE_ROOT", str(lab["stage"]))
    monkeypatch.setattr(run_blind, "BlindRunner", lambda *a, **k: pytest.fail("must not run"))
    assert run_blind.main([str(folder), "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "B1" in out and marker not in out and prog not in out
    assert (lab["stage"] / run_blind.VISO_NAME).exists()


def test_stage_folder_setting_moves_the_cd_but_never_into_the_project(lab, monkeypatch, tmp_path):
    import importlib
    elsewhere = tmp_path / "shared-stage"
    monkeypatch.setenv("ANALYSTLAB_BLIND_STAGE", str(elsewhere))
    try:
        mod = importlib.reload(run_blind)
        assert mod.STAGE_ROOT == str(elsewhere)
        folder, _, _ = make_blind(lab["tmp"])
        assert mod.main([str(folder), "--dry-run"]) == 0
        assert (elsewhere / mod.VISO_NAME).exists()
        monkeypatch.setenv("ANALYSTLAB_BLIND_STAGE", os.path.join(mod.PROJECT_ROOT, "build", "blind-cd"))
        mod = importlib.reload(run_blind)
        with pytest.raises(mod.Refused):
            mod._validate(str(folder), mod.STAGE_ROOT)
    finally:
        monkeypatch.delenv("ANALYSTLAB_BLIND_STAGE")
        importlib.reload(run_blind)


# run_series: blind items ------------------------------------------------------------------------
def test_series_runs_blind_items_with_run_blind_and_the_label(lab):
    folder, marker, prog = make_blind(lab["tmp"])
    item = f"blind:{folder}"
    base = [sys.executable, "-u", os.path.join("x", "tools", "run_in_vm.py"), "--recordings", "R", "--headless"]
    cmd = run_series.item_cmd(base, item, "official")
    assert cmd[2] == os.path.join("x", "tools", "run_blind.py") and cmd[3:] == ["--recordings", "R", "--headless",
                                                                             "--label", "official", str(folder)]
    assert run_series.item_cmd(base, "s1", "official") == base + ["s1"]           # our scenarios: unchanged
    assert run_series.name(item) == "B1" and run_series.name("s2j") == "S2J"
    assert run_series.plan([item, "S1"], 2, seed=3).count(item) == 2              # path case kept


# (e) golden: --sheet with our own sheet = the default ------------------------------------------
def _strip(out):
    return re.sub(r"\(\d[\d,]* min ago\)", "", re.sub(r"\(\d+\.\d s\)", "", out))


def test_check_scenario_sheet_override_is_golden(tmp_path, capsys):
    import check_scenario
    from tests.test_check_scenario import good_run, run_record
    for label, rows in (("vm", good_run()), ("vmruns", [run_record()])):
        (tmp_path / label).mkdir()
        (tmp_path / label / "2026-10-17.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    sheet = os.path.join(PROJECT_ROOT, "scenarios", "s1", "ground_truth.yaml")
    a = check_scenario.main(["s1", "--recordings", str(tmp_path)]), capsys.readouterr().out
    b = check_scenario.main(["s1", "--recordings", str(tmp_path), "--sheet", sheet]), capsys.readouterr().out
    assert a[0] == 0 and (a[0], _strip(a[1])) == (b[0], _strip(b[1]))
    # and the override is really used: another sheet changes the result
    other = tmp_path / "other.yaml"
    other.write_text("scenario: S1\ntitle: other\nprograms:\n  main: nothing.exe\nsteps: []\n", encoding="utf-8")
    assert check_scenario.main(["s1", "--recordings", str(tmp_path), "--sheet", str(other)]) == 1


def test_check_graph_scenario_sheet_override_is_golden(tmp_path, capsys):
    import check_graph_scenario
    from tests.test_check_graph_scenario import good_run, iso, pool_file
    for label, rows in (("vm", good_run()), ("vmruns", [{"type": "SCENARIO_RUN", "scenario": "S1", "exit_code": 0,
                                                         "time": iso(0), "start": iso(0), "end": iso(20)}])):
        (tmp_path / label).mkdir()
        (tmp_path / label / "2026-10-17.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    pool_file(tmp_path)
    sheet = os.path.join(PROJECT_ROOT, "scenarios", "s1", "ground_truth.yaml")
    a = check_graph_scenario.main(["s1", "--recordings", str(tmp_path)]), capsys.readouterr().out
    b = check_graph_scenario.main(["s1", "--recordings", str(tmp_path), "--sheet", sheet]), capsys.readouterr().out
    assert a[0] == 0 and (a[0], _strip(a[1])) == (b[0], _strip(b[1]))
    other = tmp_path / "other.yaml"
    other.write_text("scenario: S1\ntitle: other\nprograms:\n  main: nothing.exe\nsteps: []\n"
                     "expected_graph:\n  facts:\n    - {from: main, edge: connected, to: test_server, says: x}\n  gaps: []\n",
                     encoding="utf-8")
    assert check_graph_scenario.main(["s1", "--recordings", str(tmp_path), "--sheet", str(other)]) == 1


def test_check_alerts_sheet_override_is_golden(tmp_path, capsys, monkeypatch):
    import check_alerts
    from tests.test_check_graph_scenario import good_run, iso
    for label, rows in (("vm", good_run()), ("vmruns", [{"type": "SCENARIO_RUN", "scenario": "S1", "exit_code": 0,
                                                         "time": iso(0), "start": iso(0), "end": iso(20)}])):
        (tmp_path / label).mkdir()
        (tmp_path / label / "2026-10-17.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    monkeypatch.setattr(check_alerts.score, "load_rules", lambda: [])        # no detectors: the sheet is what's tested
    monkeypatch.setattr(check_alerts.score, "load_baseline", lambda: None)
    sheet = os.path.join(PROJECT_ROOT, "scenarios", "s1", "ground_truth.yaml")
    a = check_alerts.main(["s1", "--recordings", str(tmp_path)]), capsys.readouterr().out
    b = check_alerts.main(["s1", "--recordings", str(tmp_path), "--sheet", sheet]), capsys.readouterr().out
    assert a == b and "DETECTION:" in a[1]
    none = tmp_path / "none.yaml"
    none.write_text("scenario: S1\ntitle: none\nprograms:\n  main: s1_fetch.exe\n", encoding="utf-8")
    code = check_alerts.main(["s1", "--recordings", str(tmp_path), "--sheet", str(none)])
    assert code == 0 and "DETECTION: NONE EXPECTED" in capsys.readouterr().out
    assert check_alerts.main(["s1", "--recordings", str(tmp_path), "--sheet", str(tmp_path / "missing.yaml")]) == 2


# the VM side for real: tools/vm/run_scenario.ps1 -ResolveOnly in powershell.exe -------------------
POWERSHELL = shutil.which("powershell.exe")
needs_ps = pytest.mark.skipif(POWERSHELL is None, reason="needs Windows PowerShell")


def ps_resolve(cd, scenario):
    p = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-File", os.path.join(str(cd), "run_scenario.ps1"),
                        "-Scenario", scenario, "-ResolveOnly"], capture_output=True, text=True, timeout=120)
    return p.returncode, p.stdout.strip()


@needs_ps
def test_vm_side_resolves_the_blind_entry_from_the_real_run_cd(lab):
    """Review 2026-10-30 (critical): run_scenario.ps1 built its WHOLE table first, and the s1 row
    read s1\\payload.sha256, which a blind CD lacks: every blind run would have failed."""
    folder, _, prog = make_blind(lab["tmp"], args=("-server", "http://10.0.2.2:18765/", "b c", "C:\\x\\"))
    blind = run_blind.validate(str(folder), str(lab["stage"]))
    assert run_blind.build_cd(blind, "20261030-120000-abcd", str(lab["stage"]))[0] == 0
    cd = lab["stage"] / "cd"
    assert not (cd / "s1").exists()                                        # a blind CD carries no S1 files
    code, out = ps_resolve(cd, "b1")
    assert code == 0, out
    assert json.loads(out) == {"exe": f"blind\\b1\\bin\\{prog}", "out": "C:\\AnalystLab\\scenarios\\b1\\work",
                               "args": ["-server", "http://10.0.2.2:18765/", "b c", "C:\\x\\"], "hold": None}
    code, out = ps_resolve(cd, "s3")                                       # other rows don't need their files
    assert code == 0 and json.loads(out)["exe"] == "s3\\s3_listen.exe"
    code, out = ps_resolve(cd, "b2")                                       # no blind\b2 on this CD
    assert code == 2 and out.startswith("REFUSED")
    code, out = ps_resolve(cd, "s9")
    assert code == 2 and "Unknown scenario" in out


@needs_ps
def test_vm_side_resolves_our_scenarios_as_before(tmp_path):
    cd = tmp_path / "cd"
    (cd / "s1").mkdir(parents=True)
    shutil.copy(os.path.join(PROJECT_ROOT, "tools", "vm", "run_scenario.ps1"), cd / "run_scenario.ps1")
    (cd / "s1" / "payload.sha256").write_text("ABC123", encoding="ascii")
    code, out = ps_resolve(cd, "s1")
    assert code == 0 and json.loads(out) == {"exe": "s1\\s1_fetch.exe", "out": "C:\\AnalystLab\\scenarios\\s1\\payload",
                                             "args": ["-server", "http://10.0.2.2:18765", "-sha256", "ABC123"], "hold": None}
    code, out = ps_resolve(cd, "S2J")
    assert code == 0 and json.loads(out)["args"][-4:] == ["-jitter", "0.4", "-seed", "7"]
    code, out = ps_resolve(cd, "s0")
    assert code == 0 and json.loads(out) == {"exe": None, "out": None, "args": [], "hold": 600}
    code, out = ps_resolve(cd, "s4")
    assert code == 0 and json.loads(out)["args"] == ["-script", str(cd / "s4" / "s4_note.ps1")]


PARITY_DRIVER = r"""
param($cd, $cases, $outFile)
$res = @()
foreach ($c in (Get-Content $cases -Raw | ConvertFrom-Json)) {
    [IO.File]::WriteAllText((Join-Path $cd 'blind\b1\scenario.json'), $c.json)
    $global:LASTEXITCODE = 0
    try { $o = & (Join-Path $cd 'run_scenario.ps1') -Scenario b1 -ResolveOnly; $code = $LASTEXITCODE }
    catch { $o = "$_"; $code = 99 }
    $res += [pscustomobject]@{ code = $code; out = (@($o) -join ' ') }
}
ConvertTo-Json -InputObject $res -Depth 3 | Set-Content $outFile -Encoding utf8
"""


@needs_ps
def test_laptop_and_vm_apply_the_same_scenario_json_rules(lab):
    """Every exe/out/args case: the laptop's json_rules accepts it exactly when the VM's
    run_scenario.ps1 does (with the named file present on the CD wherever Windows can make it)."""
    cd = lab["tmp"] / "cd"
    (cd / "blind" / "b1" / "bin").mkdir(parents=True)
    shutil.copy(os.path.join(PROJECT_ROOT, "tools", "vm", "run_scenario.ps1"), cd / "run_scenario.ps1")
    good = {"id": "B1", "exe": "bin\\p.exe", "args": [], "out": None}
    cases = ([dict(good, exe=e) for e in ALIASES + ["bin\\p.exe", "bin\\sub dir\\p-2_x.exe", "BIN\\P.EXE", "bin/p.exe"]]
             + [dict(good, out=o) for o in BAD_OUT + GOOD_OUT]
             + [dict(good, args=a) for a in BAD_ARGS + GOOD_ARGS])
    for c in cases:                                      # the program file, where it can exist
        e = c["exe"]
        if isinstance(e, str) and e.lower().startswith("bin\\") and ".." not in e and ":" not in e:
            try:
                p = cd / "blind" / "b1" / e
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b"x")
            except OSError:
                pass
    case_file, out_file, driver = lab["tmp"] / "cases.json", lab["tmp"] / "results.json", lab["tmp"] / "driver.ps1"
    case_file.write_text(json.dumps([{"json": json.dumps(c)} for c in cases]), encoding="ascii")
    driver.write_text(PARITY_DRIVER, encoding="ascii")
    p = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-File", str(driver), str(cd), str(case_file),
                        str(out_file)], capture_output=True, text=True, timeout=300)
    assert p.returncode == 0, p.stdout + p.stderr
    results = json.loads(out_file.read_text(encoding="utf-8-sig"))
    assert len(results) == len(cases)
    assert {r["code"] for r in results} == {0, 2}                        # refused cleanly, never a crash
    assert all(r["out"].startswith("REFUSED") for r in results if r["code"] == 2)
    mismatches = []
    for c, r in zip(cases, results):
        try:
            run_blind.json_rules(c)
            laptop = True
        except run_blind.Refused:
            laptop = False
        vm = r["code"] == 0
        if vm and json.loads(r["out"])["exe"] != "blind\\b1\\" + c["exe"]:
            vm = "wrong exe"
        if laptop is not vm:
            mismatches.append((c, laptop, r))
    assert mismatches == []
    assert sum(r["code"] == 0 for r in results) == 4 + len(GOOD_OUT) + len(GOOD_ARGS) - 1   # bin/p.exe: both refuse


# official mode reaches the checker processes ------------------------------------------------------
def test_official_env_reaches_the_checker_processes(lab, monkeypatch):
    folder, _, _ = make_blind(lab["tmp"])
    blind = run_blind.validate(str(folder), str(lab["stage"]))
    seen = []
    monkeypatch.setattr(run_blind.subprocess, "run", lambda cmd, env=None, **k: seen.append((cmd, env)) or
                        SimpleNamespace(returncode=0))
    for label in ("official", "practice"):
        r = run_blind.BlindRunner(blind, label=label, stage_root=str(lab["stage"]), vbox=FakeVBox(str(lab["recordings"])),
                                  recordings=str(lab["recordings"]), say=lambda m: None)
        assert r.run_tool("check_scenario.py", ["b1", "--sheet", "x"]) == 0
    (cmd, env), (_, env2) = seen
    assert cmd[0] == sys.executable and cmd[1].endswith(os.path.join("tools", "check_scenario.py"))
    assert env["ANALYSTLAB_OFFICIAL"] == "1"
    assert env2 is None and "ANALYSTLAB_OFFICIAL" not in os.environ      # practice: inherits, and it isn't set


def test_the_snapshot_option_reaches_the_runner(lab, monkeypatch):
    """Blind round 4 runs on the 'lived-in' snapshot (docs/plans/lived-in-vm.md); default stays 'clean'."""
    folder, _, _ = make_blind(lab["tmp"])
    monkeypatch.setattr(run_blind, "STAGE_ROOT", str(lab["stage"]))
    monkeypatch.delenv("ANALYSTLAB_OFFICIAL", raising=False)
    started = []
    monkeypatch.setattr(run_blind, "BlindRunner", lambda blind, **k: started.append(k) or type("R", (), {"run": lambda s: 0})())
    assert run_blind.main([str(folder)]) == 0 and started[-1]["snapshot"] == "clean"
    assert run_blind.main([str(folder), "--snapshot", "lived-in"]) == 0 and started[-1]["snapshot"] == "lived-in"