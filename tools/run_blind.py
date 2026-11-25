"""Run a BLIND scenario (written by someone else, kept outside the project) in the lab VM exactly
like our own scenarios, without anyone seeing its answer sheet before the run (DESIGN 6.1/6.2,
docs/blind/README.md).

    python tools/run_blind.py C:\\Users\\<you>\\Documents\\AnalystLab-blind\\b1
    python tools/run_blind.py <folder> --headless --label official   # an official run (needs freeze-v2)
    python tools/run_blind.py <folder> --dry-run                     # only the folder checks + run CD, no VM

The folder (docs/blind/README.md): ground_truth.yaml, scenario.json {"id","title","exe","args",
"out"}, bin\\... (the programs), src\\... (sources, never used here).

What it does:
  1. Refuses (exit 2, nothing touched) unless: the folder is outside the project folder and doesn't
     contain it (also the main checkout when this is a git worktree), scenario.json is there with
     an id B1..B99, its exe is bin\\<name> (plain names: letters, digits, _ - . space; no '..', ':'
     or '~', no part ending in '.' or space), its args are non-empty strings without double quotes
     (PowerShell 5.1 would drop or change them), its out is null or a folder under
     C:\\AnalystLab\\scenarios\\<id>\\, no file is larger than 50 MB, bin\\ holds real files only (no
     links or junctions, none that is the answer sheet, scenario.json or a source under another
     name; at most 100 files / 100 MB), and ground_truth.yaml exists (checked, NOT opened).
     The VM's run_scenario.ps1 checks scenario.json again with the same rules.
     `--label official` (or ANALYSTLAB_OFFICIAL=1) also needs the current freeze tag (freeze-v2).
  2. Builds a run CD OUTSIDE the project (%LOCALAPPDATA%\\AnalystLabBlindCD\\, or the folder in
     ANALYSTLAB_BLIND_STAGE: one VirtualBox can see): frozen copies of
     the folder's bin\\ (each file checked again as it is copied), a sanitized
     blind\\<id>\\scenario.json (exe, args, out only), the VM's launcher and run_scenario.ps1 and the
     run note. Never the answer sheet or the sources. Nothing from the blind folder is ever
     executed on the laptop.
  3. Runs it like tools/run_in_vm.py (same Runner): restore 'clean' -> boot 1 vCPU -> the VM's
     logon starter runs the launcher from the CD -> run_scenario.ps1's generic blind entry starts
     the program as the normal VM user -> run record + flush barrier -> checks -> shutdown.
  4. Only once the run record AND the flush barrier have arrived, copies ground_truth.yaml to
     recordings/blind/<id>/<run id>/ground_truth.yaml (git-ignored) and runs check_scenario.py,
     check_graph_scenario.py and check_alerts.py with --sheet <that copy>.
Before step 4 it prints only the scenario id, the run id, counts and the VM's progress, and writes
nothing that names the blind programs into the project. The summary (recordings/scenario_runs/
<run id>.json) adds "label" and "blind": the folder, barrier_arrived_utc, sheet_opened_utc (this
run), sheet_sha256, first_opened (from the write-once recordings/blind/<id>/first_opened.json: the
first time any run opened this id's sheet) and the run CD's file count, size and SHA-256.
Exit codes as tools/run_in_vm.py: 0 PASS · 1 check FAIL · 2 not started / refused · 3 VM step failed.

Honest limit: Claude's tools could technically read any file on this laptop; nothing technical
stops that. The protection is the process (the folder lives outside the project, nobody asks
Claude to open it) plus the record of when the sheet was first opened by this runner.
That record only covers this runner's own opening.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import uuid

import yaml

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
import run_in_vm  # noqa: E402
from run_in_vm import DETECTION, NotStarted, Runner, StepFailed, utc_now  # noqa: E402

VM_SCRIPTS = os.path.join(PROJECT_ROOT, "tools", "vm")      # the VM-side launcher and run_scenario.ps1
MAX_BYTES = 50 * 1024 * 1024             # per file in the blind folder
MAX_CD_BYTES = 100 * 1024 * 1024         # all of the blind files on the run CD together
MAX_CD_FILES = 100
BLIND_ID = re.compile(r"^[Bb][1-9][0-9]?$")      # B1..B99 (v3: round 3 uses B10 onwards)
# ANALYSTLAB_BLIND_STAGE moves the staging folder (still refused inside the project): Claude's shell is
# sandboxed, and its writes to %LOCALAPPDATA% stay invisible to VirtualBox ("Could not find file for
# the medium", dummy blind run 2026-10-30); a folder both sides see works.
STAGE_ROOT = os.environ.get("ANALYSTLAB_BLIND_STAGE") or \
    os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "AnalystLabBlindCD")
VISO_NAME = "analystlab-blind-run.viso"
SHEET = "ground_truth.yaml"
CHECKERS = ("check_scenario.py", "check_graph_scenario.py")
WORKTREES = os.sep + os.path.join(".claude", "worktrees") + os.sep

# The SAME rules as the VM's tools/vm/run_scenario.ps1 (it checks scenario.json again):
# one path part: letters, digits, _ - . and space, never starting with . or space, never ending in
# . or space (so no 8.3 aliases with ~, no ':' streams, no "name." aliases, no wildcards, no quotes)
PART = r"[A-Za-z0-9_\-](?:[A-Za-z0-9_.\- ]*[A-Za-z0-9_\-])?"
PART_RE = re.compile(PART)
EXE_RE = re.compile(rf"bin(?:\\{PART})+", re.I)              # fullmatch; '..' refused separately


ASCII_RE = re.compile(r"[\x20-\x7e]+")                         # fullmatch, case-sensitive: before EXE_RE / out_re


def out_re(sid):
    return re.compile(rf"C:\\AnalystLab\\scenarios\\{sid}(?:\\{PART})+", re.I)


def arg_ok(a):
    """An argument PowerShell 5.1's `& exe @args` passes unchanged: it drops empty ones, strips
    embedded double quotes, and mangles a trailing backslash in one with whitespace."""
    return (isinstance(a, str) and re.fullmatch(r"[\x20-\x7e]+", a) is not None and '"' not in a
            and not (" " in a and a.endswith("\\")))       # printable ASCII only (no tabs or newlines)


class Refused(Exception):
    """The blind folder (or the request) fails a safety check: nothing was touched (exit 2)."""


def _norm(path):
    return os.path.normcase(os.path.realpath(os.path.abspath(path)))


def _inside(path, root):
    path, root = _norm(path), _norm(root)
    return path == root or path.startswith(root.rstrip("\\/") + os.sep)


def project_roots():
    """This checkout, plus the main checkout when this one is a git worktree (a blind folder inside
    the main project folder is "in the project" too). Fails closed: a worktree path names its main
    checkout even when git can't be asked."""
    roots = [PROJECT_ROOT]
    i = PROJECT_ROOT.lower().find(WORKTREES.lower())
    if i > 0:
        roots.append(PROJECT_ROOT[:i])
    try:
        p = subprocess.run(["git", "-C", PROJECT_ROOT, "rev-parse", "--path-format=absolute", "--git-common-dir"],
                           capture_output=True, text=True, timeout=20)
        common = p.stdout.strip()
        if p.returncode == 0 and os.path.basename(common.rstrip("\\/")).lower() == ".git":
            roots.append(os.path.dirname(common.rstrip("\\/")))
    except (OSError, subprocess.SubprocessError):
        pass
    return roots


def _walk(top):
    """(folder, file names, linked sub-folders) for every real folder under `top`, like os.walk but
    refusing instead of skipping what it can't read (os.walk ignores errors), and never going into
    a link or junction (os.walk follows junctions on Windows: a junction to its own folder looped)."""
    def fail(e):
        raise Refused(f"could not read everything in the blind folder ({e.__class__.__name__}, errno {e.errno})")
    for dirpath, dirs, names in os.walk(top, onerror=fail):
        linked = [d for d in dirs if _is_link(os.path.join(dirpath, d))]
        dirs[:] = [d for d in dirs if d not in linked]
        yield dirpath, names, linked


def _is_link(path):
    return os.path.islink(path) or os.path.isjunction(path)


def _file_id(path):
    st = os.stat(path)
    return (st.st_dev, st.st_ino)


def secret_ids(folder):
    """File identities of what must never reach the CD: the answer sheet, scenario.json and every
    source under src\\ (a hard link or an in-folder link to one of them is the same file)."""
    ids = set()
    for n in (SHEET, "scenario.json"):
        if os.path.exists(os.path.join(folder, n)):
            ids.add(_file_id(os.path.join(folder, n)))
    src = os.path.join(folder, "src")
    if os.path.isdir(src):
        for dirpath, names, _ in _walk(src):
            ids |= {_file_id(os.path.join(dirpath, n)) for n in names}
    return ids


def check_cd_file(folder, path, secrets):
    """One blind file for the CD: a real file (no link), inside the folder but not under src\\,
    not the sheet / scenario.json / a source under another name, at most 50 MB. Returns its size.
    Raises Refused with a message that names no file."""
    if _is_link(path) or not os.path.isfile(path):
        raise Refused("links or junctions under bin\\ are not allowed (copy the real files in)")
    if not _inside(path, folder) or _inside(path, os.path.join(folder, "src")):
        raise Refused("every file under bin\\ must lie inside the folder and outside src\\")
    if _file_id(path) in secrets:
        raise Refused("a file under bin\\ is the answer sheet, scenario.json or a source under another name")
    size = os.stat(path).st_size
    if size > MAX_BYTES:
        raise Refused(f"a file under bin\\ is larger than 50 MB ({size / 2**20:.1f} MB)")
    return size


class Blind:
    """A checked blind folder. Holds only what scenario.json says and the list of files for the CD."""

    def __init__(self, folder, sid, exe, args, out, files):
        self.folder, self.id, self.exe, self.args, self.out, self.files = folder, sid, exe, args, out, files

    @property
    def sheet(self):
        return os.path.join(self.folder, SHEET)


def read_id(folder):
    """The scenario id from scenario.json ('B1'), or None (for display only, e.g. run_series)."""
    try:
        with open(os.path.join(folder, "scenario.json"), encoding="utf-8-sig") as f:
            sid = json.load(f).get("id")
        return sid.upper() if isinstance(sid, str) and BLIND_ID.match(sid) else None
    except (OSError, ValueError, AttributeError):
        return None


def validate(folder, stage_root=None):
    """The safety checks before anything is built. Reads scenario.json, file sizes and file
    identities only; never opens the answer sheet or runs anything. Messages never name the
    folder's programs."""
    try:
        return _validate(folder, stage_root or STAGE_ROOT)
    except OSError as e:                     # e.g. a broken link: refuse, without the path
        raise Refused(f"could not read the blind folder ({e.__class__.__name__}, errno {e.errno})")


def _validate(folder, stage_root):
    if not os.path.isdir(folder):
        raise Refused(f"no such folder: {folder}")
    folder = os.path.abspath(folder)
    for root in project_roots():
        if _inside(folder, root) or _inside(root, folder):
            raise Refused(f"the blind folder is inside the project folder ({root}) or contains it; keep it "
                          "outside, e.g. in Documents\\AnalystLab-blind\\")
        if _inside(stage_root, root) or _inside(root, stage_root):
            raise Refused(f"the run CD's staging folder {stage_root} must be outside the project")
    if _inside(stage_root, folder) or _inside(folder, stage_root):
        raise Refused("the run CD's staging folder and the blind folder must not overlap")
    try:
        with open(os.path.join(folder, "scenario.json"), encoding="utf-8-sig") as f:
            sj = json.load(f)
    except FileNotFoundError:
        raise Refused("scenario.json is missing")
    except ValueError:
        raise Refused("scenario.json is not valid JSON")
    sid, exe, args, out = json_rules(sj)
    if not os.path.isfile(os.path.join(folder, SHEET)):        # exists: checked, not opened
        raise Refused(f"{SHEET} (the answer sheet) is missing")
    return _files(folder, sid, exe, args, out)


def json_rules(sj):
    """scenario.json's own rules (no files looked at): the same ones the VM's run_scenario.ps1
    applies again. Returns (id, exe, args, out) or raises Refused."""
    if not isinstance(sj, dict):
        raise Refused("scenario.json must be one JSON object")
    sid = sj.get("id")
    if not isinstance(sid, str) or not BLIND_ID.match(sid):
        raise Refused("scenario.json 'id' must be B1..B99")
    sid = sid.lower()
    exe = sj.get("exe")
    if not isinstance(exe, str) or not ASCII_RE.fullmatch(exe) or not EXE_RE.fullmatch(exe) or ".." in exe:
        raise Refused("scenario.json 'exe' must be bin\\<name> (letters, digits, _ - . and space; no '..', "
                      "no name ending in '.' or space)")
    args = sj.get("args", [])
    if args is None:
        args = []
    if not isinstance(args, list) or not all(arg_ok(a) for a in args):
        raise Refused("scenario.json 'args' must be a list of non-empty plain-ASCII strings without double "
                      "quotes (and none with a space that ends in a backslash)")
    out = sj.get("out")
    if out is not None and (not isinstance(out, str) or not ASCII_RE.fullmatch(out) or not out_re(sid).fullmatch(out)
                            or ".." in out):
        raise Refused(f"scenario.json 'out' must be null or a folder under C:\\AnalystLab\\scenarios\\{sid}\\ "
                      "(the VM empties it before the run)")
    return sid, exe, list(args), out


def _files(folder, sid, exe, args, out):
    big, biggest = 0, 0
    for dirpath, names, _ in _walk(folder):
        for n in names:
            size = os.stat(os.path.join(dirpath, n)).st_size
            biggest = max(biggest, size)
            big += size > MAX_BYTES
    if big:
        raise Refused(f"{big} file(s) in the blind folder are larger than 50 MB (largest {biggest / 2**20:.1f} MB)")
    # the CD's files: everything under bin\ (the exe is one of them), real files only
    secrets = secret_ids(folder)
    bin_dir = os.path.join(folder, "bin")
    if _is_link(bin_dir) or not os.path.isdir(bin_dir):
        raise Refused("the blind folder needs a real bin\\ folder")
    files, total = [], 0
    for dirpath, names, linked in _walk(bin_dir):
        if linked:
            raise Refused("links or junctions under bin\\ are not allowed (copy the real files in)")
        for n in names:
            path = os.path.join(dirpath, n)
            rel = os.path.relpath(path, folder)
            if ".." in rel or not all(PART_RE.fullmatch(p) for p in rel.split(os.sep)):
                raise Refused("names under bin\\ must use letters, digits, _ - . and space only "
                              "(not starting or ending with . or space)")
            total += check_cd_file(folder, path, secrets)
            files.append(("/blind/" + sid + "/" + rel.replace(os.sep, "/"), path))
    if len(files) > MAX_CD_FILES or total > MAX_CD_BYTES:
        raise Refused(f"bin\\ holds {len(files)} files, {total / 2**20:.1f} MB: at most {MAX_CD_FILES} files "
                      f"and {MAX_CD_BYTES // 2**20} MB go on the run CD")
    if os.path.normcase(exe) not in {os.path.normcase(os.path.relpath(p, folder)) for _, p in files}:
        raise Refused("scenario.json 'exe' must name a file under bin\\")
    return Blind(folder, sid, exe, [str(a) for a in args], out, sorted(files))


def cd_content_map(blind, run_id, stage_root=None):
    """CD path -> laptop source, for a run CD of this blind scenario; writes the run note and the
    sanitized scenario.json into the staging folder. No answer sheet, no sources."""
    stage = os.path.join(stage_root or STAGE_ROOT, "gen")
    os.makedirs(stage, exist_ok=True)
    if not run_in_vm.RUN_ID.fullmatch(run_id):
        raise ValueError(f"bad run id {run_id!r}")
    note = os.path.join(stage, "AUTORUN_SCENARIO.txt")
    with open(note, "w", encoding="ascii", newline="") as f:
        f.write(f"scenario={blind.id}\r\nrun_id={run_id}\r\n")
    sj = os.path.join(stage, "scenario.json")
    with open(sj, "w", encoding="ascii") as f:
        json.dump({"exe": blind.exe, "args": blind.args, "out": blind.out}, f)
    vm = VM_SCRIPTS
    m = {"/AUTORUN_SCENARIO.txt": note,
         "/scenario_launcher.ps1": os.path.join(vm, "scenario_launcher.ps1"),
         "/run_scenario.ps1": os.path.join(vm, "run_scenario.ps1"),
         f"/blind/{blind.id}/scenario.json": sj}
    m.update(dict(blind.files))
    return m


def build_cd(blind, run_id, stage_root=None):
    """(exit code, message) like make_scenario_cd.ps1: FROZEN copies (a .viso points at files that
    VirtualBox reads live) in <stage>\\cd, then <stage>\\analystlab-blind-run.viso. Every blind file
    is checked again as it is copied (the folder may have changed since validate). Messages give
    counts only."""
    stage_root = stage_root or STAGE_ROOT
    try:
        content = cd_content_map(blind, run_id, stage_root)
        blind_files = {k for k, _ in blind.files}
        secrets = secret_ids(blind.folder)
        frozen_root = os.path.join(stage_root, "cd")
        if os.path.exists(frozen_root):
            shutil.rmtree(frozen_root)
        frozen, digest, total, blind_total = {}, hashlib.sha256(), 0, 0
        for key in sorted(content):
            if key in blind_files:
                check_cd_file(blind.folder, content[key], secrets)
            dst = os.path.join(frozen_root, *key.strip("/").split("/"))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(content[key], dst)
            with open(dst, "rb") as f:
                data = f.read()
            if key in blind_files:
                blind_total += len(data)
                if len(data) > MAX_BYTES or blind_total > MAX_CD_BYTES:
                    raise Refused("the blind files grew past the size limits while the CD was built")
            digest.update(key.encode("ascii") + b"\0" + hashlib.sha256(data).digest())
            total += len(data)
            frozen[key] = dst
        parts = ["--iprt-iso-maker-file-marker-bourne-sh", str(uuid.uuid4()), "--file-mode=0444", "--dir-mode=0555"]
        parts += [f"'{k}={frozen[k]}'" for k in content]
        with open(os.path.join(stage_root, VISO_NAME), "w", encoding="ascii", newline="") as f:
            f.write(" ".join(parts))
    except Refused as e:
        return 1, f"building the blind run CD refused: {e}"
    except (OSError, UnicodeError, ValueError) as e:      # no paths in the message (they name programs)
        return 1, f"building the blind run CD failed ({e.__class__.__name__}, errno {getattr(e, 'errno', None)})"
    blind.cd = {"files": len(content), "bytes": total, "sha256": digest.hexdigest()}
    return 0, f"Wrote the blind run CD ({len(content)} files, {total / 2**20:.1f} MB)"


def expects_alert(sheet):
    """"check" (our layout's rule list), "steps" (round 2: suspicious steps named), "innocent" (round
    2: an empty suspicious_steps list) or "" (nothing expected)."""
    with open(sheet, encoding="utf-8") as f:
        a = (yaml.safe_load(f) or {}).get("alert_expected") or {}
    if a.get("check"):
        return "check"
    if "suspicious_steps" in a:
        return "steps" if a["suspicious_steps"] else "innocent"
    return ""


def _sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class BlindRunner(Runner):
    """tools/run_in_vm.py's Runner for one blind scenario: its own run CD (outside the project), no
    answer sheet before the run, the three checkers with --sheet after it."""

    def __init__(self, blind, label="practice", stage_root=None, run_tool=None, **kw):
        self.blind, self.label = blind, label
        self.stage_root = stage_root or STAGE_ROOT
        env = dict(os.environ, ANALYSTLAB_OFFICIAL="1") if label == "official" else None
        self.run_tool = run_tool or (lambda tool, args: subprocess.run(
            [sys.executable, os.path.join(PROJECT_ROOT, "tools", tool), *args], env=env).returncode)
        kw.setdefault("build_cd", lambda rid: build_cd(self.blind, rid, self.stage_root))
        super().__init__(blind.id, check=self._check, detect_check=self._detect, **kw)
        self.run_cd = os.path.join(self.stage_root, VISO_NAME)
        self.sheet_copy = None
        self.summary["label"] = label
        if label == "official":
            from engine import evaluation
            self.summary["freeze"] = evaluation.FREEZE_TAG      # which evaluation this run belongs to (none = v1)
            self.summary["code"] = evaluation.code_state()
        self.summary["blind"] = {"folder": blind.folder}

    def precheck_sheets(self):
        """The answer sheet must exist, but is NOT opened before the run; single run, so the
        launcher keeps its calm-down wait."""
        if not os.path.isfile(self.blind.sheet):
            raise NotStarted(f"the blind folder has no {SHEET}")
        self.items[0]["calm"] = True

    def precheck_vm(self):
        super().precheck_vm()
        cd = getattr(self.blind, "cd", None)
        if cd:
            self.summary["blind"]["run_cd"] = cd

    def on_barrier(self, item):
        """The Runner calls this wherever a run's barrier is taken as arrived (also in its recovery
        path after a later failure)."""
        self.summary["blind"].setdefault("barrier_arrived_utc", utc_now().isoformat())

    def open_sheet(self):
        """Copy the answer sheet into recordings/blind/<id>/<run id>/ - only once the run record and
        the flush barrier are in - and note when this run opened it (sheet_opened_utc) and, write-once
        in recordings/blind/<id>/first_opened.json, when ANY run first opened this id's sheet."""
        item = self.items[0]
        if self.sheet_copy:
            return self.sheet_copy
        if "run_record" not in item or "barrier" not in item:
            raise StepFailed("refusing to open the blind answer sheet before the run record and flush barrier arrived")
        b = self.summary["blind"]
        dest = os.path.join(self.recordings, "blind", self.blind.id, item["run_id"], SHEET)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        b["sheet_opened_utc"] = utc_now().isoformat()
        shutil.copyfile(self.blind.sheet, dest)
        b["sheet_copy"] = os.path.relpath(dest, self.recordings)
        b["sheet_sha256"] = _sha256(dest)
        first = os.path.join(self.recordings, "blind", self.blind.id, "first_opened.json")
        try:
            with open(first, "x", encoding="utf-8") as f:          # write-once: never overwritten
                json.dump({"first_opened_utc": b["sheet_opened_utc"], "run_id": item["run_id"],
                           "barrier_arrived_utc": b.get("barrier_arrived_utc"), "sheet_sha256": b["sheet_sha256"]}, f,
                          indent=2)
        except FileExistsError:
            pass
        try:
            with open(first, encoding="utf-8") as f:
                b["first_opened"] = json.load(f)
        except (OSError, ValueError):
            b["first_opened"] = None
        self.sheet_copy = dest
        self.say(f"    answer sheet opened {b['sheet_opened_utc']} (after the barrier); "
                 f"copy in recordings/{b['sheet_copy'].replace(os.sep, '/')}")
        return dest

    def _args(self, scenario, rid):
        return [scenario, "--run-id", rid, "--recordings", self.recordings, "--sheet", self.open_sheet()]

    def _check(self, scenario, rid):
        codes = [self.run_tool(tool, self._args(scenario, rid)) for tool in CHECKERS]
        return 0 if all(c == 0 for c in codes) else 1

    def _detect(self, scenario, rid):
        code = self.run_tool("check_alerts.py", self._args(scenario, rid))
        kind = expects_alert(self.sheet_copy)
        if code == 2:
            return "NOT CHECKED"
        if kind == "innocent":                       # check_alerts: 0 = CLEAN, 1 = FALSE ALARM
            return {0: "CLEAN", 1: "FALSE ALARM"}.get(code, "NOT CHECKED")
        if code == 0 and not kind:
            return "NONE EXPECTED"
        return DETECTION.get(code, "NOT CHECKED")


def has_freeze_tag():
    from run_series import has_freeze_tag as tag
    return tag()


def resolve_label(label):
    """--label, or official when ANALYSTLAB_OFFICIAL=1 (like run_series); a contradiction is refused."""
    env_official = os.environ.get("ANALYSTLAB_OFFICIAL") == "1"
    if env_official and label == "practice":
        raise Refused("ANALYSTLAB_OFFICIAL=1 is set but --label practice was given")
    return label or ("official" if env_official else "practice")


def main(argv=None):
    p = argparse.ArgumentParser(description="Run a blind scenario folder (outside the project) in a fresh lab VM")
    p.add_argument("folder", help="the blind scenario's folder, e.g. C:\\Users\\<you>\\Documents\\AnalystLab-blind\\b1")
    p.add_argument("--label", choices=["practice", "official"],
                   help="practice (default) or official (needs the git tag freeze-v2; also ANALYSTLAB_OFFICIAL=1)")
    p.add_argument("--headless", action="store_true", help="no VM window")
    p.add_argument("--recordings", help="recordings folder (default: the project's recordings/)")
    p.add_argument("--keep-running", action="store_true", help="leave the VM on afterwards")
    p.add_argument("--cpus", type=int, default=1, help="virtual CPUs for this boot (default 1; 0 = the snapshot's)")
    p.add_argument("--snapshot", default=run_in_vm.SNAPSHOT,
                   help="snapshot to restore (default clean; blind round 4 uses lived-in); recorded in the run summary")
    p.add_argument("--dry-run", action="store_true", help="only the folder checks and the run CD; the VM is not touched")
    p.add_argument("--check-sheet", action="store_true",
                   help="with --dry-run: also check the answer sheet's LAYOUT (tools/sheet_check.py). It OPENS "
                        "the sheet, so only the blind WRITER uses it, before handing in")
    a = p.parse_args(argv)
    if a.check_sheet and not a.dry_run:
        print("REFUSED: --check-sheet only goes with --dry-run (it opens the answer sheet: the writer's check, "
              "never part of a run)\nNothing was built and the VM was not touched.")
        return 2
    try:
        label = resolve_label(a.label)
        if label == "official" and not has_freeze_tag():
            from engine import evaluation
            raise Refused(f"official runs need the git tag {evaluation.FREEZE_TAG} and the code exactly as frozen "
                          f"(fair-test rule 2)")
        blind = validate(a.folder)
    except Refused as e:
        print(f"REFUSED: {e}\nNothing was built and the VM was not touched.")
        return 2
    print(f"Blind scenario {blind.id.upper()} ({label}): folder checks passed, {len(blind.files)} program file(s) "
          f"for the run CD; the answer sheet stays closed until the run is in")
    if a.dry_run:
        code, out = build_cd(blind, run_in_vm.new_run_id())
        print(out)
        if a.check_sheet:
            import sheet_check
            problems, warnings, err = sheet_check.check_file(blind.sheet, blind.id)
            for x in ([f"UNREADABLE: {err}"] if err else []) + [f"problem  {x}" for x in problems] \
                    + [f"note     {x}" for x in warnings]:
                print(f"  {x}")
            ok = not err and not problems
            print(f"Answer sheet layout: {'OK' if ok else 'NOT READABLE BY THE CHECKERS: fix the problems above'}")
            code = code if ok else 1
        return 0 if code == 0 else 2
    # official: BlindRunner gives the checkers ANALYSTLAB_OFFICIAL=1 (they verify the frozen files)
    return BlindRunner(blind, label=label, recordings=a.recordings, headless=a.headless,
                       keep_running=a.keep_running, cpus=a.cpus or None, snapshot=a.snapshot).run()


if __name__ == "__main__":
    sys.exit(main())
