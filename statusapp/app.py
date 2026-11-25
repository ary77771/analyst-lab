"""The status window (DESIGN 9.2), Tkinter (built into Python), English.

    python -m statusapp.app                 # friend mode
    python -m statusapp.app --mode lab      # Yousif: adds counts, sizes, Event Viewer

Friend mode answers "is it working, how far along, what do I do?" and offers: Export my
statistics, Run self-test, Pause for 1 hour (auto-resumes, recorded), See what's collected,
Uninstall everything. There is deliberately no Stop button (silent gaps). Lab mode adds event
counts, recording size, Sysmon log size and an Event Viewer shortcut.

The window never needs admin rights: it reads the recorder's heartbeat (status.json), its
own statistics cache, and writes only pause.json and the exported file. All decisions about
what to show are in view() (plain data in, plain data out), so they are tested without a screen.
"""

import argparse
import json
import os
import queue
import subprocess
import sys
import threading
from datetime import datetime, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
from agent import control, paths  # noqa: E402
from statusapp import selftest, stats  # noqa: E402

STALE_SECONDS = 120             # the recorder writes its heartbeat every 5 s
STATUS_EVERY_MS = 5000
STATS_EVERY_MS = 10 * 60 * 1000
FIRST_RUN_DELAY_MS = 20 * 1000     # give the just-started recorder time to begin
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
GREEN, AMBER, RED = "#1e7d32", "#b26a00", "#b00020"

PRIVACY_NOTE = ("Your recording stays on this laptop. Only the statistics file you export "
                "yourself (numbers only, you read it first) is ever shared.")
WHAT_IS_COLLECTED = """What the recorder notes down (Windows' own Sysmon tool):
  - programs starting and closing
  - network connections (which program, to which address)
  - name lookups (which website names were looked up)
  - new or deleted program and script files, and files in Downloads and Startup

Where it is kept: only on this laptop, in
  {folder}
It is never uploaded or sent anywhere by this app.

What leaves the laptop: only the statistics file, and only if you send it yourself. It holds
counts (for example "412 programs started per hour of use"), no names, files, websites or
times. Use "Preview my statistics" to see exactly what it contains.

Pause for 1 hour: during a pause only "something happened" is counted, never what."""


def local_hhmm(utc_text: str) -> str:
    return control.parse_utc(utc_text).astimezone().strftime("%H:%M")


def view(status: dict, now: datetime, summary: dict = None, pause=None, mode: str = "friend") -> dict:
    """What the window shows. status: the recorder's status.json (or None); summary: stats.summarize
    output (or None while it is being computed); pause: control.read_pause(...) result."""
    now_text = control.utc_text(now)
    v = {"pause_button": "Pause for 1 hour", "pause_enabled": True, "lab": []}
    paused = pause is not None and pause[1] > now_text
    age = None
    if status and status.get("updated"):
        try:
            age = (now - control.parse_utc(status["updated"])).total_seconds()
        except ValueError:
            age = None
    if status is None or age is None:
        v.update(headline="The recorder has not started yet", colour=RED,
                 detail="Restart the laptop. If this message stays, tell Yousif.")
        v["pause_enabled"] = False
    elif age > STALE_SECONDS:
        mins = int(age // 60)
        v.update(headline="The recorder is not running", colour=RED,
                 detail=f"No sign of it for {mins} min. Restart the laptop; if it keeps happening, tell Yousif.")
        v["pause_enabled"] = False
    elif paused:
        v.update(headline=f"Paused until {local_hhmm(pause[1])}", colour=AMBER,
                 detail="Recording resumes by itself. Only counts are kept until then.")
        v["pause_button"] = "Resume now"
    elif status.get("errors"):
        v.update(headline="Collecting, with a problem", colour=AMBER,
                 detail="Please run the self-test. If it fails, tell Yousif.")
    else:
        v.update(headline="Collecting. You don't need to do anything.", colour=GREEN,
                 detail="You can close this window; recording continues in the background.")
    if summary is None:
        v["progress"], v["progress_fraction"] = "Counting your progress...", 0.0
    else:
        days, target = summary["days_recorded"], summary["target_days"]
        v["progress_fraction"] = min(1.0, days / target)
        v["progress"] = f"Day {min(days, target)} of {target}  ·  {summary['active_hours']:.1f} active hours"
        if days >= target:
            v["progress"] += "  ·  Done! Export your statistics and send them to Yousif."
    if mode == "lab" and status:
        v["lab"] = [f"Events written this session: {status.get('events_written', 0):,}",
                    f"Last Sysmon record: {status.get('last_record_id')}",
                    f"Errors: {status.get('errors', 0)}  ·  CPU {status.get('cpu_percent_of_machine')}%"
                    f"  ·  memory {status.get('memory_mb')} MB"]
        if summary is not None:
            h = summary["health"]
            v["lab"].append(f"Sysmon records {h['sysmon_records']:,}, missing {h['sysmon_records_missing']:,}"
                            f"  ·  sessions {h['recorder_sessions']}")
    return v


def desktop_folder() -> str:
    try:
        from win32com.shell import shell, shellcon
        return shell.SHGetFolderPath(0, shellcon.CSIDL_DESKTOPDIRECTORY, None, 0)
    except Exception:
        return os.path.join(os.path.expanduser("~"), "Desktop")


def export(recordings: str, label: str, control_dir: str, folder: str = None, now: datetime = None) -> str:
    """Write the statistics file and return its path."""
    now = now or datetime.now()
    summary = stats.summarize(stats.collect(recordings, label, control_dir), selftest.history(control_dir))
    text = stats.export_text(summary, now.strftime("%Y-%m-%d"))
    path = os.path.join(folder or desktop_folder(), f"AnalystLab-statistics-{now:%Y-%m-%d}.txt")
    with open(path, "w", encoding="utf-8", newline="\r\n") as f:
        f.write(text)
    return path


def folder_size_mb(folder: str) -> float:
    total = 0
    for root, _, files in os.walk(folder):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return total / 2**20


def sysmon_log_size_mb():
    """The Sysmon log's file size, or None (reading it may need admin rights)."""
    try:
        out = subprocess.run(["wevtutil", "gli", SYSMON_CHANNEL], capture_output=True, text=True,
                             timeout=10, creationflags=selftest.CREATE_NO_WINDOW)
        for line in out.stdout.splitlines():
            if line.strip().startswith("fileSize:"):
                return int(line.split(":", 1)[1]) / 2**20
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return None


def sysmon_installed_by():
    """From Setup's install.json: 'builtin'/'standalone' (ours), 'already-there', or None."""
    try:
        with open(os.path.join(paths.data_root(), "install.json"), encoding="utf-8-sig") as f:
            return json.load(f).get("sysmon")
    except (OSError, ValueError, AttributeError):
        return None


def uninstaller():
    """Inno Setup puts unins000.exe next to the installed program; a developer copy has none."""
    if getattr(sys, "frozen", False):
        path = os.path.join(os.path.dirname(sys.executable), "unins000.exe")
        if os.path.exists(path):
            return path
    return None


class StatusWindow:
    def __init__(self, root, recordings: str, label: str, mode: str, first_run: bool = False, control_dir: str = None):
        import tkinter as tk
        from tkinter import ttk
        self.tk, self.ttk = tk, ttk
        self.root, self.recordings, self.label, self.mode = root, recordings, label, mode
        self.state_dir = os.path.join(recordings, ".state", label)        # the recorder's (read only)
        # where the window writes: pause file, statistics cache, self-test result (the bundle uses
        # C:\ProgramData\AnalystLab\control, the only folder there a friend may write)
        self.control_dir = control_dir or self.state_dir
        root.report_callback_exception = self.on_error
        self.summary = None
        self.jobs = queue.Queue()
        self.busy = set()

        root.title("Analyst Lab" + (" (lab)" if mode == "lab" else ""))
        root.minsize(520, 0)
        pad = {"padx": 16, "pady": 4}
        self.headline = tk.Label(root, font=("Segoe UI", 14, "bold"), anchor="w", justify="left")
        self.headline.pack(fill="x", padx=16, pady=(16, 2))
        self.detail = tk.Label(root, font=("Segoe UI", 10), anchor="w", justify="left", wraplength=500)
        self.detail.pack(fill="x", **pad)
        self.bar = ttk.Progressbar(root, maximum=1.0, length=480)
        self.bar.pack(fill="x", padx=16, pady=(10, 2))
        self.progress = tk.Label(root, font=("Segoe UI", 10), anchor="w")
        self.progress.pack(fill="x", **pad)
        tk.Label(root, text=PRIVACY_NOTE, font=("Segoe UI", 9), fg="#555", anchor="w", justify="left",
                 wraplength=500).pack(fill="x", padx=16, pady=(8, 4))
        self.lab = tk.Label(root, font=("Consolas", 9), anchor="w", justify="left")
        if mode == "lab":
            self.lab.pack(fill="x", **pad)

        buttons = tk.Frame(root)
        buttons.pack(fill="x", padx=12, pady=(8, 4))
        self.b_export = ttk.Button(buttons, text="Export my statistics", command=self.on_export)
        self.b_test = ttk.Button(buttons, text="Run self-test", command=self.on_selftest)
        self.b_pause = ttk.Button(buttons, text="Pause for 1 hour", command=self.on_pause)
        self.b_what = ttk.Button(buttons, text="See what's collected", command=self.on_what)
        for i, b in enumerate((self.b_export, self.b_test, self.b_pause, self.b_what)):
            b.grid(row=i // 2, column=i % 2, sticky="ew", padx=4, pady=3)
        buttons.columnconfigure(0, weight=1)
        buttons.columnconfigure(1, weight=1)
        extra = tk.Frame(root)
        extra.pack(fill="x", padx=12, pady=(0, 12))
        if mode == "lab":
            ttk.Button(extra, text="Event Viewer (Sysmon)", command=self.on_event_viewer).pack(side="left", padx=4)
            ttk.Button(extra, text="Open recordings folder", command=self.on_open_folder).pack(side="left", padx=4)
        ttk.Button(extra, text="Uninstall everything", command=self.on_uninstall).pack(side="right", padx=4)
        self.message = tk.Label(root, font=("Segoe UI", 9), anchor="w", justify="left", wraplength=500)
        self.message.pack(fill="x", padx=16, pady=(0, 12))

        self.refresh()
        self.refresh_stats()
        root.after(200, self.poll_jobs)
        if first_run:                 # right after Setup: prove recording works, no click needed
            self.say("First start: checking that recording works in a moment...")
            root.after(FIRST_RUN_DELAY_MS, self.on_selftest)

    # background work ---------------------------------------------------------------------
    def background(self, name, fn, done):
        if name in self.busy:
            return
        self.busy.add(name)

        def work():
            try:
                result = (True, fn())
            except Exception as e:       # shown in the window, never a crash
                result = (False, e)
            self.jobs.put((name, done, result))
        threading.Thread(target=work, daemon=True).start()

    def poll_jobs(self):
        try:
            while True:
                name, done, result = self.jobs.get_nowait()
                self.busy.discard(name)
                done(*result)
        except queue.Empty:
            pass
        self.root.after(200, self.poll_jobs)

    # refresh -----------------------------------------------------------------------------
    def read_status(self):
        try:
            with open(os.path.join(self.state_dir, "status.json"), encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

    def refresh(self):
        self.draw()
        self.root.after(STATUS_EVERY_MS, self.refresh)

    def draw(self):
        v = view(self.read_status(), datetime.now(timezone.utc), self.summary,
                 control.read_pause(self.control_dir), self.mode)
        self.headline.config(text=v["headline"], fg=v["colour"])
        self.detail.config(text=v["detail"])
        self.progress.config(text=v["progress"])
        self.bar["value"] = v["progress_fraction"]
        self.b_pause.config(text=v["pause_button"], state="normal" if v["pause_enabled"] else "disabled")
        if self.mode == "lab":
            self.lab.config(text="\n".join(v["lab"] + getattr(self, "lab_sizes", [])))

    def refresh_stats(self):
        def fn():
            s = stats.summarize(stats.collect(self.recordings, self.label, self.control_dir),
                                selftest.history(self.control_dir))
            sizes = []
            if self.mode == "lab":
                sizes.append(f"Recording folder: {folder_size_mb(os.path.join(self.recordings, self.label)):,.0f} MB")
                log = sysmon_log_size_mb()
                sizes.append(f"Sysmon log: {log:,.0f} MB" if log is not None else "Sysmon log: size needs admin rights")
            return s, sizes

        def done(ok, value):
            if ok:
                self.summary, self.lab_sizes = value
                self.draw()
            else:
                self.say(f"Couldn't count the progress ({type(value).__name__}). Tell Yousif if this stays.")
        self.background("stats", fn, done)
        self.root.after(STATS_EVERY_MS, self.refresh_stats)

    def say(self, text, colour="#333"):
        self.message.config(text=text, fg=colour)

    def on_error(self, kind, value, tb):
        """Any unexpected error in a button: shown in the window (a windowed program has no
        console), by its type only: the text could contain the friend's folders."""
        self.say(f"Something went wrong ({kind.__name__}). Tell Yousif if it happens again.", RED)

    # buttons -----------------------------------------------------------------------------
    def on_export(self):
        self.say("Writing your statistics file...")

        def done(ok, value):
            if ok:
                self.say(f"Saved to your Desktop: {os.path.basename(value)}. It opens now: read it, "
                         "then send it to Yousif if you're happy with it.", GREEN)
                os.startfile(value)
            else:
                self.say(f"Export failed ({type(value).__name__}). Tell Yousif.", RED)
        self.background("export", lambda: export(self.recordings, self.label, self.control_dir), done)

    def on_selftest(self):
        self.b_test.config(state="disabled")
        self.say("Self-test running (up to 90 seconds)...")

        def done(ok, value):
            self.b_test.config(state="normal")
            if not ok:
                self.say(f"The self-test itself failed ({type(value).__name__}). Tell Yousif.", RED)
                return
            if value.get("paused"):
                self.say(value["message"], AMBER)
                return
            lines = [("PASS  " if c["ok"] else "FAIL  ") + c["label"] for c in value["checks"]]
            self.say("\n".join(lines + [value["message"]]), GREEN if value["passed"] else RED)
        self.background("selftest", lambda: selftest.run(self.recordings, self.label, self.control_dir,
                                                                   foreign_sysmon=sysmon_installed_by() == "already-there"), done)

    def on_pause(self):
        pause = control.read_pause(self.control_dir)
        if pause and pause[1] > control.utc_text(datetime.now(timezone.utc)):
            control.resume_now(self.control_dir)
            self.say("Resumed. Recording continues as normal.", GREEN)
        else:
            p = control.request_pause(self.control_dir)
            self.say(f"Paused until {local_hhmm(p['until'])}. It resumes by itself; the pause is noted "
                     "so the statistics stay honest.", AMBER)
        self.draw()

    def on_what(self):
        tk = self.tk
        win = tk.Toplevel(self.root)
        win.title("What is collected")
        tk.Label(win, text=WHAT_IS_COLLECTED.format(folder=os.path.join(self.recordings, self.label)),
                 justify="left", font=("Segoe UI", 10), wraplength=560).pack(padx=16, pady=12)
        row = tk.Frame(win)
        row.pack(pady=(0, 12))
        self.ttk.Button(row, text="Preview my statistics", command=self.on_preview).pack(side="left", padx=4)
        self.ttk.Button(row, text="Open the folder", command=self.on_open_folder).pack(side="left", padx=4)

    def on_preview(self):
        def fn():
            s = stats.summarize(stats.collect(self.recordings, self.label, self.control_dir),
                                selftest.history(self.control_dir))
            return stats.export_text(s, datetime.now().strftime("%Y-%m-%d"))

        def done(ok, value):
            if not ok:
                self.say(f"Preview failed ({type(value).__name__}). Tell Yousif.", RED)
                return
            tk = self.tk
            win = tk.Toplevel(self.root)
            win.title("Preview: the statistics file")
            text = tk.Text(win, width=90, height=32, font=("Consolas", 9))
            text.insert("1.0", value)
            text.config(state="disabled")
            text.pack(fill="both", expand=True, padx=8, pady=8)
        self.background("preview", fn, done)

    def on_open_folder(self):
        os.startfile(os.path.join(self.recordings, self.label))

    def on_event_viewer(self):
        subprocess.Popen(["mmc.exe", "eventvwr.msc", f"/c:{SYSMON_CHANNEL}"])

    def on_uninstall(self):
        from tkinter import messagebox
        path = uninstaller()
        if path is None:
            messagebox.showinfo("Uninstall", "This copy was not installed with Setup (a developer copy), "
                                "so there is nothing to uninstall here.")
            return
        if messagebox.askyesno("Uninstall everything",
                               "This removes the recorder, its scheduled task, Sysmon and ALL recordings "
                               "on this laptop. Export your statistics first if you haven't. Continue?"):
            # ShellExecute, so Windows can ask for admin permission; /LOG keeps Inno Setup's own
            # account of what it removed (or couldn't) in the temp folder, which uninstall keeps
            log = os.path.join(os.environ.get("TEMP", os.path.expanduser("~")), "AnalystLab-uninstall-inno.log")
            try:
                import win32api
                win32api.ShellExecute(0, "open", path, f'/LOG="{log}"', os.path.dirname(path), 1)
            except Exception as e:    # pywintypes.error or ImportError
                self.say(f"Couldn't start the uninstaller ({type(e).__name__}). Use Windows Settings > Apps.", RED)
                return
            self.root.destroy()


def main(argv=None):
    p = argparse.ArgumentParser(description="Analyst Lab status window")
    p.add_argument("--mode", choices=["friend", "lab"], default="friend")
    p.add_argument("--recordings", default=paths.recordings_root())
    p.add_argument("--label", default="host")
    p.add_argument("--first-run", action="store_true", help="run the self-test by itself (after Setup)")
    p.add_argument("--control-dir", default=os.path.join(paths.data_root(), "control") if paths.frozen() else None,
                   help=argparse.SUPPRESS)
    p.add_argument("--close-after", type=float, default=0, help=argparse.SUPPRESS)   # smoke tests
    a = p.parse_args(argv)
    import tkinter as tk
    root = tk.Tk()
    StatusWindow(root, a.recordings, a.label, a.mode, first_run=a.first_run, control_dir=a.control_dir)
    if a.close_after:
        root.after(int(a.close_after * 1000), root.destroy)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
