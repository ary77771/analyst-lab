"""Agent entry point.

    python -m agent.main                      # record Sysmon (needs administrator rights)
    python -m agent.main --channel Application --label test --run-seconds 30

Loop: wait for Windows to signal new events -> read a batch -> enrich -> write to the
JSONL recording (flushed to disk) -> only then save the bookmark. Every 10 s the agent
also snapshots listening ports; every 5 s it writes a status heartbeat for the status app.

The agent runs unattended for days, so nothing short of a stop request ends the loop:
side jobs (ports, status) are isolated, a failed disk write is retried without moving the
bookmark, and every problem goes to a rotating log file (pythonw has no console).
"""

import argparse
import logging
import logging.handlers
import os
import socket
import time
import uuid
from datetime import datetime, timezone

import psutil

from . import ports
from .control import PauseWatch
from .paths import frozen, project_root, recordings_root
from .enrich import OriginTagger, file_to_hash, hash_when_closed
from .eventlog import ChannelReader
from .sink import HttpSink, JsonlSink
from .state import atomic_write_text, read_text, write_json

PROJECT_ROOT = project_root()        # the bundle's install folder when frozen (agent/paths.py)
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
VIRTUALBOX_DIR = r"C:\Program Files\Oracle\VirtualBox"
RETRY_SECONDS = 5
HASH_WAIT_SECONDS = 120     # how long to wait for a new file's writer to finish before giving up
HASH_QUEUE_MAX = 2000       # beyond this, new files get a "skipped_queue_full" gap record
HASH_BUDGET_SECONDS = 0.5   # max time spent hashing per loop pass
RESUBSCRIBE_AFTER = 5       # consecutive loop errors before rebuilding the event-log subscription
IDLE_RESUBSCRIBE = 300      # seconds without any event signal before rebuilding it anyway: the loop
                            # reads only when Windows signals, so a subscription that died silently
                            # would otherwise go unnoticed (bookmark is current: no loss, no dupes)

log = logging.getLogger("agent")


def utc_now() -> str:
    """UTC time in Sysmon's own format (7 fractional digits + Z), so all times sort as text."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"


def setup_logging(state_dir: str) -> None:
    os.makedirs(state_dir, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        os.path.join(state_dir, "agent.log"), maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    root = logging.getLogger("agent")
    root.handlers[:] = [handler]
    root.setLevel(logging.INFO)


class Agent:
    def __init__(self, args):
        self.args = args
        self.session = uuid.uuid4().hex[:12]
        self.host = socket.gethostname()
        self.started = utc_now()
        self.state_dir = args.state_dir or os.path.join(args.recordings, ".state", args.label)
        self.bookmark_path = os.path.join(self.state_dir, "bookmark.xml")
        self.status_path = os.path.join(self.state_dir, "status.json")
        setup_logging(self.state_dir)

        if args.send_to:
            key = None
            if args.lab_key_file:                                # VM: the lab key, readable by admins only
                with open(args.lab_key_file, encoding="ascii") as f:
                    key = f.read().strip()
            self.sink = HttpSink(args.send_to, args.label, key=key)   # VM: batches go to the host receiver
        else:
            self.sink = JsonlSink(os.path.join(args.recordings, args.label))
        self._pending = None          # (events, records) read but not yet confirmed written
        self._pending_agent = []      # agent records (ports, file hashes) not yet confirmed written
        self._hash_queue = []         # new files waiting until their writer has finished
        self.last_error = None
        # On friends' laptops (the bundle) only the install folder is "our own tools": their own
        # VirtualBox or Claude use is normal use there (review 2026-10-19)
        # The lab VM's agent (it sends to the laptop) tags strictly: see OriginTagger(strict=True)
        self.tagger = OriginTagger(PROJECT_ROOT, extra_prefixes=[] if frozen() else [VIRTUALBOX_DIR],
                                   dev_tools=not frozen(), strict=bool(args.send_to))
        # "pause for 1 hour" from the status app; the bundle keeps it in a friend-writable folder
        self.pauses = PauseWatch(args.control_dir or self.state_dir, enabled=not args.send_to)   # no pause in the lab VM
        self.paused_events = 0
        self._compressor = None
        self._ports_rebaseline = False
        self.reader = self._open_reader()
        self.source = "sysmon" if args.channel == SYSMON_CHANNEL else "windows"
        log.info("start session=%s channel=%s resumed=%s root=%s", self.session, args.channel, self.reader.resumed, PROJECT_ROOT)
        if self.reader.fallback_reason:
            log.warning(self.reader.fallback_reason)

        self.seq = 0
        self.errors = 0
        self.last_event_time = None
        self.last_record_id = None
        self.port_images = {}
        self.ports_before = {}
        if not args.no_ports:
            self.ports_before = self._safe_ports() or {}
            self._remember_images(self.ports_before)
        self.process = psutil.Process()
        self.process.cpu_percent(None)

    def _open_reader(self) -> ChannelReader:
        """Subscribe to the channel, resuming after the last saved bookmark if there is one."""
        return ChannelReader(
            self.args.channel,
            bookmark_xml=read_text(self.bookmark_path),
            start_at_oldest=(self.args.start == "oldest"),
            query=self.args.query,
        )

    # -- records -------------------------------------------------------------------
    def _base(self) -> dict:
        return {"host": self.host, "label": self.args.label, "session": self.session}

    def _event_record(self, event: dict) -> dict:
        record = self._base()
        record.update({
            "source": self.source,
            "channel": event["channel"],
            "record_id": event["record_id"],
            "event_id": event["event_id"],
            "provider": event["provider"],
            "time": event["time"],
            "origin": self.tagger.tag(event),     # still run while paused: keeps process lineage
            "data": event["data"],
        })
        if self.pauses.covers(event["time"]):
            # paused: keep only that something happened (number, time, type), never what
            record.update({"paused": True, "data": {}})
            self.paused_events += 1
            return record
        if "parse_error" in event:
            record["parse_error"] = event["parse_error"]
            record["raw_xml"] = event["raw_xml"]
            self.errors += 1
            log.error("unparsable event record_id=%s: %s", event["record_id"], event["parse_error"])
        elif not self.args.no_hash and record["origin"] != "project":
            # Our own development work (pip/npm installs, builds) is excluded from analysis, so
            # its thousands of new files are not fingerprinted.
            path = file_to_hash(event)
            if path:                       # fingerprint later, once the file's writer is done
                item = {"path": path, "ref_record_id": event["record_id"], "ref_time": event["time"],
                        "ProcessGuid": event["data"].get("ProcessGuid"), "origin": record["origin"],
                        "deadline": time.monotonic() + HASH_WAIT_SECONDS}
                if len(self._hash_queue) < HASH_QUEUE_MAX:
                    self._hash_queue.append(item)
                else:                      # overflow: record it as a gap instead of growing forever
                    self._pending_agent.append(self._file_hash_record(item, "skipped_queue_full", None, None))
        return record

    def _file_hash_record(self, item, status, sha256, size, final=None) -> dict:
        self.seq += 1
        record = self._base()
        record.update({
            "source": "agent", "seq": self.seq, "type": "FILE_HASH", "time": utc_now(),
            "origin": item["origin"],
            "data": {"TargetFilename": item["path"], "ProcessGuid": item["ProcessGuid"],
                     "hash_status": status, "sha256": sha256, "size": size, "final_path": final,
                     "ref_record_id": item["ref_record_id"], "ref_time": item["ref_time"]},
        })
        return record

    def _process_hash_queue(self) -> None:
        """Fingerprint queued files whose writer has finished; emit one FILE_HASH record each.
        Spends at most HASH_BUDGET_SECONDS per call, so a burst of new files can't stall event
        reading or the heartbeat; the rest wait for the next loop pass."""
        started = time.monotonic()
        done, still_waiting = [], []
        for i, item in enumerate(self._hash_queue):
            if time.monotonic() - started > HASH_BUDGET_SECONDS:
                still_waiting.extend(self._hash_queue[i:])
                break
            try:
                status, sha256, size, *extra = hash_when_closed(item["path"])
            except Exception:
                log.exception("hashing failed for a queued file")
                status, sha256, size, extra = "unreadable", None, None, []
            if status == "busy" and time.monotonic() < item["deadline"]:
                still_waiting.append(item)
                continue
            if status == "busy":
                status = "busy_timeout"
            done.append(self._file_hash_record(item, status, sha256, size, extra[0] if extra else None))
        self._pending_agent.extend(done)
        self._hash_queue = still_waiting

    def _pause_records(self) -> list:
        """PAUSE_START / PAUSE_CHANGE / PAUSE_END records for the timeline (counts only)."""
        records = []
        for kind, requested, until in self.pauses.poll(utc_now()):
            self.seq += 1
            record = self._base()
            data = {"requested": requested, "until": until}
            if kind == "end":
                data["paused_events_this_session"] = self.paused_events
            if kind == "start":
                self._ports_rebaseline = True
            record.update({"source": "agent", "seq": self.seq, "type": f"PAUSE_{kind.upper()}",
                           "time": utc_now(), "origin": "normal", "data": data})
            records.append(record)
            log.info("pause %s: %s -> %s", kind, requested, until)
        return records

    def _compress_finished(self) -> None:
        """Friend laptops (--compress-finished): gzip this label's finished days in the background
        (~300 MB a day -> ~20 MB), with the same safe steps as tools/compress_recordings.py. Runs
        in a thread so the heartbeat and event reading never wait for it."""
        if self._compressor is not None and self._compressor.is_alive():
            return

        def work():
            from tools import compress_recordings as cr
            try:
                todo = [p for label, p in cr.finished_days(self.args.recordings, idle_hours=2)
                        if label == self.args.label]
            except OSError:
                log.exception("listing finished days failed")
                return
            for path in todo:
                try:
                    before, after = cr.compress(path)
                    log.info("compressed a finished day: %.0f -> %.0f MB", before / 2**20, after / 2**20)
                except cr.StillOpen:
                    log.info("a finished day is still open; compressed copy kept, retry later")
                except (OSError, ValueError):
                    log.exception("compressing a finished day failed; original kept")

        import threading
        self._compressor = threading.Thread(target=work, name="compress", daemon=True)
        self._compressor.start()

    def _rebaseline_ports(self) -> None:
        """After a pause: take the current listening ports as the new 'before', silently."""
        now = self._safe_ports()
        if now is None:
            return
        self._remember_images(now)
        self.ports_before = now
        self._ports_rebaseline = False
        log.info("port baseline reset after a pause (%s listening)", len(now))

    def _safe_ports(self):
        try:
            return ports.listening_ports()
        except Exception:
            log.exception("port snapshot failed")
            return None

    def _remember_images(self, snapshot: dict) -> None:
        for key, pid in snapshot.items():
            if key not in self.port_images or self.port_images[key][0] != pid:
                self.port_images[key] = (pid, ports.process_image(pid), ports.process_start(pid))

    def _port_records(self) -> list:
        now = self._safe_ports()
        if now is None:
            return []
        started, stopped = ports.diff(self.ports_before, now)
        # Program names for STOP records come from the map as it was BEFORE this snapshot, so a
        # port that changed owner gets the old owner on its STOP (review finding M2).
        old_owners = {key: self.port_images.get(key, (None, None, None))[1:] for key in self.ports_before}
        self._remember_images(now)
        records = []
        # stops first, so a port that changed owner reads STOP(old) then START(new)
        for kind, items in (("PORT_LISTEN_STOP", stopped), ("PORT_LISTEN_START", started)):
            for ip, port, pid in items:
                self.seq += 1
                if kind == "PORT_LISTEN_STOP":
                    image, start = old_owners.get((ip, port), (None, None))
                else:
                    image, start = self.port_images[(ip, port)][1:]
                record = self._base()
                record.update({
                    "source": "agent", "seq": self.seq, "type": kind, "time": utc_now(),
                    "origin": "project" if image and self.tagger.is_inside(image) else "normal",
                    "data": {"LocalIp": ip, "LocalPort": port, "ProcessId": pid, "Image": image,
                             "ProcessStartUtc": start},
                })
                records.append(record)
        for ip, port, pid in stopped:
            if (ip, port) not in now:
                self.port_images.pop((ip, port), None)
        self.ports_before = now
        return records

    # -- status --------------------------------------------------------------------
    def write_status(self) -> None:
        try:
            mem = self.process.memory_info().rss / (1024 * 1024)
            cpu = self.process.cpu_percent(None) / (psutil.cpu_count() or 1)
            write_json(self.status_path, {
                "agent_pid": os.getpid(), "session": self.session, "host": self.host,
                "label": self.args.label, "channel": self.args.channel, "started": self.started,
                "updated": utc_now(), "events_written": self.sink.written,
                "last_event_time": self.last_event_time, "last_record_id": self.last_record_id,
                "recording_file": self.sink.current_path, "resumed_from_bookmark": self.reader.resumed,
                "bookmark_fallback": self.reader.fallback_reason, "errors": self.errors,
                "last_error": self.last_error, "files_waiting_for_hash": len(self._hash_queue),
                "cpu_percent_of_machine": round(cpu, 2), "memory_mb": round(mem, 1),
                "paused_until": self.pauses.paused_until,
            })
        except Exception:
            self.errors += 1
            log.exception("status write failed")

    # -- main loop -----------------------------------------------------------------
    def _drain(self) -> None:
        """Write batches until none are waiting. A batch that can't be written (disk error,
        receiver down) is kept as pending and retried on the next loop pass; no new events are
        read and the bookmark doesn't move until it succeeds, so nothing is ever skipped."""
        while True:
            if self._pending is None:
                # re-read the pause file before EVERY batch: during a long catch-up a pause
                # clicked meanwhile must cover the very next batch (review 2026-10-19)
                self._pending_agent.extend(self._pause_records())
                events = self.reader.next_batch()
                if not events:
                    return
                self._pending = (events, [self._event_record(e) for e in events])
            events, records = self._pending
            try:
                self.sink.write_batch(records)                                  # 1. data stored
            except OSError as e:
                self.errors += 1
                self.last_error = f"{utc_now()} {e}"
                log.exception("writing %s events failed; keeping them and retrying in %ss",
                              len(records), RETRY_SECONDS)
                time.sleep(RETRY_SECONDS)
                return
            atomic_write_text(self.bookmark_path, self.reader.bookmark_xml())   # 2. then position
            self._pending = None
            self.last_event_time = events[-1]["time"] or self.last_event_time
            self.last_record_id = events[-1]["record_id"] or self.last_record_id

    def _flush_agent_records(self, final: bool = False) -> None:
        """Write agent-made records (port changes, file hashes); keep them if that fails.
        While a batch of events is still unsent, wait: a file's hash must never arrive before
        the event that created it (the VM runner's flush barrier relies on this order;
        independent review 2026-10-18). On exit (final) they are written anyway."""
        if not self._pending_agent or (self._pending is not None and not final):
            return
        try:
            self.sink.write_batch(self._pending_agent)
            self._pending_agent = []
        except OSError as e:
            self.errors += 1
            self.last_error = f"{utc_now()} {e}"
            log.exception("writing agent records failed; keeping them for the next attempt")

    def run(self) -> None:
        deadline = time.monotonic() + self.args.run_seconds if self.args.run_seconds else None
        next_ports = time.monotonic() + self.args.port_interval
        next_status = time.monotonic()
        next_compress = time.monotonic() + self.args.compress_delay
        consecutive_errors = 0
        last_signal = time.monotonic()
        try:
            while deadline is None or time.monotonic() < deadline:
                try:
                    # pauses first, so a pause that just began covers this pass's events
                    self._pending_agent.extend(self._pause_records())
                    # read only when Windows signals new events, or to retry a batch that
                    # couldn't be written (it was read while signalled; the signal stays set
                    # until a read finds nothing)
                    if self.reader.wait(1000):
                        last_signal = time.monotonic()
                        self._drain()
                    elif self._pending is not None:
                        self._drain()
                    elif time.monotonic() - last_signal >= IDLE_RESUBSCRIBE:
                        log.info("no event signal for %ss; rebuilding the subscription as a precaution", IDLE_RESUBSCRIBE)
                        self.reader = self._open_reader()       # from the saved (current) bookmark
                        last_signal = time.monotonic()
                    now = time.monotonic()
                    if not self.args.no_ports and now >= next_ports and self.pauses.active is None:
                        # no port snapshots while paused (they name programs), and the first one
                        # after a pause only becomes the new baseline: reporting what changed
                        # meanwhile would name programs started during the pause (review 2026-10-19)
                        if self._ports_rebaseline:
                            self._rebaseline_ports()
                        else:
                            self._pending_agent.extend(self._port_records())
                        next_ports = now + self.args.port_interval
                    if self._hash_queue:
                        self._process_hash_queue()
                    self._flush_agent_records()
                    if self.args.compress_finished and now >= next_compress:
                        self._compress_finished()
                        next_compress = now + 3600
                    if now >= next_status:
                        self.write_status()
                        next_status = now + 5
                    consecutive_errors = 0
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    # Unexpected problem: log it, pause, keep going. The bookmark was not
                    # advanced past unsaved events, so nothing is lost.
                    self.errors += 1
                    consecutive_errors += 1
                    self.last_error = f"{utc_now()} {type(e).__name__}: {e}"
                    log.exception("unexpected error in main loop; continuing in %ss", RETRY_SECONDS)
                    time.sleep(RETRY_SECONDS)
                    if consecutive_errors >= RESUBSCRIBE_AFTER:
                        # e.g. the log was cleared or Sysmon reconfigured: start a fresh
                        # subscription from the last SAVED bookmark (unsaved events are re-read)
                        log.warning("%s errors in a row; rebuilding the event-log subscription", consecutive_errors)
                        try:
                            self._pending = None
                            self.reader = self._open_reader()
                            consecutive_errors = 0
                        except Exception:
                            log.exception("rebuilding the subscription failed; will retry")
        except KeyboardInterrupt:
            pass
        finally:
            try:                                  # last chance for port/hash records
                if self._hash_queue:
                    self._process_hash_queue()
                self._flush_agent_records(final=True)
            except Exception:
                log.exception("final flush failed")
            self.write_status()
            self.sink.close()
            log.info("stop session=%s events_written=%s errors=%s", self.session, self.sink.written, self.errors)


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Analyst Lab agent")
    p.add_argument("--channel", default=SYSMON_CHANNEL)
    p.add_argument("--query", default="*", help="XPath filter (default: all events)")
    p.add_argument("--label", default="host", help="recording folder name, e.g. host or vm")
    p.add_argument("--recordings", default=recordings_root())
    p.add_argument("--state-dir", default=None)
    p.add_argument("--control-dir", default=None,
                   help="where the status app writes pause.json (default: the state folder)")
    p.add_argument("--start", choices=["oldest", "now"], default="oldest",
                   help="where to start when there is no saved bookmark")
    p.add_argument("--run-seconds", type=float, default=0, help="stop after N seconds (0 = run forever)")
    p.add_argument("--port-interval", type=float, default=10.0)
    p.add_argument("--no-ports", action="store_true")
    p.add_argument("--no-hash", action="store_true")
    p.add_argument("--compress-finished", action="store_true",
                   help="gzip this label's finished days every hour (friend laptops)")
    p.add_argument("--compress-delay", type=float, default=600, help=argparse.SUPPRESS)
    p.add_argument("--lab-key-file", default=None,
                   help="with --send-to: file holding the lab key the receiver requires (VM, security review 2026-10-23)")
    p.add_argument("--send-to", default=None,
                   help="send batches to a VM receiver URL (e.g. http://10.0.2.2:8770) instead of local files")
    return p.parse_args(argv)


def single_instance(state_dir: str):
    """A Windows named mutex per state folder: a second agent writing the same recording and
    bookmark would interleave lines. Returns the handle (keep it alive), or None if taken."""
    import hashlib

    import win32api
    import win32event
    import winerror

    name = "Local\\AnalystLabAgent-" + hashlib.sha1(os.path.abspath(state_dir).lower().encode()).hexdigest()[:16]
    handle = win32event.CreateMutex(None, False, name)
    if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
        return None
    return handle


def main(argv=None):
    args = parse_args(argv)
    state_dir = args.state_dir or os.path.join(args.recordings, ".state", args.label)
    lock = single_instance(state_dir)
    if lock is None:
        setup_logging(state_dir)
        log.warning("another agent is already running for %s; exiting", state_dir)
        return 3
    try:
        Agent(args).run()
    except Exception:
        log.exception("agent crashed")   # recorded even under pythonw (no console)
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
