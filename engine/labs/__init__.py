"""Labs: where new investigation features live, so the rehearsed demo screens never change (2026-11-23).

THE CONTRACT (docs/night/2026-11-23.md). A lab's back end is ONE new file, `engine/labs/<name>.py`, with

    from fastapi import APIRouter
    from engine import labs

    router = APIRouter(prefix="/api/labs/<name>")       # <name> = the file's own name

    @router.get("")
    def something():
        ctx = labs.context()                            # the running dashboard's stores, READ-ONLY
        ...

Nothing else has to be touched: this package finds every such module and the dashboard includes its router.

What a lab gets from `labs.context()` (a `Context`; every method only READS):
    ctx.events_db, ctx.alerts_db      the paths the dashboard was started with (--events / --alerts)
    ctx.hosts                         the machines a lab may show: by default ONLY the lab's test machine
                                      (engine.dashboard.demo_mode.VM_HOSTS). None = no limit, which the
                                      dashboard sets only when it was started with --labs-all-hosts
    ctx.events()                      a read-only SQLite connection to the event store (close it yourself, or
                                      use `with ctx.reading() as con:`). The table `events` you see through
                                      it holds the allowed machines' rows only
    ctx.host_sql(column)              ("host IN (?, ...)", [values]) for a query on some OTHER store or table
    ctx.cases_dir                     where the case board keeps analyst cases (see "one exception" below)
    ctx.alerts()                      every alert in the alert database (engine.alerts.Alert objects)
    ctx.alert(alert_id)               one of them, or None
    ctx.shown_alerts()                the alerts at or above the frozen floor: what the screens show
    ctx.graph(host)                   the evidence graph of a host (the dashboard's own, cached)
    ctx.story(alert)                  (seed, time, sub-graph or None): the alert's own view of the graph, as the
                                      Story screen and the report build it (the seed's nodes have depth 0)
    ctx.report(alert)                 the alert's report content (facts, hypotheses, gaps, timeline, layout)
    ctx.event(key)                    one recorded event by its key, as a dict, or None

SPEED (night-hunt's audit, 2026-11-24). Two things are kept so a lab's page does not pay for them again:
  - ctx.report(alert) and ctx.story(alert) are built once per alert while the stores have not changed (a new
    event or a new alert makes them be built again). Every caller still gets its OWN copy, as before.
  - within one request, every ctx.event() uses ONE read-only connection (opening one per lookup cost about
    2.4 ms; a page that looks up thousands of records took a minute). It is closed when the request ends.
Neither changes an answer; both fall back to the old way if anything about them fails.

TEST-MACHINE DATA ONLY, BY DEFAULT (night plan rule 11). Everything the context hands out is limited to
`ctx.hosts`: the event connection (its `events` is a view of the allowed machines' rows), the alerts, the
graph, an alert's story and report. A lab that reads anything else by itself must apply `ctx.host_sql()`.
Laptop data is reachable only on a dashboard started with --labs-all-hosts (off by default), and never
belongs in a screenshot, a document or a test.

Rules a lab keeps (they are the project's, not this file's):
  - read only: never write to the event store, the alert database or recordings/. ONE EXCEPTION: the case
    board stores analyst cases as JSON files in recordings/cases/ (`ctx.cases_dir`; git-ignored like all of
    recordings/). Nothing else of a lab is ever written under recordings/;
  - never edit detectors or frozen code; a lab only shows what is recorded and what was decided;
  - privacy (DESIGN 9.1): nothing of the stores leaves this laptop; tests use fixtures, not recordings;
  - the honesty rules of the screens hold here too (Proven / Suspected / Can't be known; no overclaiming).

Safety of the dashboard itself: a lab that fails to import, has no `router`, whose router does not sit
under its own `/api/labs/<name>`, or that can't be included, is LEFT OUT and listed with its reason at
GET /api/labs (the Labs screen shows it as "failed to load"). A broken lab never stops the dashboard and
never takes over one of its routes. The whole of Labs can be switched off: `--no-labs`.
"""

import builtins
import collections
import contextlib
import contextvars
import copy
import dataclasses
import hashlib
import importlib
import inspect
import json
import keyword
import os
import pkgutil
import sqlite3
import threading
import traceback

from fastapi import APIRouter, Depends

_current = None                              # the Context of the dashboard running in this process
_scope = contextvars.ContextVar("analystlab_labs_request", default=None)    # the running request's _Scope, if any
_MISS = object()


class _Scope:
    """What ONE request of a lab keeps while it runs: one read-only connection per Context for all its
    ctx.event() lookups (with the Labs' own view of `events`, so another machine's record stays invisible), the
    records already looked up, and the stores' version. Closed when the request ends: no handle on the store
    outlives the request (an open handle would stop Windows replacing or deleting the file)."""

    MAX_ROWS = 50_000

    def __init__(self):
        self.lock = threading.RLock()            # a lab may hand work to its own threads
        self.cons, self.rows, self.versions, self.closed = {}, {}, {}, False
        self.opened = 0                          # connections opened in this request (tests read it)

    def event(self, ctx, key):
        with self.lock:
            if self.closed:
                raise RuntimeError("this request is over")
            hit = self.rows.get((ctx, key), _MISS)
            if hit is not _MISS:
                return dict(hit) if hit is not None else None
            con = self.cons.get(ctx)
            if con is None:
                con = ctx._open(any_thread=True)             # closed by close(), which may run on another thread
                self.cons[ctx] = con
                self.opened += 1
            try:
                cur = con.execute("SELECT * FROM events WHERE dedup_key = ?", (key,))
                try:
                    row, names = cur.fetchone(), [d[0] for d in cur.description]
                finally:
                    cur.close()
            except sqlite3.Error:
                self.cons.pop(ctx, None)                     # not trusted any more: the next lookup opens a new one
                con.close()
                raise
            out = {k: v for k, v in zip(names, row) if v is not None} if row else None
            if len(self.rows) < self.MAX_ROWS:
                self.rows[(ctx, key)] = out
            return dict(out) if out is not None else None

    def close(self):
        with self.lock:
            self.closed = True
            cons, self.cons, self.rows, self.versions = list(self.cons.values()), {}, {}, {}
        for con in cons:
            try:
                con.close()
            except Exception:
                pass


@contextlib.contextmanager
def session():
    """`with labs.session():` one request's scope by hand (tests, scripts). Lab routes get it by themselves."""
    scope = _Scope()
    token = _scope.set(scope)
    try:
        yield scope
    finally:
        try:
            _scope.reset(token)
        except ValueError:                       # ended in another context than it began in: nothing to put back
            pass
        scope.close()


async def request_scope():
    """The dependency every lab route gets in mount(): the request's _Scope, closed when the request ends."""
    with session():
        yield


class _Memo:
    """Values kept per key for ONE version of the stores (a new version empties it), at most `size` of them,
    and only one build of a key at a time: two requests for the same alert do not both build its report.
    A build that raises keeps nothing."""

    def __init__(self, size=64):
        self.lock = threading.Lock()
        self.version, self.items, self.gates, self.size = None, collections.OrderedDict(), {}, size
        self.builds = 0                          # how many times a value was really built (tests read it)

    def get(self, version, key, build):
        with self.lock:
            if self.version != version:
                self.items.clear()
                self.version = version
            if key in self.items:
                self.items.move_to_end(key)
                return self.items[key]
            gate = self.gates.setdefault((version, key), threading.Lock())
        with gate:
            with self.lock:
                if self.version == version and key in self.items:       # built while this caller waited
                    return self.items[key]
            try:
                value = build()
                with self.lock:
                    self.builds += 1
                    if self.version == version:
                        self.items[key] = value
                        while len(self.items) > self.size:
                            self.items.popitem(last=False)
                return value
            finally:
                with self.lock:
                    self.gates.pop((version, key), None)


class Context:
    """The running dashboard's stores, for reading. Built by engine/dashboard/app.py; labs only use it."""

    def __init__(self, events_db, alerts_db, recordings=None, graph=None, story=None, report=None, min_level=None, hosts=None):
        self.events_db, self.alerts_db, self.recordings = events_db, alerts_db, recordings
        self._graph, self._story, self._report, self._min_level = graph, story, report, min_level
        # the machines a lab may show; None = no limit (the dashboard passes the test machine's names by default)
        self.hosts = None if hosts is None else frozenset(hosts)
        self._reports, self._stories = _Memo(), _Memo()      # per alert, while the stores have not changed
        # ONE heavy build at a time (the graph, a story, a report). They are plain Python, so two at once are no
        # faster than one after the other, and without this, pages opened together each built the whole graph
        # (the dashboard's own graph cache does not make a second asker wait for the first).
        self._building = threading.RLock()

    @property
    def cases_dir(self):
        """Where the case board keeps analyst cases (the one place under recordings/ a lab may write to)."""
        return os.path.join(self.recordings, "cases") if self.recordings else None

    def allows(self, host):
        """May a lab show this machine's data?"""
        return self.hosts is None or host in self.hosts

    def host_sql(self, column="host"):
        """("<column> IN (?, ...)", [names]) for the allowed machines, or ("1=1", []) when there is no limit."""
        if self.hosts is None:
            return "1=1", []
        names = sorted(self.hosts)
        return (f"{column} IN ({', '.join('?' * len(names))})" if names else "0=1"), names

    def _must_allow(self, host, what):
        if not self.allows(host):
            raise PermissionError(f"labs show the test machine's data only ({what} of another machine was asked for; "
                                  "see --labs-all-hosts)")

    # -- the event store -------------------------------------------------------------------------------
    def events(self):
        """A READ-ONLY connection to the event store (SQLite refuses every write on it). Close it yourself."""
        return self._open()

    def _open(self, any_thread=False):
        if not self.events_db or not os.path.exists(self.events_db):
            raise FileNotFoundError("this dashboard has no event store yet")
        con = sqlite3.connect("file:" + os.path.abspath(self.events_db).replace("\\", "/") + "?mode=ro", uri=True,
                              check_same_thread=not any_thread)
        if self.hosts is not None:
            # `events`, as a lab sees it, is the allowed machines' rows: a view in the connection's own
            # temporary schema, which SQLite looks in first. (The store itself stays read-only and untouched.)
            where, names = self.host_sql("host")
            quoted = ", ".join("'" + n.replace("'", "''") + "'" for n in names)
            try:
                con.execute("CREATE TEMP VIEW events AS SELECT * FROM main.events WHERE " + (f"host IN ({quoted})" if names else "0=1"))
            except sqlite3.OperationalError:             # no events table yet: nothing to limit
                pass
        return con

    @contextlib.contextmanager
    def reading(self):
        """`with ctx.reading() as con:` a read-only connection that is closed for you."""
        con = self.events()
        try:
            yield con
        finally:
            con.close()

    def event(self, key):
        """One recorded event by its key (the `dedup_key` the reports cite), as a dict; None when there is none.
        Inside a request all lookups share the request's one connection (_Scope); outside one, or if that fails
        in any unexpected way, each lookup opens and closes its own, as it always did."""
        scope = _scope.get()
        if scope is not None:
            try:
                return scope.event(self, key)
            except (FileNotFoundError, sqlite3.OperationalError):
                return None
            except Exception:
                pass
        try:
            with self.reading() as con:
                con.row_factory = sqlite3.Row
                row = con.execute("SELECT * FROM events WHERE dedup_key = ?", (key,)).fetchone()
        except (FileNotFoundError, sqlite3.OperationalError):
            return None
        return {k: row[k] for k in row.keys() if row[k] is not None} if row else None

    # -- the alerts ------------------------------------------------------------------------------------
    def alerts(self):
        """Every alert in the alert database (engine.alerts.Alert objects), as raised; [] when there is none.
        READ-ONLY, like the event store (review of 2026-11-24): the alert store's own class opens the file for
        writing and may CREATE its table or ALTER it when it is opened. A lab never does that: the file is
        opened with SQLite's mode=ro, and the store's own reader runs on that connection."""
        if not self.alerts_db or not os.path.exists(self.alerts_db):
            return []
        from engine.alerts import AlertStore
        con = sqlite3.connect("file:" + os.path.abspath(self.alerts_db).replace("\\", "/") + "?mode=ro", uri=True)
        try:
            columns = {r[1] for r in con.execute("PRAGMA table_info(alerts)")}
            if not columns:                              # a store with no alerts table yet: nothing was raised
                return []
            if "incident" not in columns:
                # a store from before incidents: the reader asks for that column, so it sees an empty one through
                # a view in THIS connection's own temporary schema (the file is not altered)
                con.execute("CREATE TEMP VIEW alerts AS SELECT *, NULL AS incident FROM main.alerts")
            store = AlertStore.__new__(AlertStore)       # the reader without __init__ (which is what writes)
            store.db = con
            return [a for a in store.read() if self.allows(a.host)]
        finally:
            con.close()

    def alert(self, alert_id):
        return builtins.next((a for a in self.alerts() if a.alert_id == alert_id), None)

    def min_level(self):
        """The frozen alert floor (what the screens show starts here)."""
        if self._min_level:
            return self._min_level() if callable(self._min_level) else self._min_level
        from engine import config
        return config.min_level()

    def shown_alerts(self):
        """The alerts at or above the frozen floor, newest first: exactly what the dashboard's own list shows."""
        from engine.alerts import LEVELS
        floor = LEVELS.index(self.min_level())
        return sorted((a for a in self.alerts() if LEVELS.index(a.level) >= floor), key=lambda a: a.time, reverse=True)

    # -- the evidence graph, as the dashboard itself builds it -----------------------------------------------
    def graph(self, host=None):
        """The evidence graph of `host` (the dashboard's own cached one; rebuilt when the store grew)."""
        self._need(self._graph, "the evidence graph")
        self._must_allow(host, "the graph")
        with self._building:
            return self._graph(host)

    def story(self, alert):
        """(seed, time, sub-graph or None) of an alert: its own view of the graph, as Story and the report use it
        (engine.report.alert_view; the sub-graph's seed nodes carry depth 0)."""
        self._need(self._story, "an alert's story")
        self._must_allow(alert.host, "an alert")
        kept, fresh = self._kept(self._stories, alert, lambda: self._story(alert))
        if fresh:
            return kept
        try:                                     # the caller's own graph, as a fresh build gave it
            seed, at, H = kept
            if H is not None:
                mine = H.copy()
                mine.graph.update(copy.deepcopy(dict(H.graph)))
                H = mine
            return copy.copy(seed), at, H
        except Exception:
            return self._story(alert)

    def report(self, alert):
        """The alert's report content (facts, hypotheses, gaps, timeline, layout, verdict): Python's own words."""
        self._need(self._report, "an alert's report")
        self._must_allow(alert.host, "an alert")
        kept, fresh = self._kept(self._reports, alert, lambda: self._report(alert))
        if fresh:
            return kept
        try:
            return copy.deepcopy(kept)           # the caller's own copy: a lab may change what it was given
        except Exception:
            return self._report(alert)

    # -- built once per alert while the stores have not changed ----------------------------------------------
    def _kept(self, memo, alert, build):
        """(value, fresh): the kept value for this alert, or a fresh build (fresh=True: the caller's alone) when
        nothing can be kept: the stores' version or the alert can't be read as a key."""
        def one_at_a_time():
            with self._building:
                return build()
        version, key = self._version(), self._alert_key(alert)
        if version is None or key is None:
            return one_at_a_time(), True
        return memo.get(version, key, one_at_a_time), False

    def _version(self):
        """What an alert's story and report depend on in the stores, or None when it can't be read: the newest
        event's row id (the store is append-only: a new event raises it; the dashboard's own graph cache uses the
        same) and the alert database's row count and newest row. Read once per request."""
        scope = _scope.get()
        if scope is not None:
            with scope.lock:
                if self in scope.versions:
                    return scope.versions[self]
        version = self._read_version()
        if scope is not None:
            with scope.lock:
                if not scope.closed:
                    scope.versions[self] = version
        return version

    def _read_version(self):
        def one(path, sql):
            con = sqlite3.connect("file:" + os.path.abspath(path).replace("\\", "/") + "?mode=ro", uri=True)
            try:
                return tuple(con.execute(sql).fetchone())
            finally:
                con.close()
        try:
            if not self.events_db or not os.path.exists(self.events_db):
                return None
            # (the store itself, not the Labs' view of it: MAX over a view would read every row)
            events = one(self.events_db, "SELECT MAX(id) FROM main.events")
            alerts = (one(self.alerts_db, "SELECT COUNT(*), MAX(rowid) FROM alerts")
                      if self.alerts_db and os.path.exists(self.alerts_db) else ())
            return events + alerts
        except (sqlite3.Error, OSError):
            return None

    @staticmethod
    def _alert_key(alert):
        """(alert id, a fingerprint of everything the alert says), or None. The fingerprint is why an alert
        that was rewritten in place (same id, same count) is not answered from an older build."""
        try:
            alert_id = getattr(alert, "alert_id", None)
            if not alert_id:
                return None
            said = dataclasses.asdict(alert) if dataclasses.is_dataclass(alert) else dict(vars(alert))
            return alert_id, hashlib.sha1(json.dumps(said, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        except Exception:
            return None

    @staticmethod
    def _need(fn, what):
        if fn is None:
            raise RuntimeError(f"this dashboard was started without {what}")


def context():
    """The running dashboard's Context. A lab calls this inside its route functions (not at import time)."""
    if _current is None:
        raise RuntimeError("no dashboard is running in this process (engine.labs.context() is set by engine/dashboard/app.py)")
    return _current


def configure(ctx):
    """Called by the dashboard when it starts (and by tests): the Context labs will read from."""
    global _current
    _current = ctx
    return ctx


def discover(package=None):
    """Every lab module of this package: ([(name, router)], [{name, problem}]). A module that can't be
    imported, has no APIRouter called `router`, or whose router is not under /api/labs/<its own name>
    is a problem, never an exception."""
    package = package or __name__
    pkg = importlib.import_module(package)
    good, bad = [], []
    for info in builtins.sorted(pkgutil.iter_modules(pkg.__path__), key=lambda i: i.name):
        name = info.name
        if name.startswith("_"):
            continue
        # A lab's file becomes an attribute of this package when it is imported. A file called like a Python
        # builtin (next.py, open.py, filter.py, ...) or like a name this package itself uses (context.py,
        # mount.py, ...) would REPLACE that name for the whole package and break every lab (found by
        # night-explain, 2026-11-23: engine/labs/next.py made Context.alert() fail). Such a file is never
        # imported: it is left out and told to take another name.
        taken = getattr(pkg, name, None)
        if (name in _BUILTIN_NAMES or name in _RESERVED or keyword.iskeyword(name)
                or (taken is not None and not (inspect.ismodule(taken) and getattr(taken, "__name__", "") == f"{package}.{name}"))):
            bad.append({"name": name, "problem": f"its file name '{name}.py' is a name Python or the Labs registry already uses: "
                                                 "rename the file (and its /api/labs/<name> prefix)"})
            continue
        try:
            mod = importlib.import_module(f"{package}.{name}")
        except Exception as e:                       # a lab's own mistake: reported, never fatal
            bad.append({"name": name, "problem": f"could not be loaded: {type(e).__name__}: {e}",
                        "detail": traceback.format_exc(limit=3)})
            continue
        router = getattr(mod, "router", None)
        if not isinstance(router, APIRouter):
            bad.append({"name": name, "problem": "has no `router` (an APIRouter)"})
            continue
        want = f"/api/labs/{name}"
        paths = [r.path for r in router.routes if hasattr(r, "path")]
        if router.prefix != want or any(not (p == want or p.startswith(want + "/")) for p in paths):
            bad.append({"name": name, "problem": f"its router must have prefix {want} (it has {router.prefix!r})"})
            continue
        good.append((name, router))
    return good, bad


_BUILTIN_NAMES = frozenset(dir(builtins))
_RESERVED = frozenset({"state"})                 # /api/labs/state is the shell's own (see mount)


def _run_names():
    """Everyday names of the lab's test runs for the labs' pickers (engine/labs/_names.py). Never a reason for
    the listing to fail: without them a run is shown as "unnamed run"."""
    try:
        from engine.labs._names import run_names
        return run_names()
    except Exception:
        return {}


def mount(app, ctx, package=None):
    """Include every lab's router in the dashboard and add GET /api/labs (which labs are in, which were left
    out and why). Returns the list GET /api/labs gives."""
    configure(ctx)
    found, bad = discover(package)
    good = []
    for name, router in found:
        try:                                         # one lab's trouble is that lab's alone
            # every lab route runs inside one request scope (one connection for its event lookups; see _Scope)
            app.include_router(router, dependencies=[Depends(request_scope)])
            good.append((name, router))
        except Exception as e:
            bad.append({"name": name, "problem": f"could not be included: {type(e).__name__}: {e}"})
    listing = {"enabled": True, "labs": [{"name": n, "prefix": f"/api/labs/{n}"} for n, _ in good],
               "left_out": [{"name": b["name"], "problem": b["problem"]} for b in bad],
               "hosts": None if ctx.hosts is None else sorted(ctx.hosts),
               "run_names": _run_names()}
    for b in bad:
        print(f"labs: '{b['name']}' left out: {b['problem']}", flush=True)
    index = APIRouter()

    @index.get("/api/labs")
    def labs_index():
        return listing

    @index.get("/api/labs/state")
    def labs_state():
        """May a lab speak yet? `replay`: None on a dashboard that is not a demo replay; otherwise how many
        records the recording holds and whether the replay has finished filling the store (engine/labs/_replay.py).
        The Labs shell draws no lab while a replay is not done."""
        try:
            from engine.labs import _replay
            return {"replay": _replay.state()}
        except Exception:
            return {"replay": None}

    app.include_router(index)
    return listing


def switched_off(app):
    """The dashboard was started with --no-labs: no lab is loaded, and GET /api/labs says so (the page then
    shows no Labs entry at all)."""
    index = APIRouter()

    @index.get("/api/labs")
    def labs_index():
        return {"enabled": False, "labs": [], "left_out": [], "hosts": []}

    app.include_router(index)
