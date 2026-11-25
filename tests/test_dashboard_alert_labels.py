"""The Story header's labels for a warm session's alerts (GET /api/alert-labels, 2026-11-23).

A numbered button per alert said nothing about WHOSE alert it was. Python now says it: the test whose own
programs the alert was raised on ("S1"), or that it was another program on the test machine. Decided by the
records (engine/dashboard/attribution.py), never by a name; no label at all when that can't be known yet."""

import pytest
from fastapi.testclient import TestClient

from engine.alerts import AlertStore
from engine.dashboard import app as dash
from engine.dashboard.app import create_app
from tests.test_dashboard_attribution import RUN_A, RUN_B, alert_on, keys_of, store, template
from tests.test_dashboard_words_scan import BANNED


class NoRun:
    log, started, lock = None, None, None

    def status(self):
        return type("S", (), {"running": False, "scenario": None, "started": None, "exit_code": None, "log_tail": []})()


class Session:
    """Stands in for the warm session: only what the labels read (its runs)."""

    def __init__(self, runs):
        self.runs = runs

    def status(self):
        return {"state": "ready", "runs": self.runs, "allowed": ["s1", "s4", "s5"], "used": []}


def client(tmp_path, path, alerts, session):
    s = AlertStore(str(tmp_path / "a.db"))
    s.write(alerts)
    s.close()
    return TestClient(create_app(path, str(tmp_path / "a.db"), recordings=str(tmp_path / "rec"), runner=NoRun(), warm=session))


def test_each_alert_is_labelled_with_the_test_whose_own_programs_raised_it_or_as_another_programs(tmp_path):
    path, t = store(tmp_path), template(tmp_path)
    own_a = alert_on(t, "A's own", keys_of(path, "{TA}", 11), 13)
    own_b = alert_on(t, "B's own", keys_of(path, "{TB}", 3), 63)
    shell = alert_on(t, "the telemetry's shell", keys_of(path, "{P}"), 45)
    runs = [{"scenario": "s5", "run_id": RUN_A, "step": "done"}, {"scenario": "s1", "run_id": RUN_B, "step": "done"}]
    c = client(tmp_path, path, [own_a, own_b, shell], Session(runs))
    labels = c.get("/api/alert-labels").json()
    assert labels[own_a.alert_id] == {"label": "S5", "kind": "test", "title": "Raised on S5's own programs"}
    assert labels[own_b.alert_id] == {"label": "S1", "kind": "test", "title": "Raised on S1's own programs"}
    assert labels[shell.alert_id] == {"label": "other", "kind": "other",
                                      "title": "Raised on another program on the test machine, not on a test's own programs"}
    assert set(labels) == {r["id"] for r in c.get("/api/alerts").json()}          # the alerts the screens show, each once
    # the alert list itself is exactly what it was: the labels are their own route
    assert set(c.get("/api/alerts").json()[0]) == {"id", "title", "rule", "source", "level", "time", "host", "reason", "events"}


def test_no_label_is_given_while_it_cannot_be_known(tmp_path):
    path, t = store(tmp_path), template(tmp_path)
    own_a = alert_on(t, "A's own", keys_of(path, "{TA}", 11), 13)
    shell = alert_on(t, "the telemetry's shell", keys_of(path, "{P}"), 45)
    # no warm session at all (a replay, a one-boot run): no labels, the buttons keep their numbers
    assert client(tmp_path, path, [own_a, shell], None).get("/api/alert-labels").json() == {}
    (tmp_path / "b").mkdir()
    assert client(tmp_path / "b", path, [own_a, shell], Session([])).get("/api/alert-labels").json() == {}
    # a test is going whose first program is not recorded yet: it could still own the shell's alert, so that
    # one gets no label; A's own alert is known and labelled
    (tmp_path / "c").mkdir()
    going = [{"scenario": "s5", "run_id": RUN_A, "step": "done"}, {"scenario": "s4", "run_id": "20261121-150000-aaaa", "step": "inserted"}]
    labels = client(tmp_path / "c", path, [own_a, shell], Session(going)).get("/api/alert-labels").json()
    assert labels == {own_a.alert_id: {"label": "S5", "kind": "test", "title": "Raised on S5's own programs"}}
    # once that test is over without ever having started a program, the others are "another program" again
    (tmp_path / "d").mkdir()
    going[1]["step"] = "failed"
    labels = client(tmp_path / "d", path, [own_a, shell], Session(going)).get("/api/alert-labels").json()
    assert labels[shell.alert_id]["kind"] == "other" and labels[own_a.alert_id]["label"] == "S5"
    # a session whose status can't be read: no labels, never an error
    (tmp_path / "e").mkdir()

    class Broken:
        def status(self):
            raise RuntimeError("the session's state can't be read")

    with pytest.raises(RuntimeError):
        Broken().status()
    app = create_app(path, str(tmp_path / "e" / "a.db"), recordings=str(tmp_path / "e" / "rec"), runner=NoRun(), warm=None)
    assert TestClient(app).get("/api/alert-labels").json() == {}


def test_the_labels_claim_whose_programs_and_nothing_about_harm():
    for text in dash.ALERT_LABEL_WORDS.values():
        assert not BANNED.search(text), text
        for word in ("harmless", "safe", "benign", "normal", "innocent", "ignore", "false alarm", "expected", "legitimate"):
            assert word not in text.lower(), (text, word)
