"""Critique 2026-11-24: on the test VM only 10.0.2.2's lab ports get out; other connections Sysmon logged
there are ATTEMPTS. The allowance is read from the project's own VM setup script, not typed."""

import pytest

from engine.labs import network, _huntdb as db
from tests.labs import hunt_fixtures as fx


@pytest.fixture(autouse=True)
def no_dashboard(monkeypatch):
    from engine import labs
    monkeypatch.setattr(labs, "_current", None)


def test_the_allowance_comes_from_the_vm_setup_script():
    fw = network.vm_firewall()
    assert fw == {"host": "10.0.2.2", "ports": [8770, 18765], "source": "tools/vm/vm_guest_setup.ps1"}


def test_a_setup_without_a_default_block_allows_no_judgement(tmp_path):
    p = tmp_path / "setup.ps1"
    p.write_text("param([string]$HostAddr = '10.0.2.2', [int[]]$LabPorts = @(8770))\n", encoding="utf-8")
    assert network.vm_firewall(str(p)) is None                       # no "DefaultOutboundAction Block": can't tell
    assert network.vm_firewall(str(tmp_path / "missing.ps1")) is None


def test_connections_other_than_the_lab_ports_are_attempts(tmp_path, monkeypatch):
    fx.use_store(monkeypatch, fx.build(tmp_path / "e.db"))
    con = db.connect(db.events_path())
    try:
        out = network.view(con, db.window(con, "24h"))
    finally:
        con.close()
    by = {(p["program"].rsplit("\\", 1)[-1], p["dest"]): p["attempted"] for p in out["pairs"]}
    assert by[("evil.exe", "10.0.2.2:18765")] is False                # the test server: allowed out
    assert by[("chrome.exe", "142.250.0.1:443")] is True              # anything else: an attempt
    assert by[("svchost.exe", "10.0.2.3:53")] is True                 # a DNS server: an attempt too
    assert out["totals"]["attempted"] == sum(by.values()) and out["firewall"]["host"] == "10.0.2.2"
    assert "ATTEMPTED" in out["notes"][0] and "vm_guest_setup.ps1" in out["notes"][0]


def test_no_judgement_when_the_page_shows_every_machine(tmp_path, monkeypatch):
    fx.use_store(monkeypatch, fx.build(tmp_path / "e.db"), hosts=None)
    con = db.connect(db.events_path())
    try:
        out = network.view(con, db.window(con, "24h"))
    finally:
        con.close()
    assert out["firewall"] is None and not any(p["attempted"] for p in out["pairs"])
