"""Noise meter (engine/labs/noise.py): counts read from the committed official results, never typed."""

import subprocess

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine.labs import noise

SAMPLE = """# Version 9 evaluation: J4 false alerts per active hour (normal use) (official)

- Active hours: **10.0**
- RAISED alerts (>= medium): **1,000** = **100.00 per active hour**
- All levels: 3,000 = 300.00 per active hour

| level | alerts | per active hour |
|---|---:|---:|
| informational | 1,500 | 150.0 |
| low | 500 | 50.0 |
| medium | 990 | 99.0 |
| high | 10 | 1.0 |
| critical | 0 | 0.000 |

## Raised alerts by rule (the ones an analyst would see)

| source | level | rule | alerts | per active hour | days | programs | where the programs live |
|---|---|---|---:|---:|---:|---:|---|
| analystlab | medium | SOME RULE NAME | 900 | 90.0 | 6 | 39 | Program Files 4947 |
| sigma | medium | OTHER RULE NAME | 100 | 10.0 | 1 | 1 | other 105 |

## Something else
| x | y | z | 99999 | 1 |
"""


class Done:
    def __init__(self, code, out="", err=""):
        self.returncode, self.stdout, self.stderr = code, out, err


def test_parse_reads_counts_only():
    p = noise.parse(SAMPLE)
    assert p == {"active_hours": 10.0, "raised": 1000, "per_hour": 100.0, "all_levels": 3000, "all_per_hour": 300.0,
                 "levels": {"informational": 1500, "low": 500, "medium": 990, "high": 10, "critical": 0},
                 "rules": 2, "top_rule_share": 90}
    assert "RULE NAME" not in str(p)                       # names never leave the module


def test_parse_refuses_a_file_without_the_headline():
    with pytest.raises(ValueError):
        noise.parse("# nothing here")


def test_meter_reads_each_file_at_its_commit_and_says_when_it_cannot():
    asked = []

    def git(args):
        asked.append(args)
        return Done(0, SAMPLE) if args[1].startswith("a62afba:") else Done(128, err="fatal: bad object")
    m = noise.meter(git)
    assert [a[1] for a in asked] == [f"{c}:{p}" for _, c, p, _, _ in noise.SOURCES]
    v2, v3, v4 = m["versions"]
    assert v2["ok"] and v2["per_hour"] == 100.0
    assert not v3["ok"] and "could not be read" in v3["problem"] and "bad object" in v3["problem"]
    assert "4 an hour" in m["words"]["honest"]


def _have(commit):
    r = subprocess.run(["git", "cat-file", "-e", commit], cwd=noise.ROOT, capture_output=True)
    return r.returncode == 0


@pytest.mark.skipif(not all(_have(c) for _, c, _, _, _ in noise.SOURCES), reason="the scoring commits are not in this clone")
def test_the_real_committed_results():
    m = noise.meter()
    got = {v["version"]: (v["per_hour"], v["active_hours"], v["raised"]) for v in m["versions"]}
    # VERIFICATION_LOG 2026-11-22: v2 95.21 (82.6 h), v3 6.28 (75.6 h), v4 4.22 (75.6 h)
    assert got == {"v2": (95.21, 82.6, 7866), "v3": (6.28, 75.6, 475), "v4": (4.22, 75.6, 319)}


def test_api():
    app = FastAPI()
    app.include_router(noise.router)
    r = TestClient(app).get("/api/labs/noise/")
    assert r.status_code == 200 and [v["version"] for v in r.json()["versions"]] == ["v2", "v3", "v4"]
