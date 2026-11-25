"""Second opinion, our side, in its OWN process (so loading ~1,900 Sigma rules never slows the dashboard):

    python -m engine.labs._so_worker <file.evtx> <work folder>

Reads the .evtx (wevtutil), runs our detectors on a temporary store in the work folder and writes
<work folder>/ours.json: {fingerprint, records: [the few fields the comparison shows], ours: [...], errors, rules}.
"""

import json
import os
import sys


VERSION = 2                       # bump when the cached file's content changes (2: process ids for "nearby")


def fingerprint(path):
    st = os.stat(path)
    return [os.path.abspath(path), st.st_size, st.st_mtime_ns]


def slim(records):
    out = []
    for r in records:
        d = r.get("data") or {}
        out.append({"record_id": r["record_id"], "time": r.get("time"), "event_id": r.get("event_id"),
                    "channel": r.get("channel"),
                    "data": {k: d[k] for k in ("Image", "SourceImage", "ProcessGuid", "SourceProcessGUID",
                                                "SourceProcessGuid") if d.get(k)}})
    return out


def run(evtx, workdir):
    from engine.labs import secondopinion as S
    os.makedirs(workdir, exist_ok=True)
    records = S.read_evtx(evtx)
    ours, errors = S.our_side(records, workdir)
    out = {"version": VERSION, "fingerprint": fingerprint(evtx), "records": slim(records), "ours": ours, "errors": len(errors),
           "rules": len(S._rules["rules"] or [])}
    tmp = os.path.join(workdir, "ours.json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(out, f)
    os.replace(tmp, os.path.join(workdir, "ours.json"))
    return out


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    run(sys.argv[1], sys.argv[2])
