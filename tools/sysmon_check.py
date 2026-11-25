"""Stage 2 check: does Sysmon record the activity the lab depends on?

Generates harmless, known activity on this machine and confirms each piece appears in the
Sysmon log as the expected event ID:

    1  ProcessCreate        start Notepad
    5  ProcessTerminate     close Notepad
    11 FileCreate           create a test file
    26 FileDeleteDetected   delete that test file
    22 DnsQuery             look up a unique, non-existent example.com subdomain
    3  NetworkConnect       connect to a listener on this machine (127.0.0.1)

Reading the Sysmon log needs administrator rights, so run this elevated.
Writes a JSON result (expected vs found, with record IDs) to --out.
"""

import argparse
import json
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone

import win32evtlog

CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def latest_record_id():
    q = win32evtlog.EvtQuery(CHANNEL, win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection)
    events = win32evtlog.EvtNext(q, 1)
    if not events:
        return 0
    xml = win32evtlog.EvtRender(events[0], win32evtlog.EvtRenderEventXml)
    return int(re.search(r"<EventRecordID>(\d+)<", xml).group(1))


def events_after(record_id):
    """Events newer than record_id. Reads newest-first and stops at record_id, instead of an
    XPath filter that would scan the whole (up to 1 GB) log."""
    q = win32evtlog.EvtQuery(CHANNEL, win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection)
    out = []
    while True:
        batch = win32evtlog.EvtNext(q, 100)
        if not batch:
            break
        for e in batch:
            xml = win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml)
            rid = int(re.search(r"<EventRecordID>(\d+)<", xml).group(1))
            if rid <= record_id:
                return list(reversed(out))
            eid = int(re.search(r"<EventID[^>]*>(\d+)<", xml).group(1))
            data = dict(re.findall(r"<Data Name='([^']+)'>([^<]*)</Data>", xml))
            out.append({"record_id": rid, "event_id": eid, "data": data})
    return list(reversed(out))


def generate_activity(marker):
    facts = {}

    # 1 / 5: start and close Notepad
    proc = subprocess.Popen(["notepad.exe"])
    time.sleep(2)
    proc.terminate()
    proc.wait(timeout=10)

    # 11 / 26: create and delete a test file
    # an \AnalystLab\ folder: config v0.2 records file events there (and for executables/scripts)
    folder = os.path.join(tempfile.gettempdir(), "AnalystLab", "check")
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, f"check_{marker}.txt")
    with open(path, "w") as f:
        f.write("analyst lab sysmon check\n")
    time.sleep(1)
    os.remove(path)
    facts["file"] = path

    # 22: DNS lookup of a unique name, so Windows' DNS cache can't answer it silently
    # (example.com subdomains don't exist; the lookup failing is expected and harmless)
    dns_name = f"analystlab-{marker.lower()}.example.com"
    try:
        socket.getaddrinfo(dns_name, 80)
    except socket.gaierror:
        pass
    facts["dns_name"] = dns_name

    # 3: connection to a listener on this machine only
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    accepted = threading.Thread(target=lambda: server.accept()[0].close())
    accepted.start()
    client = socket.create_connection(("127.0.0.1", port), timeout=5)
    client.close()
    accepted.join(timeout=5)
    server.close()
    facts["port"] = port

    return facts


def check(found, facts):
    def has(event_id, pred):
        return [e["record_id"] for e in found if e["event_id"] == event_id and pred(e["data"])]

    def image_is(name):
        return lambda d: d.get("Image", "").lower().endswith(name)

    return {
        "1 ProcessCreate (notepad)": has(1, image_is("notepad.exe")),
        "5 ProcessTerminate (notepad)": has(5, image_is("notepad.exe")),
        "11 FileCreate (test file)": has(11, lambda d: d.get("TargetFilename", "").lower() == facts["file"].lower()),
        "26 FileDeleteDetected (test file)": has(26, lambda d: d.get("TargetFilename", "").lower() == facts["file"].lower()),
        "22 DnsQuery (unique test name)": has(22, lambda d: d.get("QueryName", "").lower() == facts["dns_name"]),
        "3 NetworkConnect (127.0.0.1)": has(
            3,
            lambda d: d.get("DestinationIp") == "127.0.0.1" and d.get("DestinationPort") == str(facts["port"]),
        ),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--wait", type=float, default=10.0, help="seconds to let Sysmon flush events")
    args = parser.parse_args()

    marker = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    start_id = latest_record_id()
    facts = generate_activity(marker)
    time.sleep(args.wait)
    found = events_after(start_id)
    results = check(found, facts)

    summary = {
        "marker": marker,
        "start_record_id": start_id,
        "events_seen_during_check": len(found),
        "events_by_id": {str(k): sum(1 for e in found if e["event_id"] == k) for k in sorted({e["event_id"] for e in found})},
        "checks": {name: {"pass": bool(ids), "record_ids": ids} for name, ids in results.items()},
        "all_pass": all(results.values()),
    }
    with open(args.out, "w") as f:
        json.dump(summary, f, indent=2)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
