"""Fixtures for the night-tools labs: a tiny Windows program file built in code (no binary in git) and an
event store written in a temp folder. Nothing here comes from a real recording."""

import os
import struct

from engine.store import EventStore

FA, SA = 0x200, 0x1000          # file / section alignment


def _align(n, a):
    return (n + a - 1) // a * a


def build_pe(sections=None, imports=None, timestamp=0x5F000000, dll=False, extra=b""):
    """Bytes of a minimal 64-bit PE: `sections` = [(name, data, characteristics)], `imports` = {dll: [names]}
    placed in an '.idata' section after them. `extra` is appended after the last section (overlay)."""
    sections = list(sections or [(".text", b"\xc3" * 64, 0x60000020)])
    imports = imports or {}
    n = len(sections) + (1 if imports else 0)
    rvas = [SA * (i + 1) for i in range(n)]
    idata = b""
    if imports:
        base = rvas[-1]
        dlls = list(imports)
        desc_size = 20 * (len(dlls) + 1)
        # layout: descriptors | per dll: ILT, IAT | hint/name entries | dll names
        cursor = desc_size
        thunk_pos = {}
        for d in dlls:
            k = len(imports[d]) + 1
            thunk_pos[d] = (cursor, cursor + 8 * k)
            cursor += 16 * k
        hn_pos, hn_blob = {}, b""
        for d in dlls:
            for f in imports[d]:
                hn_pos[(d, f)] = cursor + len(hn_blob)
                e = struct.pack("<H", 0) + f.encode() + b"\x00"
                hn_blob += e + (b"\x00" if len(e) % 2 else b"")
        cursor += len(hn_blob)
        name_pos, names_blob = {}, b""
        for d in dlls:
            name_pos[d] = cursor + len(names_blob)
            names_blob += d.encode() + b"\x00"
        desc = b"".join(struct.pack("<IIIII", base + thunk_pos[d][0], 0, 0, base + name_pos[d], base + thunk_pos[d][1])
                        for d in dlls) + b"\x00" * 20
        thunks = b""
        for d in dlls:
            t = b"".join(struct.pack("<Q", base + hn_pos[(d, f)]) for f in imports[d]) + b"\x00" * 8
            thunks += t + t
        idata = desc + thunks + hn_blob + names_blob
        sections.append((".idata", idata, 0xC0000040))
    headers = 0x40 + 4 + 20 + 240 + 40 * n
    size_headers = _align(headers, FA)
    raw, ptr, shdrs = b"", size_headers, b""
    for (name, data, ch), rva in zip(sections, rvas):
        rsize = _align(max(len(data), 1), FA)
        shdrs += struct.pack("<8sIIIIIIHHI", name.encode()[:8], max(len(data), 1), rva, rsize, ptr, 0, 0, 0, 0, ch)
        raw += data.ljust(rsize, b"\x00")
        ptr += rsize
    size_image = rvas[-1] + _align(max(len(sections[-1][1]), 1), SA)
    dirs = [(0, 0)] * 16
    if imports:
        dirs[1] = (rvas[-1], 20 * (len(imports) + 1))
    opt = struct.pack("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", 0x20B, 14, 0, FA, 0, 0, rvas[0], rvas[0], 0x140000000, SA, FA,
                      6, 0, 0, 0, 6, 0, 0, size_image, size_headers, 0, 3, 0x8160, 0x100000, 0x1000, 0x100000, 0x1000,
                      0, 16)
    opt += b"".join(struct.pack("<II", a, s) for a, s in dirs)
    coff = struct.pack("<HHIIIHH", 0x8664, n, timestamp, 0, 0, 240, 0x2022 if dll else 0x22)
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
    head = (dos + b"PE\x00\x00" + coff + opt + shdrs).ljust(size_headers, b"\x00")
    return head + raw + extra


def write_pe(path, **kw):
    data = build_pe(**kw)
    with open(path, "wb") as f:
        f.write(data)
    return path


def store_with(path, records):
    """An event store at `path` holding these simplified records: dicts with host, time, event_id or type, and
    the Sysmon/agent fields in `data`."""
    s = EventStore(path)
    out = []
    for i, r in enumerate(records):
        rec = {"host": r.get("host", "analystlab-vm"), "channel": "Microsoft-Windows-Sysmon/Operational", "record_id": i + 1,
               "time": r.get("time", f"2026-11-01T10:00:{i:02d}.000Z"), "event_id": r.get("event_id"),
               "type": r.get("type"), "data": r.get("data", {})}
        if r.get("type"):
            rec.pop("record_id")
            rec.update(session="s1", seq=i + 1, channel=None)
        out.append(rec)
    s.insert(out)
    s.close()
    return path


def lab_folder(tmp_path, monkeypatch):
    """A lab-files folder for the labs (ANALYSTLAB_LAB_FILES points at it)."""
    from engine.labs import _files
    d = tmp_path / "labfiles"
    d.mkdir(exist_ok=True)
    monkeypatch.setenv("ANALYSTLAB_LAB_FILES", str(d))
    monkeypatch.setattr(_files, "CACHE_FILE", str(tmp_path / "hash-cache.json"))   # never the real temp cache
    monkeypatch.setitem(_files._disk, "loaded", True)
    return d


def sha256(path):
    import hashlib
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


VM = ("analystlab-vm",)


def configure(tmp_path, events_db, hosts=VM):
    """Point the Labs context at a fixture store (alerts db absent). `hosts` as the dashboard passes it: the test
    machine by default; None = every machine (a dashboard started with --labs-all-hosts)."""
    from engine import labs
    return labs.configure(labs.Context(str(events_db), str(tmp_path / "alerts.db"), recordings=str(tmp_path / "rec"),
                                       hosts=hosts))


__all__ = ["build_pe", "write_pe", "store_with", "lab_folder", "sha256", "configure", "os"]
