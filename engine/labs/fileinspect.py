"""Lab: File inspector. "What is this program file, looked at from the outside?"

For a program or script the recording mentions (and that we provably have a copy of here, see _files.py),
or one of the lab's own test files: fingerprints (SHA-256, MD5, size), the digital signature (Windows' own
Get-AuthenticodeSignature: it also knows catalog-signed Windows tools), the PE header via `pefile`
(build time, 32/64-bit, imported Windows functions grouped by what they make possible), each section's
entropy (very random content = maybe packed or encrypted) and interesting text inside the file (web
addresses, IP addresses, folder paths, registry keys). One plain-English line sums it up.

Static only: the file is READ, never run. Nothing leaves this laptop. Wording rule: a file "can" do what
its imports make possible; it is never said that it "does" it.
"""

import hashlib
import json
import math
import os
import re
import subprocess
import threading
from collections import Counter
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from engine import labs
from engine.labs import _files

router = APIRouter(prefix="/api/labs/fileinspect")

MAX_PARSE_BYTES = 100 * 1024 * 1024        # PE parsing and strings: only files up to this size
MAX_STRING_BYTES = 24 * 1024 * 1024        # text is looked for in the first this-many bytes
SHOW_PER_KIND = 40
PACKED_ENTROPY = 7.2                       # Shannon bits per byte; 8.0 = perfectly random
PACKER_SECTIONS = {"upx0", "upx1", "upx2", ".aspack", ".adata", ".petite", ".nsp0", ".nsp1", "mpress1",
                   "mpress2", ".themida", ".vmp0", ".vmp1", ".enigma1", ".mew"}

WORDS = {
    "title": "File inspector",
    "intro": ("A program file looked at from the outside: its fingerprints, who signed it, what Windows "
              "functions it asks for and what text is inside. The file is only read, never run."),
    "pick": "Files the recording mentions, and the lab's own test files",
    "pick_alert": "The programs and files this alert's story names",
    "no_alert_files": "This alert's story names no program or file that the recording links to a copy here.",
    "no_evidence": ("The exact file that ran isn't on this laptop (only its fingerprint was recorded). Lab copies below "
                    "are rebuilds, not the evidence."),
    "rebuild": "rebuild, not the evidence",
    "where_from": ("The recording keeps only each program's fingerprint (SHA-256), never its content. The content "
                   "shown here comes from the lab's own copies of the test programs (the scenario folders, the test "
                   "machine's CDs), and only when a copy has exactly the recorded "
                   "fingerprint is it shown as the file that ran."),
    "match": {
        "sha256": "Same SHA-256 as recorded: this is the very content that ran",
        "path": "Still at the recorded place on this laptop",
        "changed": "The file at the recorded place has changed since: not inspected",
        "name": ("Not the file that ran: a newer build of the same test program is shown, not the exact file that "
                 "ran (the fingerprints differ)"),
        "lab": "A lab test file (not in this recording)",
        "none": "No copy on this laptop (it existed only on the machine that recorded it)",
    },
    "sections": {
        "hashes": "Fingerprints", "signature": "Signature", "pe": "Program header", "imports": "What it can do",
        "entropy": "Sections and randomness", "strings": "Text inside the file",
    },
    "imports_note": ("Grouped from the Windows functions the file imports by name. An import shows an ability, "
                     "not that the program used it."),
    "go_note": ("A Go program: Go loads most Windows functions while running, so the import list is short and "
                "says little. The text inside the file is more telling."),
    "entropy_note": "Entropy near 8 means the bytes look random: typical of packed, compressed or encrypted parts.",
    "strings_note": "Found by pattern in the file's bytes. Text inside a file is not proof that it is used.",
    "noise_note": "left out as common library text",
    "no_pe": "Not a Windows program file (no PE header).",
    "not_installed": "The pefile library is not installed in this Python, so the program header is not read.",
    "sig_off": ("Not checked yet. Checking asks Windows (Get-AuthenticodeSignature), and Windows may contact the "
                "internet to see whether the signing certificate was revoked, so it happens only when you press the button."),
    "sig_button": "Check the signature with Windows",
}

# Windows functions -> what they make possible. A short list of well-known names, after the categories
# malware triage guides use (e.g. MalAPI.io, the "suspicious imports" lists of PE tools); not exhaustive.
IMPORT_GROUPS = {
    "network": ("Network", "can talk over the network",
                ["InternetOpen", "InternetConnect", "InternetReadFile", "HttpOpenRequest", "HttpSendRequest",
                 "URLDownloadToFile", "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest", "WinHttpReadData",
                 "WSAStartup", "socket", "connect", "send", "recv", "gethostbyname", "getaddrinfo", "GetAddrInfoW",
                 "DnsQuery", "WSASocket", "WSAConnect", "InternetOpenUrl", "FtpPutFile"]),
    "crypto": ("Encryption", "can encrypt, decrypt or hash data",
               ["CryptEncrypt", "CryptDecrypt", "CryptAcquireContext", "CryptGenKey", "CryptImportKey",
                "CryptCreateHash", "CryptHashData", "CryptProtectData", "CryptUnprotectData", "BCryptEncrypt",
                "BCryptDecrypt", "BCryptGenerateSymmetricKey", "BCryptOpenAlgorithmProvider", "CryptStringToBinary",
                "CryptBinaryToString"]),
    "injection": ("Touching other programs", "can write into or control other running programs",
                  ["VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
                   "CreateRemoteThreadEx", "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
                   "NtQueueApcThread", "SetThreadContext", "GetThreadContext", "NtUnmapViewOfSection",
                   "ZwUnmapViewOfSection", "OpenProcess", "SetWindowsHookEx", "NtWriteVirtualMemory",
                   "VirtualProtectEx", "ResumeThread", "SuspendThread"]),
    "start": ("Starting programs", "can start other programs",
              ["CreateProcess", "CreateProcessAsUser", "CreateProcessWithToken", "CreateProcessWithLogon",
               "ShellExecute", "ShellExecuteEx", "WinExec", "system", "_wsystem"]),
    "delete": ("Deleting or moving files", "can delete or move files",
               ["DeleteFile", "RemoveDirectory", "MoveFile", "MoveFileEx", "SHFileOperation", "NtDeleteFile"]),
    "autostart": ("Autostart and services", "can change the registry or install services",
                  ["RegSetValue", "RegSetValueEx", "RegCreateKey", "RegCreateKeyEx", "CreateService",
                   "ChangeServiceConfig", "StartService", "OpenSCManager"]),
    "spying": ("Watching the user", "can read keys, the screen or the clipboard",
               ["GetAsyncKeyState", "GetKeyState", "GetKeyboardState", "SetWindowsHookEx", "BitBlt",
                "GetClipboardData", "GetForegroundWindow"]),
    "hiding": ("Checking for a debugger", "can check whether it is being watched or debugged",
               ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
                "OutputDebugString"]),
    "loading": ("Loading code at run time", "can load more code while running",
                ["LoadLibrary", "LoadLibraryEx", "GetProcAddress", "LdrLoadDll", "VirtualAlloc", "VirtualProtect"]),
}


# What the Go runtime itself imports from kernel32 in every Windows program it builds (its scheduler stops
# and resumes its own threads, hence the thread-context functions). Left out of the groups for Go programs,
# or every Go program would look able to control other programs.
GO_RUNTIME_IMPORTS = {
    "AddVectoredContinueHandler", "AddVectoredExceptionHandler", "CloseHandle", "CreateEventA",
    "CreateIoCompletionPort", "CreateThread", "CreateWaitableTimerExW", "DuplicateHandle", "ExitProcess",
    "FreeEnvironmentStringsW", "GetConsoleMode", "GetCurrentThreadId", "GetEnvironmentStringsW", "GetErrorMode",
    "GetProcAddress", "GetProcessAffinityMask", "GetQueuedCompletionStatusEx", "GetStdHandle",
    "GetSystemDirectoryA", "GetSystemInfo", "GetThreadContext", "LoadLibraryExW", "LoadLibraryW", "LoadLibraryA",
    "PostQueuedCompletionStatus", "RaiseFailFastException", "ResumeThread", "RtlLookupFunctionEntry",
    "RtlVirtualUnwind", "SetConsoleCtrlHandler", "SetErrorMode", "SetEvent", "SetProcessPriorityBoost",
    "SetThreadContext", "SetUnhandledExceptionFilter", "SetWaitableTimer", "SuspendThread", "SwitchToThread",
    "TlsAlloc", "VirtualAlloc", "VirtualFree", "VirtualQuery", "WaitForMultipleObjects", "WaitForSingleObject",
    "WerGetFlags", "WerSetFlags", "WriteConsoleW", "WriteFile", "timeBeginPeriod", "timeEndPeriod",
}


def _base_name(fn):
    """CreateProcessW -> CreateProcess; RegSetValueExA -> RegSetValueEx (the list holds both spellings)."""
    return fn[:-1] if fn and fn[-1] in "AW" and len(fn) > 2 and fn[-2].islower() else fn


def group_imports(names):
    """[{key, title, means, functions}] for the imported function names that fall into a known group."""
    lookup = {}
    for key, (_, _, fns) in IMPORT_GROUPS.items():
        for f in fns:
            lookup.setdefault(f.lower(), []).append(key)
    hits = {}
    for n in names:
        if not n:
            continue
        for cand in {n, _base_name(n)}:
            for key in lookup.get(cand.lower(), []):
                hits.setdefault(key, set()).add(n)
    return [{"key": k, "title": IMPORT_GROUPS[k][0], "means": IMPORT_GROUPS[k][1], "functions": sorted(hits[k])}
            for k in IMPORT_GROUPS if k in hits]


def entropy(data):
    """Shannon entropy in bits per byte (0 = all the same byte, 8 = perfectly random)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


# --- text inside the file ---------------------------------------------------------------------------------
_ASCII = re.compile(rb"[\x20-\x7e]{5,}")
_WIDE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")
PATTERNS = {
    "urls": re.compile(r"\b(?:https?|ftp)://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{3,}", re.I),
    "ips": re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{1,5})?(?![\d.])"),
    "paths": re.compile(r"(?:\b[A-Za-z]:\\|\\\\[A-Za-z0-9_.$-]+\\|%[A-Za-z]+%\\)[^\s\"'<>|*?]{2,}"),
    "registry": re.compile(r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)(?:\\[^\s\"'<>|*?\\]+)+|\b(?:SOFTWARE|SYSTEM)\\(?:Microsoft|CurrentControlSet)\\[^\s\"'<>|*?]+", re.I),
}
# Text that nearly every program of a toolchain carries (library docs, certificate links, XML schemas):
# counted and left out so the page shows what is particular to this file.
NOISE = re.compile(r"golang\.org|go\.dev|github\.com/golang|w3\.org|schemas\.microsoft\.com|schemas\.xmlsoap\.org|"
                   r"ietf\.org|digicert\.com|microsoft\.com/pki|crl\.|ocsp\.|verisign\.com|symcb\.com|symcd\.com|"
                   r"sectigo\.com|usertrust\.com|globalsign|unicode\.org|python\.org|mozilla\.org", re.I)
_VERSIONISH = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


def strings_in(data):
    """Printable text runs (ASCII and UTF-16LE) of 5+ characters."""
    out = [m.group(0).decode("ascii") for m in _ASCII.finditer(data)]
    out += [m.group(0).decode("utf-16le") for m in _WIDE.finditer(data)]
    return out


def interesting(texts):
    """{kind: {"items": [...], "count": n, "noise": m}} for URLs, IPs, paths and registry keys."""
    found = {k: [] for k in PATTERNS}
    noise = Counter()
    seen = {k: set() for k in PATTERNS}
    for t in texts:
        for kind, rx in PATTERNS.items():
            for m in rx.finditer(t):
                v = m.group(0).rstrip(".,;:)'\"")
                if kind == "ips" and _VERSIONISH.match(v) and (v.startswith("0.") or v.endswith(".0")):
                    continue                     # 1.0.0.0-style version numbers
                if v.lower() in seen[kind]:
                    continue
                seen[kind].add(v.lower())
                if kind in ("urls", "paths") and NOISE.search(v):
                    noise[kind] += 1
                    continue
                found[kind].append(v)
    return {k: {"items": v[:SHOW_PER_KIND], "count": len(v), "noise": noise[k]} for k, v in found.items()}


# --- the signature ----------------------------------------------------------------------------------------
_sig_cache, _sig_lock = {}, threading.Lock()
_SIG_PS = ("$s = Get-AuthenticodeSignature -LiteralPath $env:AL_SIG_PATH; "
           "[pscustomobject]@{status=[string]$s.Status; type=[string]$s.SignatureType; "
           "signer=$(if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { $null }); "
           "issuer=$(if ($s.SignerCertificate) { $s.SignerCertificate.Issuer } else { $null }); "
           "timestamped=[bool]$s.TimeStamperCertificate; os_binary=[bool]$s.IsOSBinary; "
           "message=[string]$s.StatusMessage} | ConvertTo-Json -Compress")


def signature(path, sha=None, runner=subprocess.run):
    """Windows' own verdict on the file's digital signature (embedded or catalog), cached by content.
    The path goes in through an environment variable, never into the command text."""
    key = sha or path
    with _sig_lock:
        if key in _sig_cache:
            return _sig_cache[key]
    if os.name != "nt":
        return {"checked": False, "reason": "signatures are checked with Windows' own tool"}
    try:
        r = runner(["powershell", "-NoProfile", "-NonInteractive", "-Command", _SIG_PS], capture_output=True,
                   text=True, timeout=30, env={**os.environ, "AL_SIG_PATH": path},
                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        d = json.loads((r.stdout or "").strip() or "null")
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        return {"checked": False, "reason": f"the signature could not be checked ({type(e).__name__})"}
    if not isinstance(d, dict):
        return {"checked": False, "reason": "the signature could not be checked"}
    out = {"checked": True, "status": d.get("status"), "type": d.get("type"), "signer": _cn(d.get("signer")),
           "signer_full": d.get("signer"), "issuer": _cn(d.get("issuer")), "timestamped": d.get("timestamped"),
           "os_binary": d.get("os_binary"), "valid": d.get("status") == "Valid"}
    with _sig_lock:
        _sig_cache[key] = out
    return out


def _cn(subject):
    m = re.search(r"CN=(\"[^\"]+\"|[^,]+)", subject or "")
    return m.group(1).strip('"') if m else subject


# --- the PE header ----------------------------------------------------------------------------------------
def pe_info(data):
    """Header facts of a Windows program file, or {"pe": False}. Needs pefile (imported here so the lab
    still loads, and says so, without it)."""
    if data[:2] != b"MZ":
        return {"pe": False}
    try:
        import pefile
    except ImportError:
        return {"pe": None, "error": WORDS["not_installed"]}
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    except pefile.PEFormatError as e:
        return {"pe": False, "error": str(e)}
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    ts = fh.TimeDateStamp
    built, built_note = None, None
    if ts == 0:
        built_note = "not set (0): common for Go and reproducible builds"
    else:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        built = dt.strftime("%Y-%m-%d %H:%M:%SZ")
        if dt.year < 1995 or dt > datetime.now(timezone.utc):
            built_note = "implausible: the build time seems to have been replaced (reproducible build or edited)"
    imports, dlls = [], []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("ascii", "replace")
        fns = [(i.name.decode("ascii", "replace") if i.name else f"#{i.ordinal}") for i in entry.imports]
        dlls.append({"dll": dll, "count": len(fns)})
        imports.extend(fns)
    sections = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("ascii", "replace")
        raw = s.get_data()
        e = round(entropy(raw), 2)
        execu = bool(s.Characteristics & 0x20000000)
        sections.append({"name": name, "size": len(raw), "virtual_size": s.Misc_VirtualSize, "entropy": e,
                         "executable": execu, "writable": bool(s.Characteristics & 0x80000000),
                         "high": e >= PACKED_ENTROPY and len(raw) >= 1024})
    is_go = b"Go buildinf:" in data or b"Go build ID:" in data or any(s["name"] == ".symtab" for s in sections) and b"runtime.main" in data
    runtime = [f for f in imports if f in GO_RUNTIME_IMPORTS] if is_go else []
    own = [f for f in imports if f not in GO_RUNTIME_IMPORTS] if is_go else imports
    packer = sorted({s["name"] for s in sections if s["name"].lower() in PACKER_SECTIONS})
    machine = {0x14c: "32-bit (x86)", 0x8664: "64-bit (x64)", 0xaa64: "64-bit (ARM64)"}.get(fh.Machine, hex(fh.Machine))
    kind = "DLL (library)" if fh.Characteristics & 0x2000 else (
        "driver" if oh.Subsystem == 1 else "console program" if oh.Subsystem == 3 else
        "windowed program" if oh.Subsystem == 2 else "program")
    # read from the file's own header only: does it carry an embedded signature block? (no check, nothing online)
    sec = oh.DATA_DIRECTORY[4] if len(oh.DATA_DIRECTORY) > 4 else None
    embedded = bool(sec and sec.Size > 0 and sec.VirtualAddress > 0)
    pe.close()
    return {"pe": True, "embedded_signature": embedded, "machine": machine, "kind": kind, "built": built, "built_note": built_note,
            "go": is_go, "dlls": dlls, "import_count": len(imports), "groups": group_imports(own),
            "go_runtime_left_out": len(set(runtime)),
            "sections": sections, "packer_sections": packer,
            "packed_hint": bool(packer) or any(s["high"] and s["executable"] for s in sections)}


def _size_words(n):
    for unit in ("bytes", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "bytes" else f"{n:.1f} {unit}"
        n /= 1024


def summary(info):
    """One plain-English line from the inspection (no judgement words)."""
    parts = []
    sig, pe, s = info.get("signature") or {}, info.get("pe") or {}, info.get("strings") or {}
    if not sig.get("checked") and pe.get("pe"):
        parts.append("Carries an embedded signature (not checked)" if pe.get("embedded_signature")
                     else "No embedded signature (a catalog signature is not checked)")
    if sig.get("checked"):
        if sig.get("valid"):
            how = "catalog" if (sig.get("type") or "").lower() == "catalog" else "embedded"
            parts.append(f"Signed by {sig.get('signer')} ({how} signature, valid)")
        elif (sig.get("status") or "") == "NotSigned":
            parts.append("Not signed")
        else:
            parts.append(f"Signature present but {sig.get('status')}")
    if pe.get("pe"):
        lang = "Go " if pe.get("go") else ""
        parts.append(f"{pe['machine']} {lang}{pe['kind']}, {_size_words(info['size'])}")
        abilities = [g["means"].removeprefix("can ") for g in pe.get("groups") or [] if g["key"] != "loading"]
        if abilities:
            parts.append("its imports show it can " + "; ".join(abilities))
        elif pe.get("groups"):
            parts.append("it imports only functions for loading more code at run time")
        elif pe.get("go"):
            parts.append("it imports only what every Go program imports")
        if pe.get("packed_hint"):
            parts.append("parts look packed or encrypted (high randomness)")
    elif pe.get("pe") is False:
        parts.append(f"not a Windows program file, {_size_words(info['size'])}")
    counts = [(s.get(k) or {}).get("count", 0) for k in ("urls", "ips", "paths", "registry")]
    if any(counts):
        names = ["web address", "IP address", "folder path", "registry key"]
        parts.append("its text holds " + ", ".join(f"{c} {n}{'' if c == 1 else ('es' if n.endswith('ss') else 's')}"
                                                     for c, n in zip(counts, names) if c))
    return "; ".join(parts) + "." if parts else "Nothing to say about this file."


_inspect_cache, _inspect_lock = {}, threading.Lock()


def inspect_file(path, sig_runner=subprocess.run, check_signature=False):
    """Everything the page shows about one file on this disk (cached by path + size + mtime). The signature is
    checked by Windows only when asked (`check_signature`): Windows may contact the internet to see whether the
    certificate was revoked, so it is never done by itself."""
    st = os.stat(path)
    key = (os.path.abspath(path), st.st_size, st.st_mtime_ns, bool(check_signature))
    with _inspect_lock:
        if key in _inspect_cache:
            return _inspect_cache[key]
    sha, md5 = hashlib.sha256(), hashlib.md5()
    head = bytearray()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            sha.update(chunk)
            md5.update(chunk)
            if len(head) < MAX_PARSE_BYTES:
                head.extend(chunk[:MAX_PARSE_BYTES - len(head)])
    data = bytes(head)
    info = {"name": os.path.basename(path), "size": st.st_size, "sha256": sha.hexdigest(), "md5": md5.hexdigest(),
            "magic": data[:4].hex(), "truncated": st.st_size > MAX_PARSE_BYTES}
    info["pe"] = pe_info(data)
    info["strings"] = interesting(strings_in(data[:MAX_STRING_BYTES]))
    info["signature"] = (signature(path, info["sha256"], runner=sig_runner) if check_signature
                         else {"checked": False, "reason": WORDS["sig_off"], "can_check": os.name == "nt"})
    info["summary"] = summary(info)
    with _inspect_lock:
        _inspect_cache[key] = info
    return info


# --- routes ------------------------------------------------------------------------------------------------
def _public(item):
    """A catalogue item as the page gets it (the local path is shown only for lab files, which are ours)."""
    out = {k: item[k] for k in ("id", "name", "recorded_path", "host", "sha256", "kinds", "first", "last", "times",
                                "match", "inspectable")}
    out["evidence"] = bool(item.get("evidence"))
    out["match"] = item["match"] or "none"
    out["match_words"] = WORDS["match"][out["match"]]
    return out


@router.get("")
def files(alert: str = None):
    """Every file the recording mentions (and the lab's own); with `alert`, only that alert's own programs and files."""
    ctx = labs.context()
    items = _files.ctx_catalogue(ctx)
    scope = None
    if alert:
        try:
            scope = _files.alert_scope(ctx, alert)
        except LookupError as e:
            raise HTTPException(status_code=404, detail=str(e))
        items = [i for i in items if i["match"] != "lab" and _files.in_scope(i, scope)]
    return {"words": WORDS, "files": [_public(i) for i in items], "lab_dirs": len(_files.lab_dirs(ctx.recordings)),
            "alert": scope and scope["alert"],
            # with an alert: is the exact file that ran here at all? (if not, the page says so before anything else)
            "evidence_here": None if scope is None else any(i.get("evidence") for i in items)}


@router.get("/inspect/{file_id}")
def inspect(file_id: str, signature: bool = False):
    ctx = labs.context()
    item = _files.resolve(_files.ctx_catalogue(ctx), file_id)
    if item is None:
        raise HTTPException(status_code=404, detail="no such file in this recording or the lab folders")
    if not item["inspectable"]:
        raise HTTPException(status_code=409, detail=WORDS["match"][item["match"] or "none"])
    info = dict(inspect_file(item["local"], check_signature=signature))
    if not item.get("evidence"):
        info["lookalike"] = item["match"] == "name"    # the page says plainly: a rebuild, not the file that ran
        info["evidence"] = False
    else:
        info["evidence"] = True
    if item.get("sha256") and item["match"] == "sha256" and info["sha256"] != item["sha256"]:
        raise HTTPException(status_code=409, detail="the local copy changed while it was read")
    return {"file": _public(item), "info": info}
