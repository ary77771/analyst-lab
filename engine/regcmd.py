"""v4 F7: a registry write DECLARED on a reg.exe command line, in the shape Sysmon would have logged it.

Our Sysmon config records registry events only for autostart places, so `reg add <key> /v <name>
/d <data>` on any other key leaves one trace: reg.exe's own process start (event 1) with that command
line. SigmaHQ's ~250 registry rules read registry events (TargetObject, Details, EventType), so they
never see it. This module translates the command line into those fields; engine/detect.py offers the
result to the registry rules as DERIVED rows (never stored, never a graph fact: the alert cites the
reg.exe start and says the write was declared, not recorded; it may have failed).

Nothing here knows any key, value or rule: it is reg.exe's syntax plus Sysmon's naming, nothing else
(tests/test_regcmd.py checks every path-like text in this file against a short allowed list).

Where each fact comes from (docs/plans/v4-prereg.md section 5, F7):
  - reg.exe's syntax and defaults: `reg add /?` and probes on scratch keys under HKCU (Windows 11,
    10.0.26300, 2026-11-16: ours and the independent reviewer's ~160): the key is the first argument;
    `reg add` switches start with / or -, `reg delete` switches only with /, any case; a repeated or
    unknown switch, /v with /ve, or a stray argument is "Invalid syntax" (nothing is written); no /v,
    /v "" and /v " " all mean the default value; key, value name and type are trimmed of spaces and
    tabs, data is not; the default type is REG_SZ; REG_DWORD needs /d: decimal ("010" is ten, any
    Unicode decimal digits, an optional +) or 0x hex, spaces/tabs around it, 0..0xffffffff;
    REG_QWORD: the same, plus no /d = 0 and a decimal minus that wraps; REG_BINARY: hex digits with
    spaces/tabs, or no /d; /s only with REG_MULTI_SZ and exactly one character; ONE trailing
    backslash on the key is accepted, a doubled backslash anywhere is not; `reg add HIVE /v ...`
    works on a bare root; a key part longer than 255 characters is refused.
  - Sysmon's naming, from the 55 real registry events SigmaHQ ships as samples for its rules
    (regression_data): `HKLM\\SOFTWARE\\...`, `HKLM\\System\\CurrentControlSet\\...`, `HKU\\<SID>\\...`,
    `HKU\\<SID>_Classes\\...`, `\\(Default)` for the default value, Details `DWORD (0x%08x)`, the text
    itself, `(Empty)`, `Binary Data`; event 13 SetValue, event 12 CreateKey / DeleteKey / DeleteValue.
  - NOT in those samples (taken from Sysmon's documentation and the spellings SigmaHQ's rules use,
    so less certain): machine classes, ControlSet00x -> CurrentControlSet, WOW6432Node, HKCC,
    QWORD's `QWORD (0x%08x-0x%08x)`, and `Binary Data` for REG_MULTI_SZ / REG_NONE /
    REG_DWORD_BIG_ENDIAN.

Where Sysmon's spelling cannot be known from the command line alone, every candidate is returned (the
write went to ONE of them; detect raises one alert per reg.exe start): machine classes
(`HKLM\\SOFTWARE\\Classes\\x` or `HKCR\\x`), the 32-bit view (redirected to WOW6432Node or, for shared
keys, not), HKCC (`Hardware Profiles\\Current` or `\\0001`).

Known limits (stated, not hidden):
  - the user's SID is not on a command line: HKCU becomes `HKU\\<SID>\\...` with the literal text
    `<SID>` (a rule that spells out a SID pattern will not match);
  - HKCR is read as the machine's classes (reg.exe writes there unless the key exists only per user);
  - `reg add KEY /v ...` on a key that does not exist also creates the key: only the value is
    declared; a bare `reg add KEY` declares CreateKey although the key may exist already;
  - `reg import`, `reg copy`, `reg restore`, `reg load`, `reg delete /va` and remote keys
    (`\\\\machine\\...`) declare no single value: nothing is derived;
  - a command line can lie or fail (no rights, wrong key, the overwrite question answered "no"): the
    write is DECLARED, never a fact.
"""

import re

SET_VALUE, CREATE_KEY, DELETE_KEY, DELETE_VALUE = "SetValue", "CreateKey", "DeleteKey", "DeleteValue"
DEFAULT_VALUE = "(Default)"
SID = "<SID>"                      # the user's SID is unknown from a command line
MAX_KEY_PART = 255                 # the registry's limit for one key name
_WS = " \t"                        # what reg.exe trims from key, value name and type

ROOTS = {"hklm": "HKLM", "hkey_local_machine": "HKLM", "hkcu": "HKCU", "hkey_current_user": "HKCU",
         "hkcr": "HKCR", "hkey_classes_root": "HKCR", "hku": "HKU", "hkey_users": "HKU",
         "hkcc": "HKCC", "hkey_current_config": "HKCC"}
TYPES = {"reg_sz", "reg_multi_sz", "reg_expand_sz", "reg_dword", "reg_dword_little_endian",
         "reg_dword_big_endian", "reg_qword", "reg_binary", "reg_none"}
# switch -> takes a value?   (reg add /?, reg delete /?)
ADD_SWITCHES = {"v": True, "ve": False, "t": True, "s": True, "d": True, "f": False, "reg:32": False, "reg:64": False}
DELETE_SWITCHES = {"v": True, "ve": False, "va": False, "f": False, "reg:32": False, "reg:64": False}

_DECIMAL = re.compile(r"[ \t]*([+-]?)(\d{1,400})[ \t]*\Z")      # \d: any Unicode decimal digit, as reg.exe
_HEX_NUMBER = re.compile(r"[ \t]*0[xX]([0-9a-fA-F]{1,400})[ \t]*\Z")
_HEX_BYTES = re.compile(r"[0-9a-fA-F \t]*\Z")
_CONTROL_SET = re.compile(r"(?i)\ASYSTEM\\ControlSet\d{3}(?=\\|\Z)")
_USER_SID = re.compile(r"(?i)\AS-1-5-21-[\d-]+\Z")


def split_args(command_line: str, doubled_quote_ends: bool = False) -> list:
    """A Windows command line as the program's argv (Microsoft C runtime rules, the ones reg.exe gets
    its arguments by): spaces/tabs separate arguments outside quotes; 2n backslashes before a quote
    give n backslashes and the quote opens/closes; 2n+1 give n backslashes and a literal quote; `""`
    inside quotes is a literal quote; other backslashes are literal. The program name (argv[0]) has
    no backslash rules: quotes only switch "spaces count" off and on, and it ends at the first space
    outside quotes (so `"C:\\x\\reg.exe"add` is ONE word). Empty arguments ("") are kept.
    doubled_quote_ends (v4 F8, powershell.exe: the OLD msvcrt.dll rule, probed): `""` inside quotes is
    a literal quote AND ends the quoted part (the 2008+ runtime stays inside the quotes)."""
    s = command_line or ""
    i, n = 0, len(s)
    out = []
    if not s.strip(_WS):
        return out
    name, quoted = [], False
    while i < n and (quoted or s[i] not in _WS):
        if s[i] == '"':
            quoted = not quoted
        else:
            name.append(s[i])
        i += 1
    out.append("".join(name))
    while True:
        while i < n and s[i] in _WS:
            i += 1
        if i >= n:
            break
        arg, quoted = [], False
        while i < n:
            c = s[i]
            if c == "\\":
                j = i
                while j < n and s[j] == "\\":
                    j += 1
                slashes = j - i
                if j < n and s[j] == '"':
                    arg.append("\\" * (slashes // 2))
                    if slashes % 2:
                        arg.append('"')
                        i = j + 1
                    else:
                        i = j                   # the quote itself is handled next round
                else:
                    arg.append("\\" * slashes)
                    i = j
            elif c == '"':
                if quoted and i + 1 < n and s[i + 1] == '"':
                    arg.append('"')
                    i += 2
                    if doubled_quote_ends:
                        quoted = False
                else:
                    quoted = not quoted
                    i += 1
            elif c in _WS and not quoted:
                break
            else:
                arg.append(c)
                i += 1
        out.append("".join(arg))
    return out


def is_reg(image, original_file_name=None) -> bool:
    """True for Windows' reg.exe: by the name built into the file (OriginalFileName, so a renamed copy
    counts and a different program merely CALLED reg.exe does not) when Sysmon recorded one, else by
    the image's file name."""
    original = str(original_file_name or "").strip().lower()
    if original and original not in ("-", "?"):
        return original == "reg.exe"
    return str(image or "").replace("/", "\\").rsplit("\\", 1)[-1].strip().lower() == "reg.exe"


def _switches(args, known, prefixes):
    """{switch: value or True} for a switch list, or None where reg.exe says "Invalid syntax"."""
    found = {}
    i = 0
    while i < len(args):
        a = args[i]
        if len(a) < 2 or a[0] not in prefixes:
            return None                              # a stray argument (or - where only / is a switch)
        name = a[1:].lower()
        if name not in known or name in found:
            return None                              # unknown or repeated switch
        if known[name]:
            if i + 1 >= len(args):
                return None                          # the value is missing
            found[name] = args[i + 1]                # taken as is, even if it starts with / or -
            i += 2
        else:
            found[name] = True
            i += 1
    if "reg:32" in found and "reg:64" in found:
        return None
    return found


def _number(text, bits, minus_wraps=False):
    """reg.exe's reading of a number for /d, or None where it refuses: 0x hex (no sign), or decimal
    with an optional + (and, for REG_QWORD, a minus that wraps around), below 2**bits."""
    text = text or ""
    m = _HEX_NUMBER.match(text)
    if m:
        value = int(m.group(1), 16)
        return value if value < (1 << bits) else None
    m = _DECIMAL.match(text)
    if not m:
        return None
    try:
        value = int(m.group(2))
    except ValueError:                               # never let one odd command line stop the pass
        return None
    if value >= (1 << bits):
        return None
    if m.group(1) == "-":
        if not minus_wraps:
            return None
        value = ((1 << bits) - value) % (1 << bits)
    return value


def _details(kind, data):
    """Sysmon's `Details` text for a value of this type, or None where reg.exe refuses the data."""
    if kind in ("reg_sz", "reg_expand_sz"):
        return data if data else "(Empty)"
    if kind in ("reg_dword", "reg_dword_little_endian"):
        value = _number(data, 32) if data is not None else None
        return None if value is None else f"DWORD (0x{value:08x})"
    if kind == "reg_dword_big_endian":               # stored as its own type, which Sysmon does not spell out
        return "Binary Data" if data is not None and _number(data, 32) is not None else None
    if kind == "reg_qword":
        value = 0 if not data else _number(data, 64, minus_wraps=True)
        return None if value is None else f"QWORD (0x{value >> 32:08x}-0x{value & 0xFFFFFFFF:08x})"
    if kind == "reg_binary":
        return "Binary Data" if _HEX_BYTES.match(data or "") else None
    return "Binary Data"                             # REG_MULTI_SZ, REG_NONE


def _key_paths(key, view32):
    """The key as Sysmon names it: a list of candidates (usually one), or [] for a key that is not
    this computer's registry (`\\\\machine\\...` has no known root) or that reg.exe refuses."""
    root, sep, sub = (key or "").strip(_WS).partition("\\")
    root = ROOTS.get(root.lower())
    if root is None:
        return []
    if sep:
        if sub.endswith("\\"):
            sub = sub[:-1]                           # ONE trailing backslash is accepted
        if not sub or sub.startswith("\\") or sub.endswith("\\") or "\\\\" in sub:
            return []                                # "HKCU\", a doubled backslash: refused
        if any(len(part) > MAX_KEY_PART for part in sub.split("\\")):
            return []

    def join(head, tail):                            # tail: "" or a path without a leading backslash
        return head + ("\\" + tail if tail else "")

    def below(path, prefix):
        """The rest of `path` under `prefix` ("" = the prefix itself), or None when it is not under it."""
        low = path.lower()
        if low == prefix:
            return ""
        return path[len(prefix) + 1:] if low.startswith(prefix + "\\") else None

    if root == "HKCC":
        return [join("HKLM\\System\\CurrentControlSet\\Hardware Profiles\\" + profile, sub) for profile in ("Current", "0001")]
    if root == "HKCR":
        root, sub = "HKLM", join("SOFTWARE\\Classes", sub)
    if root in ("HKCU", "HKU"):
        if root == "HKCU":
            user, more = SID, sub
        else:
            user, _, more = sub.partition("\\")
        classes = below(more, "software\\classes") if (root == "HKCU" or _USER_SID.match(user)) else None
        if classes is None:
            return [join("HKU", join(user, more))]
        out = [join(f"HKU\\{user}_Classes", classes)]
        if view32 and below(classes, "wow6432node") is None:
            out.append(join(f"HKU\\{user}_Classes\\WOW6432Node", classes))
        return out
    # HKLM
    sub = _CONTROL_SET.sub(lambda m: "System\\CurrentControlSet", sub)
    out = [join("HKLM", sub)]
    classes = below(sub, "software\\classes")
    if classes is not None:
        out.append(join("HKCR", classes))
        if view32 and below(classes, "wow6432node") is None:
            out.append(join("HKLM\\SOFTWARE\\Classes\\WOW6432Node", classes))
            out.append(join("HKCR\\WOW6432Node", classes))
    elif view32:
        software = below(sub, "software")
        if software is not None and below(software, "wow6432node") is None:
            out.append(join("HKLM\\SOFTWARE\\WOW6432Node", software))
    return out


def declared(command_line, image=None) -> list:
    """The registry events a reg.exe command line declares: a list of
    {"event_id": 13|12, "EventType", "TargetObject", "Details" (None for event 12)}; [] for anything
    that is not a well-formed local `reg add` / `reg delete` of one key or value. `image` (reg.exe's
    path) tells the 32-bit reg.exe (SysWOW64), whose view of some keys is redirected."""
    args = split_args(command_line)
    if len(args) < 3:
        return []
    verb, key = args[1].lower(), args[2]
    if verb not in ("add", "delete"):
        return []
    add = verb == "add"
    sw = _switches(args[3:], ADD_SWITCHES if add else DELETE_SWITCHES, "/-" if add else "/")
    if sw is None:
        return []
    if sum(k in sw for k in ("v", "ve", "va")) > 1:
        return []
    view32 = "reg:32" in sw or ("\\syswow64\\" in str(image or "").lower() and "reg:64" not in sw)
    paths = _key_paths(key, view32)
    if not paths:
        return []
    name = (str(sw.get("v") or "").strip(_WS) or DEFAULT_VALUE) if ("v" in sw or "ve" in sw) else None
    out = []
    if not add:
        if "va" in sw:
            return []                                # every value of the key: no single value is named
        for p in paths:
            if name is None:
                out.append({"event_id": 12, "EventType": DELETE_KEY, "TargetObject": p, "Details": None})
            else:
                out.append({"event_id": 12, "EventType": DELETE_VALUE, "TargetObject": p + "\\" + name, "Details": None})
        return out
    kind = str(sw.get("t", "REG_SZ")).strip(_WS).lower()
    if kind not in TYPES:
        return []
    if "s" in sw and (kind != "reg_multi_sz" or len(sw["s"]) != 1):
        return []                                    # a separator: only for REG_MULTI_SZ, one character
    details = _details(kind, sw.get("d"))
    if details is None:
        return []
    bare = not any(k in sw for k in ("v", "ve", "t", "d"))
    for p in paths:
        if bare:                                     # `reg add KEY`: the key itself is the point
            out.append({"event_id": 12, "EventType": CREATE_KEY, "TargetObject": p, "Details": None})
        out.append({"event_id": 13, "EventType": SET_VALUE, "TargetObject": p + "\\" + (name or DEFAULT_VALUE),
                    "Details": details})
    return out
