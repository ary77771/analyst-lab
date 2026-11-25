"""v4 F7 (engine/regcmd.py): a reg.exe command line -> the registry event(s) it declares, in Sysmon's
spelling. The expectations are reg.exe's observed behaviour (probes on a scratch key, Windows 11
26200, 2026-11-16) and the field shapes of SigmaHQ's own registry event samples; keys here are
made-up names, not test or attack commands."""
import subprocess
import sys

import pytest

from engine import regcmd
from engine.regcmd import declared, is_reg, split_args

K = r"HKLM\SOFTWARE\Contoso\App"


def one(command_line, image=None):
    got = declared(command_line, image)
    assert len(got) == 1, got
    return got[0]


def set_value(target, details):
    return {"event_id": 13, "EventType": "SetValue", "TargetObject": target, "Details": details}


# -- argv splitting (Microsoft C runtime rules) ---------------------------------------------------------
@pytest.mark.parametrize("line, args", [
    (r'reg add HKLM\A /v N', ["reg", "add", r"HKLM\A", "/v", "N"]),
    (r'"C:\Windows\system32\reg.exe"  add   "HKLM\A B" /v "N M"', [r"C:\Windows\system32\reg.exe", "add", r"HKLM\A B", "/v", "N M"]),
    ('reg add K /d ""', ["reg", "add", "K", "/d", ""]),                       # an empty argument is kept
    (r'reg add "HKLM\A\" /v N', ["reg", "add", 'HKLM\\A" /v N']),            # \" is a literal quote: the key swallows the rest
    (r'reg add "HKLM\A\\" /v N', ["reg", "add", "HKLM\\A\\", "/v", "N"]),    # \\" = one backslash, then the closing quote
    (r'reg add K /d a\b\c', ["reg", "add", "K", "/d", r"a\b\c"]),            # backslashes not before a quote are literal
    ('reg add K /d "say ""hi"" now"', ["reg", "add", "K", "/d", 'say "hi" now']),
    ("reg\tadd\tK", ["reg", "add", "K"]),
    (r'"C:\Windows\system32\reg.exe"add K /v N', [r"C:\Windows\system32\reg.exeadd", "K", "/v", "N"]),   # glued: ONE program word
    (r'C:\Program" "Files\reg.exe add K', [r"C:\Program Files\reg.exe", "add", "K"]),
    ("", []), ("   ", []),
])
def test_split_args(line, args):
    assert split_args(line) == args


@pytest.mark.parametrize("args", [
    ["reg", "add", r"HKLM\Software\A B", "/v", "Na me", "/d", r"C:\Program Files\x\\"],
    ["reg", "add", "K", "/d", 'he said "hi"', "/f"],
    ["reg", "add", "K", "/d", "", "/v", r"tail\\"],
    ["reg", "add", "K", "/d", r'a\"b', "/t", "REG_SZ"],
])
def test_split_args_inverts_pythons_windows_quoting(args):
    """subprocess.list2cmdline writes a command line by the same Microsoft rules: reading it back
    must give the arguments again."""
    assert split_args(subprocess.list2cmdline(args)) == args


@pytest.mark.skipif(sys.platform != "win32", reason="Windows' own parser")
@pytest.mark.parametrize("line", [
    r'reg add "HKLM\A B\" /v N', r'reg add "HKLM\A\\" /v N /d "x y"', r'reg  add K /d a\\b "c d"\e',
    r'reg add K /d \\\"x\\\" /f', 'reg add K /d "" /f',
])
def test_split_args_agrees_with_windows(line):
    """CommandLineToArgvW (shell32) follows the same rules for these cases (it differs only on `""`
    inside quotes, which is not used here)."""
    import ctypes
    from ctypes import wintypes
    fn = ctypes.windll.shell32.CommandLineToArgvW
    fn.argtypes, fn.restype = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)], ctypes.POINTER(wintypes.LPWSTR)
    n = ctypes.c_int()
    argv = fn(line, ctypes.byref(n))
    try:
        assert split_args(line) == [argv[i] for i in range(n.value)]
    finally:
        ctypes.windll.kernel32.LocalFree(argv)


# -- which program -------------------------------------------------------------------------------------
@pytest.mark.parametrize("image, original, expected", [
    (r"C:\Windows\System32\reg.exe", "reg.exe", True),
    (r"C:\Windows\SysWOW64\REG.EXE", None, True),
    (r"C:\Users\u\Desktop\notreg.exe", "reg.exe", True),         # a renamed copy of the real reg.exe
    (r"C:\Users\u\Desktop\reg.exe", "evil.exe", False),          # another program merely called reg.exe
    (r"C:\Users\u\Desktop\reg.exe", "-", True),                  # Sysmon knew no built-in name: the file name decides
    (r"C:\Users\u\Desktop\reg.exe", "?", True),
    (r"C:\Users\u\Desktop\tool.exe", "?", False),
    (r"C:\Windows\System32\regedit.exe", "REGEDIT.EXE", False),
    (r"C:\Windows\System32\cmd.exe", "Cmd.Exe", False),
    (None, None, False),
])
def test_is_reg(image, original, expected):
    assert is_reg(image, original) is expected


# -- reg add: value name, type, data ---------------------------------------------------------------------
@pytest.mark.parametrize("tail, target, details", [
    ("/v Name /t REG_DWORD /d 1 /f", K + r"\Name", "DWORD (0x00000001)"),
    ("/v Name /t REG_DWORD /d 010", K + r"\Name", "DWORD (0x0000000a)"),           # "010" is ten, not octal
    ("/v Name /t REG_DWORD /d 0x10", K + r"\Name", "DWORD (0x00000010)"),
    ("/v Name /t REG_DWORD /d 0XfF", K + r"\Name", "DWORD (0x000000ff)"),
    ("/v Name /t REG_DWORD /d 4294967295", K + r"\Name", "DWORD (0xffffffff)"),
    ('/v Name /t REG_DWORD /d " 5"', K + r"\Name", "DWORD (0x00000005)"),
    ("/v Name /t REG_DWORD /d +5", K + r"\Name", "DWORD (0x00000005)"),
    ("/V Name /T reg_dword /D 5", K + r"\Name", "DWORD (0x00000005)"),             # switches and types in any case
    ("-v Name -d x", K + r"\Name", "x"),                                           # - works like /
    ("/v Name /d hello", K + r"\Name", "hello"),                                   # the default type is REG_SZ
    ("/v Name", K + r"\Name", "(Empty)"),
    ('/v Name /d ""', K + r"\Name", "(Empty)"),
    ("/v Name /t REG_SZ", K + r"\Name", "(Empty)"),
    (r'/v Name /t REG_EXPAND_SZ /d "%TEMP%\a b.exe"', K + r"\Name", r"%TEMP%\a b.exe"),
    ("/v Name /d /c", K + r"\Name", "/c"),                                         # /d takes the next argument as is
    ("/v Name /d -x", K + r"\Name", "-x"),
    ("/ve /d x", K + r"\(Default)", "x"),
    ("/d x", K + r"\(Default)", "x"),                                              # no /v = the default value
    ('/v "" /d x', K + r"\(Default)", "x"),
    ("/v Name /t REG_BINARY /d 0A0b", K + r"\Name", "Binary Data"),
    ("/v Name /t REG_BINARY /d 0A0", K + r"\Name", "Binary Data"),
    ("/v Name /t REG_BINARY", K + r"\Name", "Binary Data"),
    (r"/v Name /t REG_MULTI_SZ /d a\0b", K + r"\Name", "Binary Data"),
    ("/v Name /t REG_MULTI_SZ /s , /d a,b", K + r"\Name", "Binary Data"),
    ("/v Name /t REG_NONE /d x", K + r"\Name", "Binary Data"),
    ("/v Name /t REG_QWORD /d 0x1122334455667788", K + r"\Name", "QWORD (0x11223344-0x55667788)"),
    ("/v Name /d x /reg:64", K + r"\Name", "x"),
    ('/v "Na me" /d "a b"', K + r"\Na me", "a b"),
    # found by the independent review's probes of the real reg.exe (2026-11-16):
    ('/v " Name\t" /d " x "', K + r"\Name", " x "),                               # the name is trimmed, the data is not
    ('/v " " /d x', K + r"\(Default)", "x"),
    ('/v Name /t " REG_DWORD\t" /d 1', K + r"\Name", "DWORD (0x00000001)"),       # the type is trimmed
    ('/v Name /t REG_DWORD /d "5 "', K + r"\Name", "DWORD (0x00000005)"),
    ('/v Name /t REG_DWORD /d "5\t"', K + r"\Name", "DWORD (0x00000005)"),
    ("/v Name /t REG_DWORD /d \uff15", K + r"\Name", "DWORD (0x00000005)"),       # fullwidth 5
    ("/v Name /t REG_DWORD /d \u0665\u0665", K + r"\Name", "DWORD (0x00000037)"),  # Arabic-Indic 55
    ("/v Name /t REG_DWORD_LITTLE_ENDIAN /d 0x10", K + r"\Name", "DWORD (0x00000010)"),
    ("/v Name /t REG_DWORD_BIG_ENDIAN /d 1", K + r"\Name", "Binary Data"),
    ("/v Name /t REG_QWORD", K + r"\Name", "QWORD (0x00000000-0x00000000)"),      # QWORD (not DWORD) defaults to 0
    ('/v Name /t REG_QWORD /d ""', K + r"\Name", "QWORD (0x00000000-0x00000000)"),
    ("/v Name /t REG_QWORD /d -1", K + r"\Name", "QWORD (0xffffffff-0xffffffff)"),  # a QWORD minus wraps around
    ("/v Name /t REG_QWORD /d -18446744073709551615", K + r"\Name", "QWORD (0x00000000-0x00000001)"),
    ("/v Name /t REG_QWORD /d +5", K + r"\Name", "QWORD (0x00000000-0x00000005)"),
    ('/v Name /t REG_BINARY /d "0a 0b"', K + r"\Name", "Binary Data"),
    ("/v Name /t REG_MULTI_SZ", K + r"\Name", "Binary Data"),
    ("/v Name /t REG_EXPAND_SZ", K + r"\Name", "(Empty)"),
])
def test_reg_add_declares_one_value(tail, target, details):
    assert one(f"reg add {K} {tail}") == set_value(target, details)


@pytest.mark.parametrize("tail", [
    "/v Name /t REG_DWORD",                    # a number type needs /d
    "/v Name /t REG_DWORD /d 4294967296", "/v Name /t REG_DWORD /d -1", "/v Name /t REG_DWORD /d abc",
    "/v Name /t REG_QWORD /d 18446744073709551616",
    "/v Name /t REG_BINARY /d zz",
    "/v Name /t REG_FOO /d x",
    "/ve /v Name /d x",                        # both a name and "the default value"
    "/v A /v B /d x",                          # a switch twice
    "/v Name /d x /f /f",
    "/v Name /d x /z",                         # an unknown switch
    "/v Name /d x extra",                      # a stray argument
    "/v Name /d x /reg:16", "/v Name /d x /reg:32 /reg:64",
    "/v",                                      # the value of a switch is missing
    # found by the independent review's probes of the real reg.exe:
    "/v Name /d a,b /s ,", "/v Name /t REG_SZ /s , /d a,b",        # a separator without REG_MULTI_SZ
    "/v Name /t REG_MULTI_SZ /s ab /d aabb", '/v Name /t REG_MULTI_SZ /s "" /d a',
    "/v Name /t REG_DWORD /d +0x10", "/v Name /t REG_QWORD /d -0x1", "/v Name /t REG_QWORD /d +0x10",
    '/v Name /t REG_DWORD /d ""', "/v Name /t REG_DWORD /d 0x", "/v Name /t REG_DWORD /d 0x100000000",
    "/v Name /t REG_DWORD /d 5\u00a0",                             # a no-break space is not trimmed
    "/v Name /t REG_QWORD /d -18446744073709551616",
    "/v Name /t REG_DWORD_BIG_ENDIAN",                             # needs /d like REG_DWORD
    "/v Name /t REG_LINK /d x", "/v Name /t REG_FULL_RESOURCE_DESCRIPTOR /d x",
    "/v Name /t REG_DWORD /d " + "9" * 5000, "/v Name /t REG_QWORD /d " + "9" * 5000,   # refused, and never an exception
    "/v Name /t REG_DWORD /d 0x" + "0" * 5000,
])
def test_what_reg_exe_calls_invalid_syntax_declares_nothing(tail):
    assert declared(f"reg add {K} {tail}") == []


@pytest.mark.parametrize("line", [
    r"reg query HKLM\SOFTWARE\Contoso /v Name", r"reg export HKLM\SOFTWARE\Contoso out.reg",
    r"reg import evil.reg", r"reg copy HKLM\A HKLM\B /s /f", r"reg save HKLM\SAM sam.hiv",
    r"reg load HKLM\X file.hiv", r"reg restore HKLM\X file.hiv", "reg", "reg add", "", None,
    r"reg add /v Name /d x HKLM\SOFTWARE\Contoso",           # the key must come first
    r"reg add \\server\HKLM\SOFTWARE\Contoso /v Name /d x",  # another computer's registry
    r"reg add HKXX\SOFTWARE\Contoso /v Name /d x", r"reg add HKCU:\Software\Contoso /v Name /d x",
    "reg add HKCU\\ /v Name /d x", r"reg add HKLM\SOFTWARE\\Contoso /v Name /d x",
    r"reg delete HKLM\SOFTWARE\Contoso /va /f",              # every value: no single value is named
    r"reg delete HKLM\SOFTWARE\Contoso /v A /ve",
    # found by the independent review's probes of the real reg.exe:
    "reg add HKLM\\SOFTWARE\\Contoso\\\\ /v Name /d x",             # the key ends in TWO backslashes
    "reg delete HKLM\\SOFTWARE\\Contoso\\\\ /f",
    r"reg delete HKLM\SOFTWARE\Contoso -v Name -f",              # reg delete takes only / switches
    r"reg delete HKLM\SOFTWARE\Contoso /v Name -f",
    r'"C:\Windows\system32\reg.exe"add HKLM\SOFTWARE\Contoso /v Name /d x',   # no space after the quoted program
    "reg add HKLM\\SOFTWARE\\" + "k" * 256 + " /v Name /d x",          # a key part over the registry's 255
])
def test_not_a_local_single_write_declares_nothing(line):
    assert declared(line) == []


def test_bare_reg_add_creates_the_key_and_an_empty_default_value():
    assert declared(f"reg add {K} /f") == [
        {"event_id": 12, "EventType": "CreateKey", "TargetObject": K, "Details": None},
        set_value(K + r"\(Default)", "(Empty)")]


def test_verb_and_program_spelling_do_not_matter():
    for line in (f"REG ADD {K} /v N /d x", f'"C:\\Windows\\system32\\reg.exe" Add "{K}" /v N /d x',
                 f'reg add " {K}\t" /v N /d x',                    # the key is trimmed of spaces and tabs
                 "reg add HKLM\\SOFTWARE\\Contoso\\" + "A" * 0 + "App /v N /d x",
                 f"reg.exe   add   {K}\\ /v N /d x"):             # ONE trailing backslash on the key is accepted
        assert one(line) == set_value(K + r"\N", "x")


# -- Sysmon's key names ----------------------------------------------------------------------------------
@pytest.mark.parametrize("key, targets", [
    (r"HKLM\SOFTWARE\Contoso", [r"HKLM\SOFTWARE\Contoso\N"]),
    (r"hkey_local_machine\Software\Contoso", [r"HKLM\Software\Contoso\N"]),
    (r"HKLM", [r"HKLM\N"]),                                                    # reg.exe accepts a bare root
    (r"HKLM\SYSTEM\ControlSet001\Services\Svc", [r"HKLM\System\CurrentControlSet\Services\Svc\N"]),
    (r"HKLM\SYSTEM\CurrentControlSet\Services\Svc", [r"HKLM\SYSTEM\CurrentControlSet\Services\Svc\N"]),
    (r"HKLM\SYSTEM\ControlSet001x\Svc", [r"HKLM\SYSTEM\ControlSet001x\Svc\N"]),
    (r"HKCU\Software\Contoso", [r"HKU\<SID>\Software\Contoso\N"]),
    (r"HKEY_CURRENT_USER\Control Panel\Desktop", [r"HKU\<SID>\Control Panel\Desktop\N"]),
    (r"hkcu\software\classes\thing\shell\open\command", [r"HKU\<SID>_Classes\thing\shell\open\command\N"]),
    (r"HKCU\Software\ClassesX\thing", [r"HKU\<SID>\Software\ClassesX\thing\N"]),
    (r"HKU\S-1-5-18\Software\Contoso", [r"HKU\S-1-5-18\Software\Contoso\N"]),
    (r"HKEY_USERS\S-1-5-21-1-2-3-1001\Software\Classes\thing", [r"HKU\S-1-5-21-1-2-3-1001_Classes\thing\N"]),
    (r"HKCR\thing\shell", [r"HKLM\SOFTWARE\Classes\thing\shell\N", r"HKCR\thing\shell\N"]),
    (r"HKLM\Software\Classes\thing\shell", [r"HKLM\Software\Classes\thing\shell\N", r"HKCR\thing\shell\N"]),
    (r"HKCC\Software\Fonts", [r"HKLM\System\CurrentControlSet\Hardware Profiles\Current\Software\Fonts\N",
                               r"HKLM\System\CurrentControlSet\Hardware Profiles\0001\Software\Fonts\N"]),
    (r"HKU\.DEFAULT\Software\Classes\thing", [r"HKU\.DEFAULT\Software\Classes\thing\N"]),     # no _Classes hive there
    (r"HKU\S-1-5-18\Software\Classes\thing", [r"HKU\S-1-5-18\Software\Classes\thing\N"]),
    (r"HKU", [r"HKU\N"]), (r"HKCR", [r"HKLM\SOFTWARE\Classes\N", r"HKCR\N"]),
    (r"HKCU\Software\Classes", [r"HKU\<SID>_Classes\N"]),
    ("HKLM\\SOFTWARE\\" + "k" * 255, ["HKLM\\SOFTWARE\\" + "k" * 255 + "\\N"]),
])
def test_key_names_as_sysmon_writes_them(key, targets):
    assert [e["TargetObject"] for e in declared(f'reg add "{key}" /v N /d x')] == targets


def test_the_32_bit_view_gives_both_candidates():
    native, redirected = r"HKLM\SOFTWARE\Contoso\N", r"HKLM\SOFTWARE\WOW6432Node\Contoso\N"
    line = r"reg add HKLM\SOFTWARE\Contoso /v N /d x"
    assert [e["TargetObject"] for e in declared(line + " /reg:32")] == [native, redirected]
    assert [e["TargetObject"] for e in declared(line, r"C:\Windows\SysWOW64\reg.exe")] == [native, redirected]
    assert [e["TargetObject"] for e in declared(line + " /reg:64", r"C:\Windows\SysWOW64\reg.exe")] == [native]
    assert [e["TargetObject"] for e in declared(line, r"C:\Windows\System32\reg.exe")] == [native]
    already = r"reg add HKLM\SOFTWARE\WOW6432Node\Contoso /v N /d x /reg:32"
    assert [e["TargetObject"] for e in declared(already)] == [redirected]
    assert [e["TargetObject"] for e in declared(r"reg add HKCU\Software\Contoso /v N /d x /reg:32")] == \
        [r"HKU\<SID>\Software\Contoso\N"]                                      # HKCU\Software itself is shared
    classes = r"reg add {} /v N /d x /reg:32"                                 # class keys: partly redirected
    assert [e["TargetObject"] for e in declared(classes.format(r"HKCU\Software\Classes\CLSID\{x}"))] == \
        [r"HKU\<SID>_Classes\CLSID\{x}\N", r"HKU\<SID>_Classes\WOW6432Node\CLSID\{x}\N"]
    assert [e["TargetObject"] for e in declared(classes.format(r"HKCR\CLSID\{x}"))] == \
        [r"HKLM\SOFTWARE\Classes\CLSID\{x}\N", r"HKCR\CLSID\{x}\N",
         r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{x}\N", r"HKCR\WOW6432Node\CLSID\{x}\N"]
    assert [e["TargetObject"] for e in declared(classes.format(r"HKLM\Software\Classes\WOW6432Node\CLSID\{x}"))] == \
        [r"HKLM\Software\Classes\WOW6432Node\CLSID\{x}\N", r"HKCR\WOW6432Node\CLSID\{x}\N"]
    assert [e["TargetObject"] for e in declared(classes.format(r"HKCU\Software\Classes\wow6432node\CLSID"))] == \
        [r"HKU\<SID>_Classes\wow6432node\CLSID\N"]
    assert [e["TargetObject"] for e in declared(r"reg add HKLM\SYSTEM\Contoso /v N /d x /reg:32")] == \
        [r"HKLM\SYSTEM\Contoso\N"]


# -- reg delete --------------------------------------------------------------------------------------------
def test_reg_delete():
    assert declared(f"reg delete {K} /v Name /f") == [
        {"event_id": 12, "EventType": "DeleteValue", "TargetObject": K + r"\Name", "Details": None}]
    assert declared(f"reg delete {K} /ve /f") == [
        {"event_id": 12, "EventType": "DeleteValue", "TargetObject": K + r"\(Default)", "Details": None}]
    assert declared(f"reg delete {K}\\ /f") == [
        {"event_id": 12, "EventType": "DeleteKey", "TargetObject": K, "Details": None}]
    assert declared(f"reg delete {K} /v Name /d x") == []                      # /d is not a delete switch


def test_reg_add_accepts_dash_switches_reg_delete_does_not():
    assert one(f"reg add {K} -v Name -d x -f") == set_value(K + r"\Name", "x")
    assert declared(f"reg delete {K} -v Name") == []


# what the translator may know: registry roots, value types, switches and Sysmon's naming of hives
ALLOWED_PATH_TEXT = {
    "\\", "\\\\", "/", "/-", "\\syswow64\\", "software\\classes", "SOFTWARE\\Classes", "wow6432node", "software",
    "System\\CurrentControlSet", "HKLM\\System\\CurrentControlSet\\Hardware Profiles\\",
    "HKLM\\SOFTWARE\\Classes\\WOW6432Node", "HKCR\\WOW6432Node", "HKLM\\SOFTWARE\\WOW6432Node",
    "_Classes", "_Classes\\WOW6432Node", "HKU\\",
}


def test_the_module_names_no_key_or_rule():
    """Fair-test rule: the translator is reg.exe's syntax and Sysmon's naming only; the keys worth an
    alert live in the community rules. Every text constant in the module that looks like a registry
    path (has a backslash) or is long must be on the short list above: adding a key name fails here."""
    import ast
    tree = ast.parse(open(regcmd.__file__, encoding="utf-8").read())
    docstrings = {id(n.body[0].value) for n in ast.walk(tree)
                  if isinstance(n, (ast.Module, ast.FunctionDef)) and n.body and isinstance(n.body[0], ast.Expr)
                  and isinstance(n.body[0].value, ast.Constant) and isinstance(n.body[0].value.value, str)}
    texts = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings}
    regexes = {p.pattern for p in vars(regcmd).values() if isinstance(p, type(regcmd._DECIMAL))}
    words = (set(regcmd.ROOTS) | set(regcmd.ROOTS.values()) | regcmd.TYPES | set(regcmd.ADD_SWITCHES) | set(regcmd.DELETE_SWITCHES)
             | {"SetValue", "CreateKey", "DeleteKey", "DeleteValue", "(Default)", "<SID>", "(Empty)", "Binary Data",
                "reg.exe", "add", "delete", "REG_SZ", "Current", "0001", "event_id", "EventType", "TargetObject", "Details"})
    odd = sorted(x for x in texts - regexes - words - ALLOWED_PATH_TEXT if "\\" in x or len(x) > 12)
    assert odd == [], odd
