"""v4 F8: PowerShell code DECLARED on a powershell.exe command line, as script block logging would log it.

Our recorder reads Sysmon only, not PowerShell's own log, so the code an attacker passes on the command
line (`powershell.exe -Command <code>`, `powershell.exe <code>`, `powershell.exe -EncodedCommand
<base64>`) leaves one trace: powershell.exe's process start (Sysmon event 1). SigmaHQ's ~165 PowerShell
script rules (category ps_script) read PowerShell's script block event (4104, field ScriptBlockText),
so they never see it. This module reads the command line the way powershell.exe does and returns the
code it would compile; engine/detect.py offers it to the ps_script rules as a DERIVED row (never
stored, never a graph fact: the alert cites the powershell.exe start and says the code was declared,
not recorded; it may not have run).

Nothing here knows any command, cmdlet or rule: it is powershell.exe's own argument syntax, nothing else.

Where each fact comes from (docs/plans/v4-prereg.md section 5, F8):
  - the arguments: Microsoft's C runtime rules (engine/regcmd.split_args, cross-checked against
    Windows' CommandLineToArgvW in tests/test_regcmd.py);
  - what powershell.exe 5.1 does with them: probes on this laptop (Windows PowerShell 5.1,
    Windows 11 10.0.26300, 2026-11-16), every command printing its OWN script block text
    ($MyInvocation.MyCommand.ScriptBlock); results in tests/data/powershell_cmdline_oracle.json:
      * `-Command` / its prefixes: EVERY argument after it, joined by ONE space, is the code (later
        "switches" are code too); `-Command -` reads standard input (nothing declared);
      * the first argument that does not start with a dash or '/' starts the code the same way
        (Windows PowerShell 5.1; PowerShell 7 would read it as a script FILE);
      * `-EncodedCommand` / its prefixes: the next argument is base64 of UTF-16LE text (spaces inside
        are ignored, padding is required, as .NET Convert.FromBase64String); a further code argument
        is refused by powershell.exe ("a command is already specified");
      * a parameter starts with '-', '/' or a Unicode dash (en dash seen working), any case, and may
        be shortened to a prefix; for the parameters in PARAMETERS every accepted prefix was probed;
        for -EncodedCommand every prefix is accepted but only e, en, enc, enco, encodedc, the full
        name and the alias ec were probed (no more base64 probes after Defender flagged some: the
        rest follows Microsoft's documentation and PowerShell 7's table, shortest "e");
      * switches (-NoProfile, -NonInteractive, ...) are skipped; -WindowStyle, -ExecutionPolicy,
        -Version, -InputFormat, -OutputFormat take the next argument.
    PowerShell's open source parser (PowerShell 7, CommandLineParameterParser.cs) has the same table
    shape; where 5.1 behaves differently, 5.1 (the probes) decides.

An UNKNOWN dash word starts the code like any other word (probed after the review: `-foo <code>`,
`-x;<code>`, `-ExecutionPolicy:Bypass -c <code>` are compiled as code), so one odd word cannot hide the
code. Nothing is declared (None) for: -File (the code is in a file we do not have), standard input
(also `-c - x`, which powershell.exe refuses), 5.1's own parameters we do not read (REFUSED: probed,
none compiles code), a missing or refused value (VALID), an undecodable -EncodedCommand, code given
twice, an empty command, and pwsh.exe (PowerShell 7 is not installed here, so its rules could not be
probed). Arguments are split with the OLD msvcrt.dll rule for `""` inside quotes (probed).

Known limits (stated, not hidden):
  - a script block that fails to parse is never logged; this module does not parse PowerShell, so
    such code is still declared (the alert says the code may not have run);
  - PowerShell splits very long script blocks over several 4104 events; one row holds all of it;
  - `-Version 2` runs the old engine, which has no script block logging; the code is still declared
    (what was asked for is the question, not what the log would have shown);
  - code that PowerShell itself builds later (Invoke-Expression, nested script blocks) is not seen.
"""

import base64
import binascii
import re

from .regcmd import split_args

DASHES = "-/–—―"          # '-', '/', en dash, em dash, horizontal bar

# parameter word (lower case, without its dash) -> what powershell.exe 5.1 does with it. Only words
# PROBED on 5.1 are here (tests/data/powershell_cmdline_oracle.json; tests/test_pscmd.py checks the
# table against it): "switch" = skipped, "value" = takes the next argument, "command" = the rest is
# code, "encoded" = the next argument is base64 code, "file" = a script file (nothing declared).
# (full name, shortest accepted prefix, kind): every prefix from the shortest to the full name was probed
# (the same shape as PowerShell 7's MatchSwitch(key, name, shortest)); "ep", "if", "of" are aliases.
_TABLE = [("command", "c", "command"), ("file", "f", "file"),
          ("executionpolicy", "ex", "value"), ("ep", "ep", "value"), ("inputformat", "i", "value"),
          ("if", "if", "value"), ("outputformat", "o", "value"), ("of", "of", "value"),
          ("version", "v", "value"), ("windowstyle", "w", "value"),
          ("sta", "st", "switch"), ("mta", "mta", "switch"), ("noexit", "noe", "switch"),
          ("nologo", "nol", "switch"), ("noninteractive", "noni", "switch"), ("noprofile", "nop", "switch"),
          ("importsystemmodules", "imp", "switch")]          # review 2026-11-17: -imp ... probed, a switch
PARAMETERS = {name[:k]: kind for name, shortest, kind in _TABLE for k in range(len(shortest), len(name) + 1)}
_NAME = {name[:k]: {"ep": "executionpolicy", "if": "inputformat", "of": "outputformat"}.get(name, name)
         for name, shortest, kind in _TABLE for k in range(len(shortest), len(name) + 1)}
_ENCODED_NAME = "encodedcommand"         # -e ... -encodedcommand (probed: e, ec, en, enc, enco, encodedc, the
                                         # full name; Microsoft documents -e/-ec; PowerShell 7's table: min "e")
# powershell.exe 5.1's OWN parameters that we do not read (probed 2026-11-17, every prefix from the shortest
# on: each was refused, opened another mode or hung, and compiled no code) -> nothing is declared.
_REFUSED_TABLE = [("configurationname", "config"), ("encodedarguments", "encodeda"), ("ea", "ea"), ("help", "h"),
                  ("namedpipeservermode", "nam"), ("psconsolefile", "p"), ("servermode", "s"),
                  ("socketservermode", "so"), ("workingdirectory", "wo")]
REFUSED = {name[:k] for name, shortest in _REFUSED_TABLE for k in range(len(shortest), len(name) + 1)} | {"?"}
# Values powershell.exe 5.1 accepts (probed; anything else: it refuses and compiles nothing).
# -ExecutionPolicy takes ANY word (probed: `-ep bogus` still runs the code).
VALID = {"windowstyle": re.compile(r"(?i)(normal|minimized|maximized|hidden|[0-3])\Z"),
         "inputformat": re.compile(r"(?i)(text|xml)\Z"),
         "outputformat": re.compile(r"(?i)(text|xml|none)\Z"),
         "version": re.compile(r"[2-5](\.[0-9])?\Z")}     # probed: 2, 2.0, 3, 5, 5.0, 5.1 run; 9, latest refused
# .NET's String.Trim() set (Char.IsWhiteSpace): unlike Python's str.strip() it keeps U+001C..U+001F
# (probed: `"\x1f-c" <code>` is compiled as code starting with \x1f; `"\xa0-c"` is -c)
_DOTNET_SPACE = " \t\n\v\f\r\x85\xa0            " \
                "    　"

_B64_SPACE = re.compile(r"[ \t\r\n]")
_B64 = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z")


def is_powershell(image, original_file_name=None) -> bool:
    """True for Windows PowerShell's powershell.exe: by the name built into the file (OriginalFileName
    "PowerShell.EXE", so a renamed copy counts) when Sysmon recorded one, else by the file name."""
    original = str(original_file_name or "").strip().lower()
    if original and original not in ("-", "?"):
        return original == "powershell.exe"
    return str(image or "").replace("/", "\\").rsplit("\\", 1)[-1].strip().lower() == "powershell.exe"


def _decode(value):
    """-EncodedCommand's argument as text, or None where powershell.exe refuses it."""
    text = _B64_SPACE.sub("", value or "")
    if not text or len(text) % 4 or not _B64.match(text):
        return None
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw.decode("utf-16-le", errors="replace")


def _kind(word):
    """What one argument is: ("param", kind, name) for a parameter we read; ("refused", None, None) for
    5.1's own parameters we do not read and a lone dash (standard input); ("code", None, None) for a
    word that starts the code: any other word, INCLUDING an unknown dash word (probed: `-foo <code>`,
    `-x`, `-n`, `-ExecutionPolicy:Bypass`, `--nop` are compiled as code; review 2026-11-17);
    ("empty", None, None) for an argument of only spaces (skipped: probed `"" <code>` runs <code>). A
    parameter word is trimmed with .NET's whitespace set first (probed: `" -nop"` is -NoProfile)."""
    word = word.strip(_DOTNET_SPACE)
    if not word:
        return "empty", None, None
    if word[:1] not in DASHES:
        return "code", None, None
    if len(word) == 1:
        return "refused", None, None             # a lone dash: standard input
    key = word[1:].lower()
    if key in PARAMETERS:
        return "param", PARAMETERS[key], _NAME[key]
    if _ENCODED_NAME.startswith(key) or key == "ec":    # -ec: Microsoft's documented alias (probed)
        return "param", "encoded", _ENCODED_NAME
    if key in REFUSED:
        return "refused", None, None
    return "code", None, None


def split(command_line) -> list:
    """powershell.exe's argv: the C runtime rules with the OLD msvcrt.dll treatment of `""` inside quotes
    (a literal quote that also ends the quoted part; probed 2026-11-17, review finding 2)."""
    return split_args(command_line, doubled_quote_ends=True)


def script_text(command_line):
    """The code powershell.exe would compile from this command line (what script block logging
    would show as ScriptBlockText), or None where nothing is declared (see the module docstring)."""
    args = split(command_line)[1:]
    code, i = None, 0
    while i < len(args):
        word = args[i]
        what, kind, name = _kind(word)
        if what == "refused":
            return None
        if what == "empty":
            i += 1
            continue
        if what == "code" or kind == "command":
            if code is not None:
                return None                      # code given twice: powershell.exe refuses (probed)
            rest = args[i:] if what == "code" else args[i + 1:]
            if not rest or rest[0] == "-":       # standard input; `-c - x` is refused (probed)
                return None
            text = " ".join(rest)
            return text if text.strip() else None
        if kind == "file":
            return None
        if kind in ("value", "encoded"):
            if i + 1 >= len(args):
                return None
            if kind == "encoded":
                if code is not None:
                    return None                  # NOT probed (no base64 to a real PowerShell): refused to be safe
                code = _decode(args[i + 1])
                if code is None:
                    return None
            elif name in VALID and not VALID[name].match(args[i + 1]):
                return None                      # powershell.exe refuses the value and runs nothing (probed)
            i += 2
            continue
        i += 1                                   # a switch
    return code if code and code.strip() else None
