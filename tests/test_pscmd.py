"""engine/pscmd.py (v4 F8): the code a powershell.exe command line declares, as Windows PowerShell 5.1
builds it. Expected values come from probes of the real powershell.exe 5.1 on this laptop
(2026-11-16; tests/data/powershell_cmdline_oracle.json holds the differential cases)."""
import ast
import base64
import json
import os

import pytest

from engine import pscmd
from engine.pscmd import is_powershell, script_text

PS = r'"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"'
ORACLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "powershell_cmdline_oracle.json")


def enc(code):
    return base64.b64encode(code.encode("utf-16-le")).decode()


@pytest.mark.parametrize("tail, code", [
    ("-Command Get-Date", "Get-Date"),
    ("-Command Get-Date   -Format  o", "Get-Date -Format o"),          # arguments joined by ONE space
    ('-Command "Get-Date  -Format o"', "Get-Date  -Format o"),          # inside quotes spaces stay
    ("-c a; b", "a; b"),
    ("-co x", "x"), ("-com x", "x"), ("-comm x", "x"), ("-COMMAND x", "x"),
    ("/c x", "x"), ("/Command x", "x"),
    ("\u2013c x", "x"), ("\u2014command x", "x"), ("\u2015c x", "x"),   # Unicode dashes
    ("Get-Date", "Get-Date"),                                            # a bare first word starts the code
    ("& {Get-Date}", "& {Get-Date}"),                                    # ART's executor form
    ('& {$a = \\""x\\""}', '& {$a = "x"}'),                             # Invoke-AtomicTest's quote escaping
    ("-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command x", "x"),
    ("-nop -noni -w hidden -ep bypass x", "x"),
    ("-nop -sta -mta -nologo -noni x", "x"),
    ("-ex bypass -exec bypass -executionpolicy bypass -c x", "x"),
    ("-v 5.1 -version 5.1 -c x", "x"),
    ("-inputformat text -if text -outputformat text -of text -o text -c x", "x"),
    ("-c x -NoLogo", "x -NoLogo"),                                       # after -Command everything is code
    ("-c x -c y", "x -c y"),
    ("-c {x}", "{x}"),
    ('-c "a""b"', 'a"b'),                                               # "" inside quotes = one quote (C runtime)
    ("-c a\\\\\\\"b", 'a\\"b'),                                          # 2n+1 backslashes before a quote
])
def test_code_from_command_line(tail, code):
    assert script_text(f"{PS} {tail}") == code


@pytest.mark.parametrize("tail", [
    "", "-NoProfile", "-c", "-c -", '-c " "', '-c ""', "-NoProfile -Command -",
    "-c - x", "-nop -c - x",                                           # 5.1 refuses arguments after `-c -` (probed)
    "-File x.ps1", "-f x.ps1", "-nop -File x.ps1 -c y",                # a script file: nothing declared
    "-w", "-ep", "-nop -w",                                            # a value is missing
    "-w bogus x", "-w 4 x", "-w -1 x", "-if bogus x", "-v 9 x", "-v latest x",   # refused values (probed)
    "-", "-nop -", "- x", "-nop - x",                                  # standard input (a lone dash)
    "-psconsolefile x -c y", "-p x", "-configurationname x -c y", "-config x", "-servermode", "-s x", "-se x",
    "-so x", "-socketservermode", "-nam x", "-ea x", "-encodeda x", "-encodedarguments x", "-wo x",
    "-workingdirectory C:\\ -c y", "-help", "-h", "-?", "/?",           # 5.1's own parameters we do not read
])
def test_nothing_declared(tail):
    assert script_text(f"{PS} {tail}") is None


@pytest.mark.parametrize("tail, code", [
    # an UNKNOWN dash word starts the code (review 2026-11-17, probed: compiled, then "not recognized")
    ("-cmd x", "-cmd x"), ("-foo x", "-foo x"), ("-x x", "-x x"), ("-n x", "-n x"), ("-no x", "-no x"),
    ("-m x", "-m x"), ("-im x", "-im x"), ("-con x", "-con x"), ("-sh x", "-sh x"), ("-int x", "-int x"),
    ("-nop -1;x", "-1;x"), ("-ExecutionPolicy:Bypass -c x", "-ExecutionPolicy:Bypass -c x"),
    ("-command:x", "-command:x"), ("-NoProfile: x", "-NoProfile: x"), ("--nop x", "--nop x"),
    ("-noprofileloadtime x", "-noprofileloadtime x"),
    # -ImportSystemModules is a switch (probed every prefix from -imp)
    ("-imp x", "x"), ("-importsystemmodules -nop x", "x"),
    # values powershell.exe accepts (probed)
    ("-w 1 x", "x"), ("-w 0 x", "x"), ("-w 3 x", "x"), ("-w MAXIMIZED x", "x"), ("-if xml x", "x"),
    ("-of none x", "x"), ("-v 2 x", "x"), ("-v 5.0 x", "x"), ("-ep bogus x", "x"), ("-ep RemoteSigned x", "x"),
    # .NET's trim: U+001C..U+001F are NOT spaces there (probed: compiled as code), NBSP / em space are
    ('"\x1f-c" x', "\x1f-c x"), ('"\x1c-c" x', "\x1c-c x"), ('"\xa0-c" x', "x"), ('"\u2003-c" x', "x"),
    ('"-c\xa0" x', "x"),
    # the OLD msvcrt rule: "" inside quotes = a quote AND the quoted part ends (probed)
    ('-nop "a;\'a""  b\'"', "a;'a\" b'"), ('-c "q;  \'x""y  z\'"', "q;  'x\"y z'"),
])
def test_code_after_the_review(tail, code):
    assert script_text(f"{PS} {tail}") == code


@pytest.mark.parametrize("word", ["-e", "-ec", "-en", "-enc", "-enco", "-encod", "-encodedc", "-encodedcommand",
                                  "-EncodedCommand", "/enc", "/e", "\u2013enc"])
def test_encoded_command_spellings(word):
    assert script_text(f"{PS} -NoProfile {word} {enc('Get-Date')}") == "Get-Date"


def test_encoded_command_details():
    e = enc("Write-Output 'é ü 日本'")
    assert script_text(f"{PS} -enc {e}") == "Write-Output 'é ü 日本'"
    assert script_text(f'{PS} -enc "{e[:8]} {e[8:]}"') == "Write-Output 'é ü 日本'"    # spaces inside: ignored
    assert script_text(f"{PS} -enc {e} -nop -w hidden") == "Write-Output 'é ü 日本'"  # switches may follow
    padded = enc("ab")                                                                   # 'YQBiAA==' needs padding
    assert padded.endswith("=")
    assert script_text(f"{PS} -enc {padded.rstrip('=')}") is None                       # no padding: refused (probed)
    assert script_text(f"{PS} -enc {e} extra") is None                                  # code twice (probed)
    assert script_text(f"{PS} -enc {e} -c x") is None
    assert script_text(f"{PS} -enc {e} -enc {e}") is None
    assert script_text(f"{PS} -enc !!!!") is None
    assert script_text(f"{PS} -enc") is None
    assert script_text(f"{PS} -enc {enc('   ')}") is None                               # empty code
    assert script_text(f"{PS} -encodedcommandx {e}") == f"-encodedcommandx {e}"         # not a prefix: CODE (probed:
                                                                                         # "term not recognized")
    assert script_text(f"{PS} -c x -enc {e}") == f"x -enc {e}"                          # after -c it is code


def test_odd_byte_count_decodes_like_dotnet():
    raw = "ab".encode("utf-16-le") + b"c"
    assert script_text(f"{PS} -enc {base64.b64encode(raw).decode()}") == "ab\ufffd"


@pytest.mark.parametrize("image, original, expected", [
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "PowerShell.EXE", True),
    (r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe", None, True),
    (r"C:\Users\u\p.exe", "PowerShell.EXE", True),                     # a renamed copy
    (r"C:\Users\u\powershell.exe", "other.exe", False),                # merely called so
    (r"C:\x\powershell.exe", "-", True), (r"C:\x\POWERSHELL.EXE", "?", True),
    (r"C:\Program Files\PowerShell\7\pwsh.exe", "pwsh.dll", False),    # PowerShell 7: not probed
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe", "powershell_ise.EXE", False),
    (None, None, False),
])
def test_is_powershell(image, original, expected):
    assert is_powershell(image, original) is expected


def test_every_table_word_is_a_prefix_of_a_powershell_parameter():
    """The table holds powershell.exe's own parameter names (and their prefixes), nothing else."""
    names = ["command", "noprofile", "noninteractive", "nologo", "noexit", "sta", "mta", "windowstyle",
             "executionpolicy", "ep", "version", "inputformat", "if", "outputformat", "of", "file", "importsystemmodules"]
    for word, kind in pscmd.PARAMETERS.items():
        assert any(n.startswith(word) for n in names), word
        assert kind in ("command", "switch", "value", "file")


def test_the_module_names_no_command_or_cmdlet():
    """No text constant in the module beyond syntax: no cmdlet, keyword or path (F8's promise)."""
    tree = ast.parse(open(pscmd.__file__, encoding="utf-8").read())
    docstrings = {id(n.body[0].value) for n in ast.walk(tree)
                  if isinstance(n, (ast.Module, ast.FunctionDef)) and n.body and isinstance(n.body[0], ast.Expr)
                  and isinstance(n.body[0].value, ast.Constant)}
    words = {n.value for n in ast.walk(tree)
             if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings}
    table_names = {name for name, shortest, kind in pscmd._TABLE} | {shortest for name, shortest, kind in pscmd._TABLE}
    refused_names = {n for pair in pscmd._REFUSED_TABLE for n in pair}
    allowed = table_names | refused_names | set(pscmd.VALID) | {v.pattern for v in pscmd.VALID.values()} | {
        "command", "switch", "value", "file", "encoded", "param", "refused", "code", "empty",
        "encodedcommand", "ec", "utf-16-le", "replace", "powershell.exe", "-", "?", "/", "\\", "", " ",
        pscmd.DASHES, pscmd._B64_SPACE.pattern, pscmd._B64.pattern, pscmd._DOTNET_SPACE,
        " \t\n\v\f\r\x85\xa0            ",
        "    　"}
    assert words - allowed == set(), f"unexpected text constants: {sorted(words - allowed)}"


def test_the_review_probes_from_real_powershell():
    """249 command lines run on the real powershell.exe 5.1 after the review (fixture `review_probes`):
    ran -> exactly its text; compiled as code (not recognized / parse error) -> the text from the first
    code word on; refused / other mode / hung -> nothing."""
    doc = json.load(open(ORACLE, encoding="utf-8"))["review_probes"]
    assert len(doc["cases"]) >= 240
    for tail, r in doc["cases"].items():
        line = f'"{doc["program"]}" {tail}'
        mine = script_text(line)
        if r["kind"] == "ran":
            assert mine == r["text"], tail
        elif r["kind"] in ("compiled-not-recognized", "parse-error"):
            assert mine is not None, tail
            first = next(a for a in pscmd.split(line)[1:] if pscmd._kind(a)[0] == "code")
            assert mine.startswith(first), tail
        else:
            assert mine is None, tail


def test_the_table_is_what_the_probe_saw():
    """Every word in PARAMETERS was probed on 5.1 and behaved as its kind; a probed word with no single
    kind (ambiguous or unknown: -n, -no, -m, -s, ...) is not in the table. ExecutionPolicy's prefixes
    also passed the switch probe because it takes ANY next word as its value (even `-nop`); the value
    probe is the deciding one there. -File prints nothing (a missing file), the file kind."""
    doc = json.load(open(ORACLE, encoding="utf-8"))
    probe = doc["parameter_probe"]["results"]
    review = {t.split(" ", 1)[0][1:]: r["kind"] for t, r in doc["review_probes"]["cases"].items() if t.startswith("-")}
    later = {w for w in pscmd.PARAMETERS if w not in probe}
    assert later == {w for w in pscmd.PARAMETERS if "importsystemmodules".startswith(w) and len(w) >= 3}   # after the review
    assert all(review.get(w) == "ran" for w in later)                  # every one of them probed: a switch
    for w in pscmd.REFUSED - {"?"}:
        assert review.get(w) in ("other", "timeout") or w in ("ea",) and review.get(w) == "other", w
    for word, kinds in probe.items():
        mine = pscmd.PARAMETERS.get(word)
        if mine == "file":
            assert kinds == [], word
        elif mine == "value":
            assert "value" in kinds, word
        elif mine is not None:
            assert kinds == [mine], word
        else:
            assert kinds == [] or word in ("e",), word


def test_cmd_line_cases_from_the_oracle_when_present():
    if not os.path.exists(ORACLE):
        pytest.skip("oracle not captured")
    cases = json.load(open(ORACLE, encoding="utf-8"))["cases"]
    wrong, over, refused = [], [], []
    for c in cases:
        real, mine = c["powershell_5_1"], script_text(c["command_line"])
        if real == "BLOCKED":
            continue
        if real is not None and mine is not None and real != mine:
            wrong.append((c["command_line"], real, mine))
        elif real is None and mine is not None:
            over.append(c["command_line"])
        elif real is not None and mine is None:
            refused.append(c["command_line"])
    doc = json.load(open(ORACLE, encoding="utf-8"))
    assert len(cases) >= 170 and sum(c["powershell_5_1"] not in (None, "BLOCKED") for c in cases) >= 140
    assert all(v != "UNEXPLAINED" for part in ("explained_over", "explained_wrong") for v in doc[part].values())
    assert {w[0] for w in wrong} <= set(doc["explained_wrong"]), [w for w in wrong if w[0] not in doc["explained_wrong"]][:3]
    known_over = set(doc.get("explained_over", {}))
    assert set(over) <= known_over, sorted(set(over) - known_over)[:3]
    known_refused = set(json.load(open(ORACLE, encoding="utf-8")).get("explained_refused", {}))
    assert set(refused) <= known_refused, sorted(set(refused) - known_refused)[:3]
