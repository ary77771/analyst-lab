# Version 2 evaluation: J4 false alerts per active hour (normal use) (official)

*Made 2026-11-22T23:03:34+00:00 by `tools/experiments.py` (v2 code) on TEST data: laptop TEST snapshot (2026-11-14 .. 2026-11-20, 2124119 events), every detector run over the snapshot by engine.score (scored in 51.8 min). Pre-registered in `docs/plans/v2-prereg.md`. Aggregate numbers, rule ids, bands and the lab's own scenario program names only (privacy rule 7). Nothing was tuned on these numbers.*

Definitions (pre-registered, reused from `tools/false_alarms.py`): on normal use every alert is a false alarm; an ACTIVE minute is a minute (of the event's UtcTime) with at least one normal-use Sysmon event (our own tools and paused rows excluded); the rate is alerts per active hour. RAISED = at or above the frozen floor (`sigma.min_level` = medium); the lower levels are stored but never shown. Each rule is categorised by its source (sigma = community rule, analystlab = our own rule, beacon = check-in rhythm), level, how many days and how many different programs (anonymous) it fired on, and where those programs live.

- Active hours: **82.6**
- RAISED alerts (>= medium): **7,866** = **95.21 per active hour**
- All levels: 28,070 = 339.76 per active hour

| level | alerts | per active hour |
|---|---:|---:|
| informational | 10,244 | 123.994 |
| low | 9,960 | 120.557 |
| medium | 7,855 | 95.078 |
| high | 11 | 0.133 |
| critical | 0 | 0.000 |

## Raised alerts by rule (the ones an analyst would see)

| source | level | rule | alerts | per active hour | days | programs | where the programs live |
|---|---|---|---:|---:|---:|---:|---|
| analystlab | medium | A program that never listened here opened a listening port | 7,337 | 88.808 | 6 | 39 | Program Files 4947, Windows 2374, ProgramData 6, user folders 5, other 5 |
| beacon | medium | Regular check-in rhythm | 126 | 1.525 | 7 | 15 | Program Files 68, user folders 43, ProgramData 7, Windows 7, other 1 |
| sigma | medium | Portable Gpg.EXE Execution | 105 | 1.271 | 1 | 1 | other 105 |
| analystlab | medium | A program started a command shell it never started here before | 51 | 0.617 | 7 | 3 | Windows 51 |
| analystlab | medium | One program created many files and deleted many files within a minute | 27 | 0.327 | 7 | 15 | Program Files 22, Windows 5 |
| sigma | medium | Whoami.EXE Execution With Output Option | 24 | 0.290 | 4 | 1 | Windows 24 |
| sigma | medium | Whoami.EXE Execution Anomaly | 24 | 0.290 | 4 | 1 | Windows 24 |
| analystlab | medium | Program connected out, wrote an executable, and it was started | 20 | 0.242 | 6 | 4 | other 9, Windows 8, Program Files 3 |
| sigma | medium | Use of OpenConsole | 18 | 0.218 | 6 | 2 | user folders 18 |
| sigma | medium | Execution of Suspicious File Type Extension | 18 | 0.218 | 1 | 9 | Program Files 18 |
| sigma | medium | Change PowerShell Policies to an Insecure Level | 17 | 0.206 | 4 | 2 | Windows 17 |
| sigma | medium | Arbitrary DLL or Csproj Code Execution Via Dotnet.EXE | 13 | 0.157 | 3 | 1 | Program Files 13 |
| sigma | medium | CurrentVersion NT Autorun Keys Modification | 11 | 0.133 | 2 | 2 | Windows 11 |
| sigma | medium | Potential Homoglyph Attack Using Lookalike Characters in Filename | 9 | 0.109 | 2 | 1 | Program Files 9 |
| sigma | medium | CurrentVersion Autorun Keys Modification | 8 | 0.097 | 5 | 4 | Windows 4, Program Files 3, user folders 1 |
| sigma | medium | Wow6432Node Windows NT CurrentVersion Autorun Keys Modification | 8 | 0.097 | 2 | 1 | Windows 8 |
| sigma | high | Script Interpreter Execution From Suspicious Folder | 7 | 0.085 | 2 | 2 | Windows 7 |
| sigma | medium | Explorer Process Tree Break | 6 | 0.073 | 3 | 1 | Windows 6 |
| sigma | medium | Potentially Suspicious CMD Shell Output Redirect | 4 | 0.048 | 1 | 1 | Windows 4 |
| sigma | high | PowerShell Base64 Encoded FromBase64String Cmdlet | 4 | 0.048 | 1 | 1 | Windows 4 |
| sigma | medium | Suspicious Execution of Powershell with Base64 | 4 | 0.048 | 1 | 1 | Windows 4 |
| sigma | medium | PowerShell Script Run in AppData | 4 | 0.048 | 1 | 1 | Windows 4 |
| sigma | medium | Potential Persistence Attempt Via Run Keys Using Reg.EXE | 4 | 0.048 | 4 | 1 | Windows 4 |
| sigma | medium | Direct Autorun Keys Modification | 4 | 0.048 | 4 | 1 | Windows 4 |
| sigma | medium | Potential Configuration And Service Reconnaissance Via Reg.EXE | 4 | 0.048 | 4 | 1 | Windows 4 |
| sigma | medium | Potentially Suspicious Powershell Script Execution From Temp Folder | 3 | 0.036 | 2 | 1 | Windows 3 |
| sigma | medium | Rundll32 Execution With Uncommon DLL Extension | 3 | 0.036 | 2 | 1 | Windows 3 |
| sigma | medium | Process Deletion of Its Own Executable | 2 | 0.024 | 2 | 2 | Program Files 2 |
| sigma | medium | Rundll32 Internet Connection | 1 | 0.012 | 1 | 1 | Windows 1 |

## Every level, per rule (tools/false_alarms.py's own report)

- Active hours: **82.6**
- Alerts: **28,070** = **339.76 per active hour**

| Level | Alerts | Per active hour |
|---|---:|---:|
| informational | 10,244 | 123.994 |
| low | 9,960 | 120.557 |
| medium | 7,855 | 95.078 |
| high | 11 | 0.133 |
| critical | 0 | 0.0 |

## Per rule (most alerts first)

| Source | Level | Rule | Alerts | Share | Per active hour | Days | Programs | Where the programs live |
|---|---|---|---:|---:|---:|---:|---:|---|
| sigma | informational | Suspicious High IntegrityLevel Conhost Legacy Option | 10,244 | 36.5 % | 123.994 | 7 | 1 | Windows 10244 |
| sigma | low | Non Interactive PowerShell Process Spawned | 9,921 | 35.3 % | 120.085 | 7 | 2 | Windows 9921 |
| analystlab | medium | A program that never listened here opened a listening port | 7,337 | 26.1 % | 88.808 | 6 | 39 | Program Files 4947, Windows 2374, ProgramData 6, user folders 5, other 5 |
| beacon | medium | Regular check-in rhythm | 126 | 0.4 % | 1.525 | 7 | 15 | Program Files 68, user folders 43, ProgramData 7, Windows 7, other 1 |
| sigma | medium | Portable Gpg.EXE Execution | 105 | 0.4 % | 1.271 | 1 | 1 | other 105 |
| analystlab | medium | A program started a command shell it never started here before | 51 | 0.2 % | 0.617 | 7 | 3 | Windows 51 |
| analystlab | medium | One program created many files and deleted many files within a minute | 27 | 0.1 % | 0.327 | 7 | 15 | Program Files 22, Windows 5 |
| sigma | low | Local Accounts Discovery | 24 | 0.1 % | 0.290 | 4 | 1 | Windows 24 |
| sigma | medium | Whoami.EXE Execution With Output Option | 24 | 0.1 % | 0.290 | 4 | 1 | Windows 24 |
| sigma | medium | Whoami.EXE Execution Anomaly | 24 | 0.1 % | 0.290 | 4 | 1 | Windows 24 |
| analystlab | medium | Program connected out, wrote an executable, and it was started | 20 | 0.1 % | 0.242 | 6 | 4 | other 9, Windows 8, Program Files 3 |
| sigma | medium | Use of OpenConsole | 18 | 0.1 % | 0.218 | 6 | 2 | user folders 18 |
| sigma | medium | Execution of Suspicious File Type Extension | 18 | 0.1 % | 0.218 | 1 | 9 | Program Files 18 |
| sigma | medium | Change PowerShell Policies to an Insecure Level | 17 | 0.1 % | 0.206 | 4 | 2 | Windows 17 |
| sigma | medium | Arbitrary DLL or Csproj Code Execution Via Dotnet.EXE | 13 | 0.0 % | 0.157 | 3 | 1 | Program Files 13 |
| sigma | medium | CurrentVersion NT Autorun Keys Modification | 11 | 0.0 % | 0.133 | 2 | 2 | Windows 11 |
| sigma | medium | Potential Homoglyph Attack Using Lookalike Characters in Filename | 9 | 0.0 % | 0.109 | 2 | 1 | Program Files 9 |
| sigma | low | NodeJS Execution of JavaScript File | 9 | 0.0 % | 0.109 | 6 | 2 | Program Files 9 |
| sigma | medium | CurrentVersion Autorun Keys Modification | 8 | 0.0 % | 0.097 | 5 | 4 | Windows 4, Program Files 3, user folders 1 |
| sigma | medium | Wow6432Node Windows NT CurrentVersion Autorun Keys Modification | 8 | 0.0 % | 0.097 | 2 | 1 | Windows 8 |
| sigma | high | Script Interpreter Execution From Suspicious Folder | 7 | 0.0 % | 0.085 | 2 | 2 | Windows 7 |
| sigma | medium | Explorer Process Tree Break | 6 | 0.0 % | 0.073 | 3 | 1 | Windows 6 |
| sigma | medium | Potentially Suspicious CMD Shell Output Redirect | 4 | 0.0 % | 0.048 | 1 | 1 | Windows 4 |
| sigma | high | PowerShell Base64 Encoded FromBase64String Cmdlet | 4 | 0.0 % | 0.048 | 1 | 1 | Windows 4 |
| sigma | medium | Suspicious Execution of Powershell with Base64 | 4 | 0.0 % | 0.048 | 1 | 1 | Windows 4 |
| sigma | medium | PowerShell Script Run in AppData | 4 | 0.0 % | 0.048 | 1 | 1 | Windows 4 |
| sigma | medium | Potential Persistence Attempt Via Run Keys Using Reg.EXE | 4 | 0.0 % | 0.048 | 4 | 1 | Windows 4 |
| sigma | medium | Direct Autorun Keys Modification | 4 | 0.0 % | 0.048 | 4 | 1 | Windows 4 |
| sigma | medium | Potential Configuration And Service Reconnaissance Via Reg.EXE | 4 | 0.0 % | 0.048 | 4 | 1 | Windows 4 |
| sigma | low | Scheduled Task Creation Via Schtasks.EXE | 4 | 0.0 % | 0.048 | 4 | 1 | Windows 4 |
| sigma | medium | Potentially Suspicious Powershell Script Execution From Temp Folder | 3 | 0.0 % | 0.036 | 2 | 1 | Windows 3 |
| sigma | medium | Rundll32 Execution With Uncommon DLL Extension | 3 | 0.0 % | 0.036 | 2 | 1 | Windows 3 |
| sigma | medium | Process Deletion of Its Own Executable | 2 | 0.0 % | 0.024 | 2 | 2 | Program Files 2 |
| sigma | low | File Deletion Via Del | 2 | 0.0 % | 0.024 | 1 | 1 | Windows 2 |
| sigma | medium | Rundll32 Internet Connection | 1 | 0.0 % | 0.012 | 1 | 1 | Windows 1 |

The 5 noisiest rules make **98.8 %** of all alerts; 35 rules fired at least once.

## Friends' laptops (statistics files: counts only)

No friends' statistics files under recordings/friends/.
