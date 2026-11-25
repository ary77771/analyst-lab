# Version 4 evaluation: J4 false alerts per active hour (normal use) (official, v3's official runs re-scored with v4's code)

*Made 2026-11-22T23:28:50+00:00 by `tools/experiments.py` (v4 code) on TEST data: laptop TEST snapshot (2026-11-15 .. 2026-11-21, 1955536 events), every detector run over the snapshot by engine.score (scored in 77.1 min). Pre-registered in `docs/plans/v4-prereg.md`. Aggregate numbers, rule ids, bands and the lab's own scenario program names only (privacy rule 7). Nothing was tuned on these numbers.*

Definitions (pre-registered, reused from `tools/false_alarms.py`): on normal use every alert is a false alarm; an ACTIVE minute is a minute (of the event's UtcTime) with at least one normal-use Sysmon event (our own tools and paused rows excluded); the rate is alerts per active hour. RAISED = at or above the frozen floor (`sigma.min_level` = medium); the lower levels are stored but never shown. Each rule is categorised by its source (sigma = community rule, analystlab = our own rule, beacon = check-in rhythm), level, how many days and how many different programs (anonymous) it fired on, and where those programs live.

- Active hours: **75.6**
- RAISED alerts (>= medium): **319** = **4.22 per active hour**
- All levels: 17,994 = 238.02 per active hour

| level | alerts | per active hour |
|---|---:|---:|
| informational | 8,882 | 117.487 |
| low | 8,793 | 116.310 |
| medium | 318 | 4.206 |
| high | 1 | 0.013 |
| critical | 0 | 0.000 |

## Raised alerts by rule (the ones an analyst would see)

| source | level | rule | alerts | per active hour | days | programs | where the programs live |
|---|---|---|---:|---:|---:|---:|---|
| beacon | medium | Regular check-in rhythm | 137 | 1.812 | 7 | 13 | Program Files 74, user folders 50, Windows 7, ProgramData 5, other 1 |
| analystlab | medium | One program created many files and deleted many files within a minute | 25 | 0.331 | 7 | 16 | Program Files 21, Windows 4 |
| analystlab | medium | A program started a command shell it never started here before | 24 | 0.317 | 7 | 3 | Windows 24 |
| sigma | medium | Whoami.EXE Execution With Output Option | 20 | 0.265 | 3 | 1 | Windows 20 |
| sigma | medium | Whoami.EXE Execution Anomaly | 20 | 0.265 | 3 | 1 | Windows 20 |
| sigma | medium | Arbitrary DLL or Csproj Code Execution Via Dotnet.EXE | 14 | 0.185 | 4 | 1 | Program Files 14 |
| sigma | medium | Use of OpenConsole | 12 | 0.159 | 5 | 2 | user folders 12 |
| sigma | medium | Change PowerShell Policies to an Insecure Level | 11 | 0.146 | 3 | 2 | Windows 11 |
| analystlab | medium | Program connected out, wrote an executable, and it was started | 9 | 0.119 | 6 | 2 | Windows 8, Program Files 1 |
| sigma | medium | CurrentVersion Autorun Keys Modification | 8 | 0.106 | 5 | 5 | Program Files 4, Windows 3, user folders 1 |
| sigma | medium | CurrentVersion NT Autorun Keys Modification | 6 | 0.079 | 1 | 1 | Windows 6 |
| sigma | medium | Wow6432Node Windows NT CurrentVersion Autorun Keys Modification | 6 | 0.079 | 1 | 1 | Windows 6 |
| analystlab | medium | A program that never listened here opened a listening port | 4 | 0.053 | 2 | 2 | other 2, user folders 2 |
| sigma | medium | Potential Homoglyph Attack Using Lookalike Characters in Filename | 3 | 0.040 | 1 | 1 | Program Files 3 |
| sigma | medium | Potential Persistence Attempt Via Run Keys Using Reg.EXE | 3 | 0.040 | 3 | 1 | Windows 3 |
| sigma | medium | Direct Autorun Keys Modification | 3 | 0.040 | 3 | 1 | Windows 3 |
| sigma | medium | Potential Configuration And Service Reconnaissance Via Reg.EXE | 3 | 0.040 | 3 | 1 | Windows 3 |
| sigma | medium | Rundll32 Execution With Uncommon DLL Extension | 3 | 0.040 | 2 | 1 | Windows 3 |
| sigma | medium | Process Deletion of Its Own Executable | 2 | 0.026 | 2 | 2 | Program Files 2 |
| sigma | medium | Explorer Process Tree Break | 2 | 0.026 | 2 | 1 | Windows 2 |
| sigma | medium | Potentially Suspicious Powershell Script Execution From Temp Folder | 1 | 0.013 | 1 | 1 | Windows 1 |
| sigma | high | Script Interpreter Execution From Suspicious Folder | 1 | 0.013 | 1 | 1 | Windows 1 |
| analystlab | medium | A program's name hides a Windows program's name | 1 | 0.013 | 1 | 1 | other 1 |
| analystlab | medium | A program was written, run, connected out, and deleted again | 1 | 0.013 | 1 | 1 | Windows 1 |

## Every level, per rule (tools/false_alarms.py's own report)

- Active hours: **75.6**
- Alerts: **17,994** = **238.02 per active hour**

| Level | Alerts | Per active hour |
|---|---:|---:|
| informational | 8,882 | 117.487 |
| low | 8,793 | 116.31 |
| medium | 318 | 4.206 |
| high | 1 | 0.013 |
| critical | 0 | 0.0 |

## Per rule (most alerts first)

| Source | Level | Rule | Alerts | Share | Per active hour | Days | Programs | Where the programs live |
|---|---|---|---:|---:|---:|---:|---:|---|
| sigma | informational | Suspicious High IntegrityLevel Conhost Legacy Option | 8,882 | 49.4 % | 117.487 | 7 | 1 | Windows 8882 |
| sigma | low | Non Interactive PowerShell Process Spawned | 8,593 | 47.8 % | 113.664 | 7 | 2 | Windows 8593 |
| analystlab | low | A program that never listened here opened a listening port | 156 | 0.9 % | 2.063 | 5 | 6 | Program Files 149, Windows 4, other 3 |
| beacon | medium | Regular check-in rhythm | 137 | 0.8 % | 1.812 | 7 | 13 | Program Files 74, user folders 50, Windows 7, ProgramData 5, other 1 |
| analystlab | medium | One program created many files and deleted many files within a minute | 25 | 0.1 % | 0.331 | 7 | 16 | Program Files 21, Windows 4 |
| analystlab | medium | A program started a command shell it never started here before | 24 | 0.1 % | 0.317 | 7 | 3 | Windows 24 |
| sigma | low | Local Accounts Discovery | 20 | 0.1 % | 0.265 | 3 | 1 | Windows 20 |
| sigma | medium | Whoami.EXE Execution With Output Option | 20 | 0.1 % | 0.265 | 3 | 1 | Windows 20 |
| sigma | medium | Whoami.EXE Execution Anomaly | 20 | 0.1 % | 0.265 | 3 | 1 | Windows 20 |
| sigma | medium | Arbitrary DLL or Csproj Code Execution Via Dotnet.EXE | 14 | 0.1 % | 0.185 | 4 | 1 | Program Files 14 |
| sigma | medium | Use of OpenConsole | 12 | 0.1 % | 0.159 | 5 | 2 | user folders 12 |
| sigma | medium | Change PowerShell Policies to an Insecure Level | 11 | 0.1 % | 0.146 | 3 | 2 | Windows 11 |
| analystlab | low | A program created files and deleted them again | 10 | 0.1 % | 0.132 | 3 | 5 | Windows 8, Program Files 2 |
| sigma | low | NodeJS Execution of JavaScript File | 9 | 0.1 % | 0.119 | 6 | 2 | Program Files 9 |
| analystlab | medium | Program connected out, wrote an executable, and it was started | 9 | 0.1 % | 0.119 | 6 | 2 | Windows 8, Program Files 1 |
| sigma | medium | CurrentVersion Autorun Keys Modification | 8 | 0.0 % | 0.106 | 5 | 5 | Program Files 4, Windows 3, user folders 1 |
| sigma | medium | CurrentVersion NT Autorun Keys Modification | 6 | 0.0 % | 0.079 | 1 | 1 | Windows 6 |
| sigma | medium | Wow6432Node Windows NT CurrentVersion Autorun Keys Modification | 6 | 0.0 % | 0.079 | 1 | 1 | Windows 6 |
| analystlab | medium | A program that never listened here opened a listening port | 4 | 0.0 % | 0.053 | 2 | 2 | other 2, user folders 2 |
| sigma | medium | Potential Homoglyph Attack Using Lookalike Characters in Filename | 3 | 0.0 % | 0.040 | 1 | 1 | Program Files 3 |
| sigma | medium | Potential Persistence Attempt Via Run Keys Using Reg.EXE | 3 | 0.0 % | 0.040 | 3 | 1 | Windows 3 |
| sigma | medium | Direct Autorun Keys Modification | 3 | 0.0 % | 0.040 | 3 | 1 | Windows 3 |
| sigma | medium | Potential Configuration And Service Reconnaissance Via Reg.EXE | 3 | 0.0 % | 0.040 | 3 | 1 | Windows 3 |
| sigma | medium | Rundll32 Execution With Uncommon DLL Extension | 3 | 0.0 % | 0.040 | 2 | 1 | Windows 3 |
| sigma | low | Scheduled Task Creation Via Schtasks.EXE | 3 | 0.0 % | 0.040 | 3 | 1 | Windows 3 |
| sigma | medium | Process Deletion of Its Own Executable | 2 | 0.0 % | 0.026 | 2 | 2 | Program Files 2 |
| sigma | low | File Deletion Via Del | 2 | 0.0 % | 0.026 | 1 | 1 | Windows 2 |
| sigma | medium | Explorer Process Tree Break | 2 | 0.0 % | 0.026 | 2 | 1 | Windows 2 |
| sigma | medium | Potentially Suspicious Powershell Script Execution From Temp Folder | 1 | 0.0 % | 0.013 | 1 | 1 | Windows 1 |
| sigma | high | Script Interpreter Execution From Suspicious Folder | 1 | 0.0 % | 0.013 | 1 | 1 | Windows 1 |
| analystlab | medium | A program's name hides a Windows program's name | 1 | 0.0 % | 0.013 | 1 | 1 | other 1 |
| analystlab | medium | A program was written, run, connected out, and deleted again | 1 | 0.0 % | 0.013 | 1 | 1 | Windows 1 |

The 5 noisiest rules make **98.9 %** of all alerts; 32 rules fired at least once.

## Friends' laptops (statistics files: counts only)

No friends' statistics files under recordings/friends/.
