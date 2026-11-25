# Version 4 evaluation: J4 false alerts per active hour (normal use) (official, v1's official runs re-scored with v4's code)

*Made 2026-11-19T21:43:40+00:00 by `tools/experiments.py` (v4 code) on TEST data: laptop TEST snapshot (2026-10-23 .. 2026-10-29, 1950840 events), every detector run over the snapshot by engine.score (scored in 29.4 min). Pre-registered in `docs/plans/v4-prereg.md`. Aggregate numbers, rule ids, bands and the lab's own scenario program names only (privacy rule 7). Nothing was tuned on these numbers.*

Definitions (pre-registered, reused from `tools/false_alarms.py`): on normal use every alert is a false alarm; an ACTIVE minute is a minute (of the event's UtcTime) with at least one normal-use Sysmon event (our own tools and paused rows excluded); the rate is alerts per active hour. RAISED = at or above the frozen floor (`sigma.min_level` = medium); the lower levels are stored but never shown. Each rule is categorised by its source (sigma = community rule, analystlab = our own rule, beacon = check-in rhythm), level, how many days and how many different programs (anonymous) it fired on, and where those programs live.

- Active hours: **47.5**
- RAISED alerts (>= medium): **285** = **6.00 per active hour**
- All levels: 11,823 = 248.91 per active hour

| level | alerts | per active hour |
|---|---:|---:|
| informational | 5,851 | 123.179 |
| low | 5,687 | 119.726 |
| medium | 284 | 5.979 |
| high | 1 | 0.021 |
| critical | 0 | 0.000 |

## Raised alerts by rule (the ones an analyst would see)

| source | level | rule | alerts | per active hour | days | programs | where the programs live |
|---|---|---|---:|---:|---:|---:|---|
| beacon | medium | Regular check-in rhythm | 116 | 2.442 | 7 | 12 | Program Files 70, user folders 33, Windows 11, ProgramData 2 |
| analystlab | medium | A program started a command shell it never started here before | 23 | 0.484 | 4 | 3 | Windows 23 |
| analystlab | medium | One program created many files and deleted many files within a minute | 21 | 0.442 | 7 | 12 | Program Files 16, Windows 4, ProgramData 1 |
| sigma | medium | Whoami.EXE Execution With Output Option | 16 | 0.337 | 3 | 1 | Windows 16 |
| sigma | medium | Whoami.EXE Execution Anomaly | 16 | 0.337 | 3 | 1 | Windows 16 |
| sigma | medium | Change PowerShell Policies to an Insecure Level | 15 | 0.316 | 3 | 2 | Windows 15 |
| sigma | medium | Execution of Suspicious File Type Extension | 9 | 0.189 | 1 | 9 | Program Files 9 |
| sigma | medium | Potential Persistence Attempt Via Run Keys Using Reg.EXE | 8 | 0.168 | 5 | 1 | Windows 8 |
| sigma | medium | Direct Autorun Keys Modification | 8 | 0.168 | 5 | 1 | Windows 8 |
| sigma | medium | Potential Configuration And Service Reconnaissance Via Reg.EXE | 8 | 0.168 | 5 | 1 | Windows 8 |
| sigma | medium | CurrentVersion Autorun Keys Modification | 8 | 0.168 | 5 | 1 | Windows 8 |
| sigma | medium | Use of OpenConsole | 6 | 0.126 | 3 | 2 | user folders 6 |
| analystlab | medium | Program connected out, wrote an executable, and it was started | 6 | 0.126 | 4 | 2 | Windows 4, Program Files 2 |
| sigma | medium | Creation Of a Suspicious ADS File Outside a Browser Download | 5 | 0.105 | 1 | 3 | Program Files 5 |
| sigma | medium | Suspicious Driver Install by pnputil.exe | 4 | 0.084 | 2 | 1 | Windows 4 |
| analystlab | medium | A program's name hides a Windows program's name | 4 | 0.084 | 2 | 4 | Program Files 4 |
| sigma | medium | Msiexec Quiet Installation | 3 | 0.063 | 2 | 1 | Windows 3 |
| sigma | medium | Always Install Elevated Windows Installer | 3 | 0.063 | 2 | 1 | Windows 3 |
| sigma | medium | Office Application Initiated Network Connection To Non-Local IP | 2 | 0.042 | 1 | 1 | Program Files 2 |
| sigma | medium | Process Deletion of Its Own Executable | 1 | 0.021 | 1 | 1 | Program Files 1 |
| sigma | medium | Rundll32 Internet Connection | 1 | 0.021 | 1 | 1 | Windows 1 |
| sigma | high | Allow Service Access Using Security Descriptor Tampering Via Sc.EXE | 1 | 0.021 | 1 | 1 | Windows 1 |
| sigma | medium | Service Security Descriptor Tampering Via Sc.EXE | 1 | 0.021 | 1 | 1 | Windows 1 |

## Every level, per rule (tools/false_alarms.py's own report)

- Active hours: **47.5**
- Alerts: **11,823** = **248.91 per active hour**

| Level | Alerts | Per active hour |
|---|---:|---:|
| informational | 5,851 | 123.179 |
| low | 5,687 | 119.726 |
| medium | 284 | 5.979 |
| high | 1 | 0.021 |
| critical | 0 | 0.0 |

## Per rule (most alerts first)

| Source | Level | Rule | Alerts | Share | Per active hour | Days | Programs | Where the programs live |
|---|---|---|---:|---:|---:|---:|---:|---|
| sigma | informational | Suspicious High IntegrityLevel Conhost Legacy Option | 5,851 | 49.5 % | 123.179 | 7 | 1 | Windows 5851 |
| sigma | low | Non Interactive PowerShell Process Spawned | 5,638 | 47.7 % | 118.695 | 7 | 2 | Windows 5638 |
| beacon | medium | Regular check-in rhythm | 116 | 1.0 % | 2.442 | 7 | 12 | Program Files 70, user folders 33, Windows 11, ProgramData 2 |
| analystlab | medium | A program started a command shell it never started here before | 23 | 0.2 % | 0.484 | 4 | 3 | Windows 23 |
| analystlab | medium | One program created many files and deleted many files within a minute | 21 | 0.2 % | 0.442 | 7 | 12 | Program Files 16, Windows 4, ProgramData 1 |
| sigma | low | Local Accounts Discovery | 16 | 0.1 % | 0.337 | 3 | 1 | Windows 16 |
| sigma | medium | Whoami.EXE Execution With Output Option | 16 | 0.1 % | 0.337 | 3 | 1 | Windows 16 |
| sigma | medium | Whoami.EXE Execution Anomaly | 16 | 0.1 % | 0.337 | 3 | 1 | Windows 16 |
| sigma | medium | Change PowerShell Policies to an Insecure Level | 15 | 0.1 % | 0.316 | 3 | 2 | Windows 15 |
| sigma | medium | Execution of Suspicious File Type Extension | 9 | 0.1 % | 0.189 | 1 | 9 | Program Files 9 |
| sigma | medium | Potential Persistence Attempt Via Run Keys Using Reg.EXE | 8 | 0.1 % | 0.168 | 5 | 1 | Windows 8 |
| sigma | medium | Direct Autorun Keys Modification | 8 | 0.1 % | 0.168 | 5 | 1 | Windows 8 |
| sigma | medium | Potential Configuration And Service Reconnaissance Via Reg.EXE | 8 | 0.1 % | 0.168 | 5 | 1 | Windows 8 |
| sigma | medium | CurrentVersion Autorun Keys Modification | 8 | 0.1 % | 0.168 | 5 | 1 | Windows 8 |
| sigma | medium | Use of OpenConsole | 6 | 0.1 % | 0.126 | 3 | 2 | user folders 6 |
| sigma | low | Start Windows Service Via Net.EXE | 6 | 0.1 % | 0.126 | 2 | 2 | Windows 6 |
| sigma | low | Stop Windows Service Via Net.EXE | 6 | 0.1 % | 0.126 | 2 | 2 | Windows 6 |
| sigma | low | NodeJS Execution of JavaScript File | 6 | 0.1 % | 0.126 | 4 | 2 | Program Files 6 |
| analystlab | medium | Program connected out, wrote an executable, and it was started | 6 | 0.1 % | 0.126 | 4 | 2 | Windows 4, Program Files 2 |
| analystlab | low | A program created files and deleted them again | 6 | 0.1 % | 0.126 | 3 | 1 | Windows 6 |
| sigma | medium | Creation Of a Suspicious ADS File Outside a Browser Download | 5 | 0.0 % | 0.105 | 1 | 3 | Program Files 5 |
| sigma | low | Stop Windows Service Via Sc.EXE | 5 | 0.0 % | 0.105 | 1 | 1 | Windows 5 |
| sigma | medium | Suspicious Driver Install by pnputil.exe | 4 | 0.0 % | 0.084 | 2 | 1 | Windows 4 |
| analystlab | medium | A program's name hides a Windows program's name | 4 | 0.0 % | 0.084 | 2 | 4 | Program Files 4 |
| sigma | medium | Msiexec Quiet Installation | 3 | 0.0 % | 0.063 | 2 | 1 | Windows 3 |
| sigma | medium | Always Install Elevated Windows Installer | 3 | 0.0 % | 0.063 | 2 | 1 | Windows 3 |
| sigma | medium | Office Application Initiated Network Connection To Non-Local IP | 2 | 0.0 % | 0.042 | 1 | 1 | Program Files 2 |
| sigma | low | File Deletion Via Del | 2 | 0.0 % | 0.042 | 1 | 1 | Windows 2 |
| analystlab | low | A program that never listened here opened a listening port | 2 | 0.0 % | 0.042 | 1 | 2 | Program Files 2 |
| sigma | medium | Process Deletion of Its Own Executable | 1 | 0.0 % | 0.021 | 1 | 1 | Program Files 1 |
| sigma | medium | Rundll32 Internet Connection | 1 | 0.0 % | 0.021 | 1 | 1 | Windows 1 |
| sigma | high | Allow Service Access Using Security Descriptor Tampering Via Sc.EXE | 1 | 0.0 % | 0.021 | 1 | 1 | Windows 1 |
| sigma | medium | Service Security Descriptor Tampering Via Sc.EXE | 1 | 0.0 % | 0.021 | 1 | 1 | Windows 1 |

The 5 noisiest rules make **98.5 %** of all alerts; 33 rules fired at least once.

## Friends' laptops (statistics files: counts only)

No friends' statistics files under recordings/friends/.
