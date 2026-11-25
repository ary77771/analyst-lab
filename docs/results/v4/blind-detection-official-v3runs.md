# Version 4 evaluation: J1 detection rate and time to detect (official, v3's official runs re-scored with v4's code)

*Made 2026-11-19T20:41:14+00:00 by `tools/experiments.py` (v4 code) on TEST data: 24 official run(s) replayed and scored with every detector (tools/check_alerts.py per run). Pre-registered in `docs/plans/v4-prereg.md`. Aggregate numbers, rule ids, bands and the lab's own scenario program names only (privacy rule 7). Nothing was tuned on these numbers.*

Definitions (pre-registered): a run is DETECTED when every alert its answer sheet lists under `alert_expected.check` (rule id, level, involved program) was raised on an instant replay of the run's window; time to detect = the first such alert's time (`Alert.time`: when the rule's condition became true, on the recorded clock) minus the scenario's first program's recorded start (its event 1); other alerts = alerts at or above the frozen floor in the run window that name none of the scenario's programs (false alarms during a run). Runs whose scenario check failed are listed and not scored.

| scenario | runs scored | judged | detected | none expected | not checked | rate (95 % CP) | time to detect s: min / median / max (n anchored of detected) | other alerts per run |
|---|---|---|---|---|---|---|---|---|
| B10 | 3 | 3 | 3 | 0 | 0 | 100 % (3/3; 95 % [29, 100] %) | 10.1 / 14.0 / 43.6 (9 of 9) | 0.00 |
| B11 | 3 | 0 | 0 | 0 | 0 | - | - / - / - (0 of 0) | 0.00 |
| B12 | 3 | 3 | 3 | 0 | 0 | 100 % (3/3; 95 % [29, 100] %) | 4.1 / 13.6 / 27.4 (9 of 9) | 0.00 |
| B13 | 3 | 3 | 3 | 0 | 0 | 100 % (3/3; 95 % [29, 100] %) | 10.1 / 13.4 / 15.5 (6 of 6) | 0.00 |
| B14 | 3 | 3 | 0 | 0 | 0 | 0 % (0/3; 95 % [0, 71] %) | - / - / - (0 of 0) | 0.00 |
| B15 | 3 | 3 | 0 | 0 | 0 | 0 % (0/3; 95 % [0, 71] %) | - / - / - (0 of 0) | 0.00 |
| B16 | 3 | 3 | 3 | 0 | 0 | 100 % (3/3; 95 % [29, 100] %) | 40.2 / 40.2 / 43.8 (12 of 12) | 0.00 |
| B17 | 3 | 3 | 0 | 0 | 0 | 0 % (0/3; 95 % [0, 71] %) | - / - / - (0 of 0) | 0.00 |

Pooled detection rate over every judged run: 57 % (12/21; 95 % [34, 78] %). Other alerts (>= frozen floor, not involving the scenario) over all runs: 0.

## Blind round 2: suspicious steps (v2 pre-registration)

A step is FLAGGED when a raised alert (>= the frozen floor) cites at least one of the records the scenario checker matches to that step's evidence. A run is DETECTED when every suspicious step its sheet names is flagged; an innocent sheet (no suspicious step) is CLEAN when no raised alert flags a step or names a scenario program, else FALSE ALARM. 'Program only' = an alert names the step's program but cites none of its events (secondary, not counted as flagged).

| scenario | suspicious steps (all runs) | flagged (95 % CP) | program only | not recorded | alerts on other steps | innocent runs: clean / false alarm |
|---|---|---|---|---|---|---|
| B10 | 9 | 100 % (9/9; 95 % [66, 100] %) | 0 | 0 | 0 | - |
| B11 | 0 | - | 0 | 0 | 0 | 3 / 0 |
| B12 | 9 | 100 % (9/9; 95 % [66, 100] %) | 0 | 0 | 0 | - |
| B13 | 6 | 100 % (6/6; 95 % [54, 100] %) | 0 | 0 | 0 | - |
| B14 | 9 | 33 % (3/9; 95 % [7, 70] %) | 6 | 0 | 0 | - |
| B15 | 15 | 40 % (6/15; 95 % [16, 68] %) | 6 | 0 | 0 | - |
| B16 | 12 | 100 % (12/12; 95 % [74, 100] %) | 0 | 0 | 0 | - |
| B17 | 12 | 50 % (6/12; 95 % [21, 79] %) | 0 | 0 | 0 | - |

## Incident level (v4 F1, v4-prereg 3b): a second column, never the verdict

A suspicious step also counts here when it lies in a raised alert's FOLLOW-THROUGH (the later recorded actions of the process the alert is about and of its descendants, 10 minutes, hubs not followed). 'Flagged by a rule' above stays the comparison with earlier versions. Symmetric: an innocent run is clean here only when no raised alert's evidence or follow-through reaches it. The price of following: steps NOT marked suspicious that follow-through alone also holds.

| scenario | runs | incident: detected / missed | innocent: clean / false alarm | suspicious steps reached (by follow-through only) | innocent steps reached by following | alerts rooted outside the scenario |
|---|---|---|---|---|---|---|
| B10 | 3 | 3 / 0 | 0 / 0 | 9 (0) | 12 | 0 |
| B11 | 3 | 0 / 0 | 3 / 0 | 0 (0) | 0 | 0 |
| B12 | 3 | 3 / 0 | 0 / 0 | 9 (0) | 9 | 0 |
| B13 | 3 | 3 / 0 | 0 / 0 | 6 (0) | 3 | 0 |
| B14 | 3 | 3 / 0 | 0 / 0 | 9 (6) | 3 | 0 |
| B15 | 3 | 0 / 3 | 0 / 0 | 12 (6) | 3 | 0 |
| B16 | 3 | 3 / 0 | 0 / 0 | 12 (0) | 3 | 0 |
| B17 | 3 | 3 / 0 | 0 / 0 | 12 (6) | 6 | 0 |

## Per run

| scenario | run | records | verdict | expected | found | time to detect (s) | other alerts (rule[level]: n) |
|---|---|---|---|---|---|---|---|
| B16 | 20261114-112402-95c1 | 413 | DETECTED | 4 | 4 | step 3[-] 40.2, step 4[-] 40.2, step 5[-] 40.2, step 6[-] 40.2 | - |
| B15 | 20261114-113011-ee67 | 465 | MISSED (missed: step 2[-], step 4[-], step 6[-]) | 5 | 2 | step 3[-] 98.0, step 5[-] 98.6 | - |
| B10 | 20261114-113835-5a06 | 366 | DETECTED | 3 | 3 | step 4[-] 10.1, step 5[-] 11.8, step 6[-] 29.9 | - |
| B17 | 20261114-114425-0233 | 354 | MISSED (missed: step 6[-], step 7[-]) | 4 | 2 | step 4[-] 6.0, step 5[-] 6.1 | - |
| B13 | 20261114-115120-9e6f | 394 | DETECTED | 2 | 2 | step 4[-] 10.1, step 5[-] 10.2 | - |
| B11 | 20261114-115709-2672 | 416 | CLEAN | 0 | 0 | - | - |
| B11 | 20261114-120622-42ec | 337 | CLEAN | 0 | 0 | - | - |
| B14 | 20261114-121259-07a4 | 356 | MISSED (missed: step 3[-], step 4[-]) | 3 | 1 | step 2[-] 1.8 | - |
| B10 | 20261114-121834-1045 | 425 | DETECTED | 3 | 3 | step 4[-] 10.1, step 5[-] 11.8, step 6[-] 30.1 | - |
| B12 | 20261114-122422-112e | 410 | DETECTED | 3 | 3 | step 4[-] 4.1, step 5[-] 7.1, step 6[-] 7.9 | - |
| B17 | 20261114-123032-68ba | 202 | MISSED (missed: step 6[-], step 7[-]) | 4 | 2 | step 4[-] 10.1, step 5[-] 10.4 | - |
| B14 | 20261114-123855-2f43 | 148 | MISSED (missed: step 3[-], step 4[-]) | 3 | 1 | step 2[-] 3.5 | - |
| B17 | 20261114-124607-9545 | 182 | MISSED (missed: step 6[-], step 7[-]) | 4 | 2 | step 4[-] 9.1, step 5[-] 9.5 | - |
| B16 | 20261114-125430-e3b4 | 94 | DETECTED | 4 | 4 | step 3[-] 40.2, step 4[-] 40.2, step 5[-] 40.2, step 6[-] 40.2 | - |
| B12 | 20261114-130202-1433 | 135 | DETECTED | 3 | 3 | step 4[-] 13.6, step 5[-] 19.7, step 6[-] 27.3 | - |
| B11 | 20261114-131317-d79d | 188 | CLEAN | 0 | 0 | - | - |
| B10 | 20261114-132243-5bfe | 147 | DETECTED | 3 | 3 | step 4[-] 14.0, step 5[-] 17.2, step 6[-] 43.6 | - |
| B15 | 20261114-133306-513e | 237 | MISSED (missed: step 2[-], step 4[-], step 6[-]) | 5 | 2 | step 3[-] 106.8, step 5[-] 110.4 | - |
| B13 | 20261114-134411-33f9 | 127 | DETECTED | 2 | 2 | step 4[-] 15.3, step 5[-] 15.5 | - |
| B14 | 20261114-135727-d6c5 | 167 | MISSED (missed: step 3[-], step 4[-]) | 3 | 1 | step 2[-] 3.7 | - |
| B16 | 20261114-140921-664b | 109 | DETECTED | 4 | 4 | step 3[-] 43.8, step 4[-] 43.8, step 5[-] 43.8, step 6[-] 43.8 | - |
| B12 | 20261114-142109-d257 | 256 | DETECTED | 3 | 3 | step 4[-] 13.5, step 5[-] 24.4, step 6[-] 27.4 | - |
| B13 | 20261114-143122-6bc9 | 107 | DETECTED | 2 | 2 | step 4[-] 13.3, step 5[-] 13.6 | - |
| B15 | 20261114-144208-68e9 | 196 | MISSED (missed: step 2[-], step 4[-], step 6[-]) | 5 | 2 | step 3[-] 87.7, step 5[-] 88.6 | - |
