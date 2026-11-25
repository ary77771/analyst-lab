# v4 results (frozen at `freeze-v4` = 8c628bb, 2026-11-17)

*Technical summary, written 2026-11-20 during the overnight scoring. Every number here comes from a file
in this folder or from `recordings/` (private, aggregate numbers only). "Seen" = data v4 was allowed to
learn from; everything else is v4's real result.*

## 1. Atomic Red Team, sealed TEST half (pre-registration 3.1) — v4's result

Same 20 official boots (2026-11-14/15), scored with frozen v3 and frozen v4 by `tools/art_score.py`
(wt\art; v3 scored at harness commit 7f10caf, v4 at f42c7f0, which differ only by v3's two results pages); comparison per test by `analysis/compare_art_v3_v4.py`
([art-v3-vs-v4.md](art-v3-vs-v4.md)); v4's own pages: [phase 1](art-official-phase1.md),
[phase 2](art-official-phase2.md). v3's official ART files were verified unchanged (SHA-256 before/after).

| TEST half (unseen) | executed | Q1 v3 | Q1 v4 | Q2 v3 | Q2 v4 | gained / lost (Q1) | gained / lost (Q2) |
|---|---:|---:|---:|---:|---:|---:|---:|
| phase 1 (user) | 119 | 68 (57.1 %) | 82 (68.9 %) | 58 (48.7 %) | 60 (50.4 %) | +14 / 0 | +2 / 0 |
| phase 2 (admin) | 51 | 22 (43.1 %) | 25 (49.0 %) | 15 (29.4 %) | 15 (29.4 %) | +3 / 0 | 0 / 0 |
| **both** | **170** | **90 (52.9 %)** | **107 (62.9 %)** | **73 (42.9 %)** | **75 (44.1 %)** | **+17 / 0** | **+2 / 0** |

- **Pre-registered rule** (3.1, exactly: "Reported: Q1 and Q2 for v3 and v4, per phase, and the tests v4
  newly detects and newly misses. **Better** = v4's Q2 (without ART-citing Sigma rules) above v3's, and no
  more than 2 tests lost."). The "Better" sentence does not say at which level, so both are given: over both
  phases **met, by a margin of +2 of 170** (both in phase 1, both detected only through declared alerts),
  0 lost; per phase: met in phase 1, **not met in phase 2** (Q2 equal, 15 = 15).
- **Where the gain comes from:** all 17 Q1 gains are tests detected **only through declared alerts**
  (events read from a command line, i.e. F7/F8; the replay marks "read from a command line" but not which
  of the two; `tools/art_learn_replay.py --half test` agrees with art_score test by test: phase 1 82/60,
  phase 2 25/15). 15 of the 17 rest on Sigma rules that cite ART tests; only 2 survive Q2, so most of v4's
  gain on unseen tests comes from Sigma rules that cite ART (checked by an independent reviewer, 2026-11-20).
- **Seen half for comparison** (practice, not v4's result): Q1 84 -> 119, Q2 68 -> 78 of 192, 0 lost
  (identical to the pre-freeze practice replay).

## 2. Regression on earlier official runs (pre-registration 3.4)

Ran 2026-11-19/20 (exit 0 each): `experiments.py blind --of v3`, `detection/story/blind --of v2`,
`detection/story/blind/false-alerts --of v1`, then `tools/compare_v3_v4.py` -> [v3-vs-v4.md](v3-vs-v4.md):
**LOST 5, all S3** (DETECTED -> MISSED in its 5 official v1 runs). This is the loss F5 knowingly accepts
(a new listening port on loopback only is graded low; Yousif accepted the S3 loss on 2026-11-14, prereg
section 5), reported as LOST, not explained away. Nothing else lost. On data v4 learned from (seen, B10-B17): B16 MISSED -> DETECTED in 3 runs,
B11 FALSE ALARM -> CLEAN in 3; stories identical (facts 285/192/20/790, checker PASS counts equal), B3 NOT
CHECKED 5/5 as in v2/v3. v1's laptop week (a small increase in raised alerts): **5.87 -> 6.00 per active hour** (279 -> 285; +8 "CurrentVersion
Autorun Keys Modification" from F7's declared registry rows, -2 new-listener alerts).

## 3. Blind round 4 on the lived-in VM (pre-registration 3.2; docs/plans/round4-prereg.md)

Series `20261119-225440` (2026-11-20 01:54 -> 06:04 local), the pinned command re-run after the incident in
prereg section 7: **24 of 24 runs completed**, all 24 answer-sheet copies match the pinned SHA-256, all 24
pass the run filters (official / freeze-v4 / snapshot lived-in, no overlap), nothing re-run or dropped within
this series. Both versions scored the same way by `harness/round4.py score` (each checkout's own frozen
`check_alerts.py` and `check_graph_scenario.py`; the scorer refuses to run unless both code gates are clean);
v4's re-score agrees with every run's in-run verdict (24/24). Checker outputs are kept per run and version.
B18-B25 were written after the freeze by a fresh session that never saw v4's code: unseen for both versions.

| scenario (3 runs each) | kind | v3 strict | v4 strict | v4 incident (labelled, 3b) | story, v3 = v4 |
|---|---|---|---|---|---|
| B18 | malicious | MISSED 3 | **DETECTED 3** | DETECTED 3 | PASS 3 |
| B20 | malicious | MISSED 3 | **DETECTED 3** | DETECTED 3 | FAIL 3 |
| B24 | malicious | MISSED 3 | MISSED 3 | DETECTED 3 | FAIL 3 |
| B21 | malicious | NOT CHECKED 3 | NOT CHECKED 3 | (none) | FAIL 3 |
| B23 | malicious | NOT CHECKED 3 | NOT CHECKED 3 | (none) | FAIL 3 |
| B19 | innocent | CLEAN 3 | CLEAN 3 | CLEAN 3 | FAIL 3 |
| B22 | innocent | FALSE ALARM 3 | **CLEAN 3** | CLEAN 3 | FAIL 3 |
| B25 | innocent | CLEAN 3 | CLEAN 3 | CLEAN 3 | PASS 3 |

- **Totals (strict verdict, the ruler of v3's prereg):** malicious runs that could be checked (9): v3 detected
  **0**, v4 **6**; innocent runs (9): v3 **3 false alarms**, v4 **0**. v4's labelled incident column reaches
  9 of 9. v4 lost nothing: no scenario is worse under v4.
- **Read the counts as scenarios, not runs:** the 3 repeats of every scenario gave identical verdicts, so the
  evidence is 6 checkable scenarios, not 18 independent runs: v4 is better on 3 (B18, B20, B22), equal on 3,
  worse on 0.
- **Why v4 gained:** B18 and B20 via **F3 `create_send_wipe`** (a program creates files, sends them out and
  deletes them; learned from seen B16). v3 also had an alert on the right program but it cited none of those
  steps' own events. B22 (an innocent local preview server) via **F5**: its port is reachable only from the VM
  itself, so v4 grades `new_listener` low (v3: medium = a false alarm; the rule and level of the one alert in
  each of the 3 runs printed by `harness/alert_rules.py`, which runs the frozen checker unchanged). This is the same rule change that loses
  S3 in section 2: one innocent loopback server gained, one malicious loopback listener lost.
- **B24 is missed by both** (2 of 4 suspicious steps cited by v4); v4's incident column reaches all 4 steps
  by following what the alerted process did next, but that column is never the verdict.
- **NOT CHECKED (B21, B23, 6 runs, both versions): an answer-sheet problem, not a detection result.** Each sheet
  lists as one program role a Windows tool its own story starts several times (B21 `schtasks.exe` 3 times:
  create / run / delete; B23 the renamed curl twice). The frozen checkers (`check_scenario.anchor`, same in
  v3 and v4) anchor a scenario only when the first listed program starts exactly once and each later one has
  exactly one start whose parent is an already-anchored program, so they refuse to guess (correctly NOT
  CHECKED, never MISSED). The
  writer's dry-run checks the sheet's layout, not this. Pinned sheets are not edited after the runs, so these 6
  runs stay unscored.
- **Story (detection AND story, v4 prereg 3.2):** identical for v3 and v4 in all 24 runs (v4 changed
  detection only): PASS 6 (B18, B25), FAIL 18. The failures are the graph meeting new shapes, e.g. an
  unlisted hypothesis between scenario nodes (B20, B24), loopback polling with no `connected_to` facts (B22),
  extra files in the scenario folder (B19), a role started more than once (B21, B23; B21 also lacks its
  `tick.done` file node); cause by cause in [round4-story-failures.md](round4-story-failures.md) (mostly
  what the answer-sheet format cannot express; 2 engine limits, both graded honestly). Malicious runs that are both DETECTED and story PASS: v4 **3** (B18), v3 **0**
  (innocent B25 is CLEAN and PASS in both, not counted here).
- **Noise boots (S0, nothing runs, prereg section 6):** raised alerts in the window, v3 / v4: lived-in
  **0 / 0** and **0 / 0**; clean **3 / 2** and **2 / 2** (`new_shell_parent` twice per clean boot in both
  versions; v3's extra is `new_listener`). The harness first read non-zero counts as "unparsed" (a regex bug,
  fixed and tested; prereg section 8); it now stores each boot's snapshot and both checkers' full output.

Independent check (fresh reviewer, 2026-11-20 morning): every number in section 3 recomputed from the raw
files: ACCURATE WITH FIXES (traceability of the noise boots and of B22's rule, anchoring wording, the
detection-and-story count; applied). Not verifiable from stored files: that the round-4 writer never saw v4's
code (a process fact: a fresh session with no access to branch v4).

## 4. Laptop false-alarm brake (pre-registration 3.3 and 3c)

From 2026-11-22 (runbook: docs/plans/v4/runbook-11-22.md).

Independent check (fresh reviewer, 2026-11-20 night): every number in sections 1-2 recomputed from the raw files: ACCURATE WITH FIXES (dates, labels and wording; applied). The v1-week rescoring ran at commit 3dcf745 (= freeze-v4 + docs/harness/tests only).
