# v4: pre-registration (FINAL at `freeze-v4`, 2026-11-17; sections 1–4 binding from 2026-11-14)

*Branch `v4` (from `v3` at 875ea75), worktree `wt\v4`. Started 2026-11-14 ~17:00 UTC, while the
official v3 ART series was running and before ANY official ART boot was scored. v4 = v3's
detectors, improved by learning from v3's misses. Sections 1–4 are fixed now. Sections 5–6 are
filled in before the freeze (tag `freeze-v4`), and the freeze commit pins this file.*

## 0. Why v4

v3's official results (2026-11-14) missed blind scenarios B14–B17 (3/3 runs each) and raised a
false alarm on B11 (3/3). The goal is to catch more. The rule that makes "catches more" mean
something: **v4 is judged only on data it never learned from** (sections 2–3).

## 1. What v4 may learn from (and what it must not see)

- **May:** v3's results on blind rounds 1–3 (B1–B17; their answer sheets are opened only with
  Yousif's OK and then count as seen); the LEARN half of the ART tests (section 2): its v3
  per-test results and its recordings; the v1/v2 own scenarios; the public recordings (N1);
  laptop data recorded **up to 2026-11-14** (already seen by v1–v3 work).
- **Must not:** the ART TEST half's per-test results or recordings (section 2's seal); laptop
  data from **2026-11-15 on** (v3's test week, 11-15..11-21: it is also v4's false-alarm test,
  section 3); blind round 4 (not written yet; its writers never see v4's code or this branch's
  plans). **v4 is frozen before v3's laptop week is scored** (11-22), because v3's per-rule false
  alarms on that week would show which rules are noisy on v4's own test data.
- **Recorder unchanged until 11-22:** v4 changes detection only (`engine/`, `rules/`, `config/`,
  `tools/`), never `agent/` or the Sysmon configuration, until v3's laptop week is collected
  (v3-prereg: the recorder is part of v3's frozen code). A v4 recorder change, if any, comes
  after 11-22, and then old recordings cannot be re-scored for what it adds.
- **Behaviour, not names.** A rule that only matches one scenario's program, file or folder
  name is not allowed (B5's lesson). Every new or changed rule says which behaviour it detects and
  is checked against the public recordings and the learn half, never only the scenario it came
  from.

## 2. The ART split and the seal

- `tools/art_split.py --seed 1095103166` (seed drawn with Python's `secrets` before any ART
  scoring) → `docs/plans/v4/art-split.json` (SHA-256
  `0f395a70b1e52a740347cbce8936878514d081448c4188c3a9c2312f433d7fee`). Unit: **parent technique**.
  The spike's techniques (T1036, T1082, T1105; seen) are always LEARN; the rest are shuffled and
  dealt to the smaller half. Result: LEARN 24 parent techniques / 197 tests (phase 1: 97,
  phase 2: 100); TEST 46 / 175 (phase 1: 124, phase 2: 51). Input lists pinned by SHA-256
  (art-prereg sections 7 and 9).
- **The seal, until `freeze-v4` exists:** nobody opens the official v3 ART output tables
  (`docs/results/art/official-phase*.md`, `recordings/experiments/art/official/art-phase*.json`). The
  official scoring's console output goes to a file that is not read either. v4 work reads them
  only through a view tool (to be written, `tools/art_view.py`): **per-test rows for LEARN
  tests; for TEST tests only the totals** (executed / detected / Q2 / Q4, no technique names). The
  totals are fine to report; they do not say which technique to fix.
- After the freeze the full tables are opened and reported as v3's result.

## 3. How v4 is judged (pass criteria)

All on data v4 never learned from, scored with frozen v4 (`ANALYSTLAB_OFFICIAL=1`, tag
`freeze-v4`), next to frozen v3 on the SAME data:

1. **ART TEST half:** the same official recordings, re-scored by v4 with `art_score.py` rules
   (attribution and verdicts as art-prereg section 4; Q4's control rules recomputed for v4, so a
   rule that fires on the harness controls never counts). Reported: Q1 and Q2 for v3 and v4, per
   phase, and the tests v4 newly detects and newly misses. **Better** = v4's Q2 (without
   ART-citing Sigma rules) above v3's, and no more than 2 tests lost.
2. **Blind round 4** (new scenarios, fresh writers, the `lived-in` VM, docs/plans/lived-in-vm.md):
   v3 and v4 both score the same runs (detection and story).
3. **False alarms (the brake):** v4 on v3's laptop week 2026-11-15..11-21 (`test-laptop-v3.db`,
   unseen by v4 per section 1), with `v3_budget.py`'s pass/fail budgets: v4 must stay within
   them. A v4 that detects more by alerting on everything fails here.
4. **Regression:** v3's official runs (rounds 1–3, own scenarios) re-scored by v4; every LOST item
   is reported (as compare_v2_v3).

### 3b. Addendum 2026-11-15 (before round 4 exists): the incident column

The criteria above are unchanged: the **verdict** of a blind run stays the strict one (every
suspicious step cited in the EVIDENCE of a raised alert), the same ruler as v3, and the ART scoring
reads alert evidence only. v4 additionally reports, per blind run, a second, labelled column:

- **Incident level** = every suspicious step is cited by a raised alert's evidence **or lies in a
  raised alert's follow-through** (F1, `engine/follow.py`: the later recorded actions of the process
  the alert is about and of its descendants, for `follow_through.window` = 600 s, at most 200 events,
  hubs never followed, alerts below the floor never followed). The same "shared with an innocent step"
  exclusion applies. **Symmetric:** an innocent scenario is CLEAN at incident level only when no
  raised alert's evidence or follow-through reaches its processes; and for every run the number of
  steps NOT marked suspicious that an incident also holds is reported (the price of following).
- It is **never** summed with the strict column and never called "detected by a rule". Wording in
  the report: "flagged by a rule" vs "inside an alerted incident" (the split MITRE's ATT&CK
  Evaluations make between rule detections and telemetry tied to an alert). v3 has no such column
  (v3 keeps no follow-through), so the v3-v4 comparison is the strict column only.

### 3c. Addendum 2026-11-17 (before the freeze, before any 11-15+ laptop data is read): the declared-alert brake

The brake in 3.3 used to measure only v3's two new rules and the short check-in test. Nothing measured
v4's **declared** alerts (F7 + F8: an event read from a command line, `details.derived_from =
"command_line"`), so a declared feature that alerted on everything would have passed the brake. Added:

- **Count:** v4's RAISED alerts (>= the frozen floor, `score.raised`) with `derived_from =
  "command_line"`, from every detector run over `test-laptop-v3.db` by `engine.score` (the same
  scoring the false-alarm week uses), F7 and F8 **together**. Every raised alert counts, the same
  way v3's two rules are counted: no de-duplication by program or command line beyond the engine's
  own (one alert per process start per rule, however many declared rows of that start match; two
  rules on one start = two alerts).
- **Budget:** at most **0.1 per awake hour** (awake hours as `tools/v3_budget.py` (a) and v3
  pre-registration 1.8: `engine/beacon.host_segments` over every host in the snapshot).
  This is the budget v3 gave EACH of its new rules (v3 pre-registration 1.8), applied here to F7 and
  F8 combined, so it is stricter than one budget per feature. Not chosen from data: on seen data F7
  gave 0.63/day on old recordings without registry recording and 0 with it, F8 gave 0, both far below
  any budget considered (the best one was picked; this is the one that reuses an
  already pre-registered number instead of inventing a new one).
- **Outcome:** above the budget = **FAIL** of the brake (3.3), reported with the F7 / F8 split,
  never re-tuned. Computed by `tools/v3_budget.py` from wt\v4 (section "declared"), which refuses
  to run if the declared features are on and the alerts were not scored, if any detector reported
  an error while scoring (including one unreadable command line), or if a declared alert is of an
  unknown kind. Reviewed by a fresh subagent 2026-11-17: PASS WITH FIXES, applied.

## 4. Reporting

v3's results stay as they are (`docs/results/v3/`, `docs/results/art/official-*`). v4's go to
`docs/results/v4/`. Learn-half and B10–B17 improvements are reported as **"on data v4 learned
from (seen)"**, never as v4's result.

## 5. What changed in v4 (filled in before the freeze)

*(the list of rule and engine changes, each with its behaviour and where it was checked)*

- **F4 `analystlab.ping_delay_chained`** (new, own Sigma rule, `rules/analystlab/`, medium):
  ping.exe to a loopback address with a count (`-n`), started by cmd.exe whose command line chains
  more commands with `&`: a "wait, then do something" one-liner (ATT&CK T1497.003). Learned from
  B17 (seen). Checks: unit test (2 hits, 4 near misses incl. a batch-file sleep; fails with the `&`
  condition removed); laptop learn period (29 days up to 11-14): 0 matches (1 ping start in all);
  VM recordings up to 11-14: 3 matches = B17's 3 runs, B17 step 5 now flagged 3/3 (B17 stays
  MISSED: steps 6–7 need F1). Full suite 1093 passed. Independent review (fresh subagent, 2026-11-14):
  PASS WITH FIXES → applied: a quoted address (`"127.`, `"localhost`) and `||` chains now match;
  known limits named in the rule (the `-w` unreachable-address timer, numeric loopback forms, a
  renamed ping.exe). Two more unit hits (count after the address + `||`; quoted address), each fails
  when its condition is removed. Counts unchanged (laptop 0, VM 3 = B17).
- **F5 `analystlab.new_listener`: loopback-only ports drop to low** (changed, `engine/own_rules.py`,
  `config/frozen.yaml` `loopback_level: low`). Behaviour: a program that never listened here opens a
  port; if the address is loopback (127.x, ::1) only this machine can reach it, so it cannot be a door
  for outsiders: the alert is kept and shown but no longer raised (below the medium floor). Every other
  address keeps medium. Learned from B11 (seen, innocent: a docs previewer on 127.0.0.1). **Known,
  accepted cost (Yousif 2026-11-14): own scenario S3 ("unexpected listener", 127.0.0.1 only) becomes
  LOST in regression.** S3 and B11 do the same thing at the moment the rule fires; a rule that kept
  S3 and cleared B11 would have to use details of those two scenarios (B5's lesson), so it was not
  written. S3's answer sheet is NOT edited; the loss is reported. Checks: unit test (loopback 127.x/::1
  low; 0.0.0.0, ::, a network address medium; fails when the split is removed); B11 3 runs:
  FALSE ALARM → CLEAN 3/3; S3 3 newest runs: MISSED (as expected); in v3's official results no other
  scenario's detection cites new_listener. Laptop learn period, simulated (learn ≤ 11-07, test week
  11-08..11-14): 9 programs listened for the first time, 2 loopback only, 6 network only, 1 both.
  Full suite 1094 passed. Independent review: PASS (is_loopback right for IPv4-mapped and odd forms; a
  missing or garbage address stays medium, the safe side; config reaches the rule; nothing else
  assumes new_listener is always medium). Alert text softened: "reachable only from this machine
  unless something forwards it".
- **F3 `analystlab.create_send_wipe`** (new, own Python rule, LEARNED-NORMAL like new_listener;
  `engine/own_rules.py` `wipe_episodes` + `create_send_wipe`; config `min_files: 3, window: 900,
  level: medium, level_without_connection: low, max_connections: 20`). Behaviour: within one
  15-minute episode a process creates ≥ 3 different files that it (or a program it started
  directly, e.g. `cmd /c del`) deletes again; **medium** if it (or such a child) connected out to an
  ordinary destination inside the episode (stage, send, wipe: T1074, T1041, T1070.004), **low**
  otherwise; and only for programs that never did this on the machine during its learning period
  (baseline "wipers", its own file, `python -m engine.baseline --wipers`; the existing laptop/VM
  baseline files are unchanged). Evidence = the episode's creations and deletions plus up to 20
  connections inside it. No published rule covers this sequence (closest: Elastic's EQL "Process
  Termination followed by Deletion", deprecated), so it is our own glue. Learned from B16 (seen).
  **How it got here (reported, not hidden):** the first version (no episode bound, no learning) was
  reviewed (PASS WITH FIXES: a reused file name delayed the alert and lost evidence; files days apart
  formed one "set"; a huge process family overflowed SQLite's variable limit; zero GUIDs counted) and
  fixed; then on the laptop's 29 learn days (10-16..11-14) it raised **65 medium alerts** (~2/day),
  all ordinary programs updating themselves (updaters, overlays, WebView, svchost…). Simulated
  learned-normal (learn ≤ 11-07, test 11-08..11-14): test-week medium alerts 6 → 0 (every program
  had been seen during learning). So the rule was made learned-normal.
  **Known limits:** learned by program NAME (code inside a program that normally does this, e.g. an
  updater or svchost.exe, is not flagged; as the other learned rules); Sysmon records file
  creations/deletions only for executables/scripts and in Downloads, Startup and `\AnalystLab\`
  (B16 staged inside `\AnalystLab\`, so it is visible; documents staged in `%TEMP%` would not be;
  the recorder may not change before 11-22); a deletion by a grandchild or by the parent, a rename
  instead of a delete, an upload by an unrelated program are not seen.
  Second review (learned version): PASS WITH FIXES → applied: shells and script hosts (baseline.SHELLS)
  and unknown programs ("?", `<unknown process>`) are never learned and never silenced (the laptop's
  learn period HAD powershell.exe doing this: learning it would have blinded the rule to the likeliest
  attacker tool); the learning store is streamed, not sorted in memory; the session lookup is per
  host. Also a stated limit: a program learned from an episode without a connection stays silent when
  it later connects out (as new_listener: learned by name, any address).
  Learned files (own files; `laptop.json`/`vm.json` unchanged): `laptop-wipers.json` 42 programs from
  the laptop 10-16..11-14 (`tools/build_learn_store.py --to 2026-11-14`, `--until 2026-11-15`);
  `vm-wipers.json` 0 programs from the same 3 S0 boots as vm.json. Pinned in config/frozen.yaml.
  Checks: 28 F3 unit tests + 4 learning/store tests (medium with all evidence; low variants; near
  misses incl. parent-deletes-child, grandchild, other host, zero GUID; child deleter/uploader; files
  days apart; reused names; chunked big families; learned program silent, unknown/shell never silent,
  no baseline = nothing; learn_wipers host/session/until filters). Each protection fails its test when
  removed (child link, "in between", episode bound, episode extension, zero GUID, learned filter,
  never-silence list). **Held-out laptop week** with the real code (learn_wipers until 11-08, rule on
  11-08..11-14, all inside v4's learn period): **0 medium** (10 low, not raised); without learning it
  was 6 medium. Blind runs B1–B17 re-scored with v4: every verdict as v3's except B11 (F5) and
  **B16 MISSED → DETECTED 3/3**; F3 cites only B16 and B5 (already DETECTED). Full suite 1125 passed.
- **F6 Sigma filter `windows_midi_default_drivers`** (new, `rules/filters/`, applied by
  `engine/detect.py` to SigmaHQ cbf93e5d and 480421f9, which stay untouched). Behaviour filtered:
  System32's svchost.exe writing Windows' own required MIDI defaults, exactly `Drivers32\midi =
  wdmaud.drv` and `Drivers32\midi1 = wdmaud2.drv` (Microsoft:
  https://microsoft.github.io/MIDI/kb/required-registry-entries); SigmaHQ master (rules modified
  2025-10-22) has no such filter. Any other Drivers32 value, data or writer still alerts. Learned from
  VM noise in blind round 3 + the ART spike (11-14 before 15:00 UTC, no official ART boot). Checks:
  VM 11-14: 140 alerts → 0; laptop learn period: 4 default writes filtered, 3 other Drivers32 writes
  still alert; unit tests (defaults quiet; 6 near misses incl. swapped values, `midi2`, a non-System32
  svchost, empty Details alert; without the filter the defaults fire; widening the filter to "any
  midi write by svchost" fails the test); a filter naming a rule the full SigmaHQ load lacks is a
  load failure (0 on the pinned set); a broken filter file stops the load with its name. Independent
  review: PASS WITH FIXES (applied).
- **F1 follow-through** (new, `engine/follow.py`, config `follow_through: {window: 600, max_events:
  200}`; definitions in section 3b). A derived view of what a raised alert's subject process and its
  descendants did next; **never evidence, never new alerts**: alert ids, the ART scoring and the
  strict blind verdict are untouched (tested: the strict result is identical with and without it).
  Shown as the incident column of `tools/check_alerts.py` and `tools/experiments.py`. Learned from
  B14/B15/B17 (seen). Limits: brokered starts (scheduled task, WMI, service) are not followed; alerts
  whose evidence is only agent records or our own tools' rows have no subject; without a hub list the
  column is not computed. On seen data (round 3 + B4, 27 runs): strict verdicts all unchanged;
  incident level B14 MISSED → DETECTED 3/3, B17 MISSED → DETECTED 3/3, B15 4 of 5 steps (the beacon
  step needs F2), B11 CLEAN at both levels, 0 alerts rooted outside a scenario; innocent steps reached
  by following: 1–4 per run (reported, the price). Laptop week ≤ 10-29: 279 raised alerts, 251 with a
  follow-through, median 7 events, 55 at the 200 cap, ~1 min. 16 follow tests + 5 checker tests; each
  protection (trigger time, floor, hub subject, hub descendant) fails a test when removed.
  Independent review: PASS WITH FIXES (applied: a follow-through failure never costs the strict
  verdict; GUID spelling; rooted-outside count; the price counts following only; experiments column).
- **F7 declared registry writes** (new, `engine/regcmd.py` + a second pass in `engine/detect.py`,
  config `declared_registry: {reg_command: true}`). *Written 2026-11-16 BEFORE the learn-half replay
  with F7 (design and rules of the game first, numbers after).* Learned from the learn half (study
  `docs/plans/v4/learn-half-study.md`: 43 missed tests are `reg.exe add`, and no missed test has a
  registry event, because Sysmon config v0.3 records registry events only for autostart places).
  **What it does:** a reg.exe process start whose command line is a well-formed local `reg add` /
  `reg delete` of one key or value is translated into the registry event it declares, in Sysmon's
  spelling, and offered to the SIMPLE registry rules (SigmaHQ's ~250 and any of ours) in a second
  pass. The translator is reg.exe's syntax + Sysmon's naming only: **no list of keys, values or
  rules, nothing taken from ART** (a test enforces that the module names none). No SigmaHQ rule is
  switched on or off for it; Sigma filters stay the only tool against false alarms.
  **Honesty of the alert:** it cites the reg.exe start (a recorded fact), its reason says "declared,
  not recorded: it may have failed", `details.derived_from = "command_line"`; a declared row is
  never stored and never a graph fact. A reg.exe process with a recorded registry event is left to
  that event (no double alert). Correlation rules never see declared rows.
  **Ground truth, not memory:** reg.exe's behaviour from `reg add /?` and probes on a scratch key
  (Windows 11 26200); Sysmon's field shapes from the 49 registry event samples SigmaHQ ships
  (`regression_data`); oracle test: for each of the 31 sampled real reg.exe events, the equivalent
  command line fires the SAME rule as the real event.
  **Limits (stated):** only reg.exe's own start counts (not PowerShell cmdlets, `reg import`,
  regedit, API writes); the user's SID is unknown (`HKU\<SID>\…`); HKCR is read as machine classes;
  where Sysmon's spelling is ambiguous both candidates are offered (machine classes, 32-bit view);
  the command may have failed (ART phase 1 runs as a normal user: an HKLM write is then an ATTEMPT);
  live mode may raise the declared alert before a real event arrives (batch scoring is exact).
  **How it is judged before the freeze (seen data only):** learn-half replay (gain at Q1 and Q2
  separately, none of v3's 84 lost); laptop false alarms on data ≤ 2026-11-14; blind runs B1–B17
  re-scored; tests + sabotage; independent review. Results are added below when measured.
  **Results (2026-11-16, all on SEEN data; never v4's result):**
  - *Learn half* (192 executed tests, practice replay of the learn windows only): Q1 84 → **105**,
    Q2 68 → **76**; **no test lost** at either level. All 21 new detections come only through
    declared alerts (24 SigmaHQ registry rules; 13 of the 21 from rules that cite ART, hence the
    smaller Q2 gain). Phase 1 (normal user): Q1 34 → 39, Q2 27 → 27; phase 2: Q1 50 → 66, Q2 41 → 49.
    22 reg.exe tests stay missed (17 `reg add` on keys no community rule covers; 5 `reg query`).
    Same numbers before and after the review fixes. At the official scoring the count "detected
    only through declared alerts" is reported next to Q1/Q2.
  - *Laptop ≤ 2026-11-14* (aggregates): 30 days, 4,745 reg.exe starts, 1,073 declare a write: 19
    declared alerts (0.63 per day), all ONE rule (SigmaHQ "CurrentVersion Autorun Keys
    Modification", medium), in a store without registry events. On the 4 days stored with registry
    events (11-09..11-12, config v0.3): 85 declaring starts, 0 declared alerts. v1's test week
    (10-23..10-29): 8, the same rule. The brake (section 3.3) decides on the unseen week.
  - *VM seen data* (every event before 2026-11-14T15:33Z: blind runs, own scenarios, S0 boots): 9
    reg.exe starts, 0 declared rows, 0 alerts. The 51 blind runs B1–B17 re-scored with F7 on and
    off: strict and incident lines identical in all 51.
  - *Tests:* 161 translator cases + 63 engine cases (incl. the 31-sample round trip) + 1 report
    case; full suite 1386 passed. *Sabotage:* 58 single-line breaks of `regcmd.py` / the declared
    pass, 57 caught by a failing test; the survivor is a second safety net behind a first one (a
    digit cap in front of a caught conversion error).
  - *Independent review* (fresh subagent, ~160 probes of the real reg.exe on a scratch key, 42
    mutations): **PASS WITH FIXES, all applied**: (1) a 5,000-digit `/d` raised inside the
    translator and switched the whole declared pass off: numbers are now capped, and one unreadable
    command line is skipped and reported once; (2) writes reg.exe performs that the first version
    missed: padded key / value name / type, REG_DWORD_LITTLE_ENDIAN / BIG_ENDIAN, REG_QWORD without
    /d or with a minus, Unicode digits, spaces in binary data; (3) events declared for commands
    reg.exe refuses: `/s` without REG_MULTI_SZ, a key ending in two backslashes, `+0x…`, `-`
    switches on `reg delete`, a program name glued to `add`, a key part over 255 characters; (4)
    "declared" is now the engine's knowledge, not a field of the row (a recorded event carrying a
    field of that name was mislabelled); (5) declared columns typed like the store's; (6) a fresh
    connection with `after_id` no longer re-reads the store (live loop); (7) the real `logs` view is
    restored in a `finally`; RuleName is not copied; only a VISIBLE recorded registry event shadows;
    a failing rule is reported once; (8) the investigation report says "declared … may have failed"
    in its summary and limitations.
  - *Three more checks (advisor, 2026-11-16):* (a) translator coverage on REAL command lines: of
    the reg.exe starts whose verb is add or delete, the translator refuses **0** in the learn
    windows (91 of 91) and **0** on the laptop ≤ 11-14 (1,073 of 1,073); (b) the 17 learn tests
    with a declaring `reg add` that stay missed: no registry rule matches at ANY level (not a floor
    effect), and the one value name a pinned rule also uses sits under a different key (a correct
    silence), so the remaining gap is rule coverage, not spelling; (c) the laptop's 19 declared
    alerts are all the user's `…\CurrentVersion\Run` key, which recorder config v0.3 includes
    (`\CurrentVersion\Run`): 17 fall before 2026-11-08 (no registry recording yet), 2 on
    11-13/11-14 in a store that holds no registry events; with the real event recorded, the
    declared row is dropped and the same SigmaHQ rule fires on the real event as it does for v3,
    so F7's expected net addition on the laptop is 0 (the unseen week decides). The harness
    controls (T0000: a cmd echo and a PowerShell output) start no reg.exe, so no declared alert
    can become a control rule.
  - *Reading the numbers:* the Q2 gain on the learn half is all in phase 2 (administrator, +8);
    phase 1 (normal user) gains 0 at Q2. The sealed half is mostly phase 1 (119 executed tests
    against 51), so F7 alone predicts only a thin Q2 gain there. A prediction from the practice
    half, not a result.
  - *Corrections to the text above (review):* SigmaHQ's samples are 49 files holding 55 events; they
    ground HKLM / HKU\<SID> / `_Classes` / `(Default)` and the DWORD / text shapes, **not** machine
    classes, ControlSet00x, WOW6432Node, HKCC, QWORD or `Binary Data` for the rarer types (those
    follow Sysmon's documentation and SigmaHQ's rule spellings: less certain, said so in
    `engine/regcmd.py`). The 31-sample test is a round trip (the samples hold no command line; the
    test builds it), not captured ground truth. The "names no key" test is now a whitelist of every
    path-like text constant in the module, not a word blacklist. More limits: `reg add KEY /v …`
    on a new key also creates the key (only the value is declared); a bare `reg add KEY` declares
    CreateKey although the key may exist; Sysmon's own spelling could not be observed for the less
    certain mappings (no registry recording outside autostart places, which is the reason F7 exists).
- **F8 declared PowerShell code** (new, `engine/pscmd.py` + the F7 declared pass in `engine/detect.py`,
  config `declared_script: {powershell_command: true}`). *Written 2026-11-16 ~23:45 local BEFORE the
  learn-half replay with F8.* Learned from the learn half (study: after F7, 42 of the 87 missed tests
  run ONLY inline PowerShell, `powershell.exe & {…}`; our recorder reads Sysmon, not PowerShell's own
  log, so SigmaHQ's 165 PowerShell script rules (`ps_script`, event 4104) never run).
  **What it does:** a powershell.exe (Windows PowerShell 5.1) process start whose command line carries
  code (`-Command …`, a bare first word, `-EncodedCommand <base64>` decoded) gets ONE declared row:
  event 4104 with `ScriptBlockText` = the code PowerShell would compile and an empty `Path`, offered
  to the simple `ps_script` rules. Those rules are now loaded but run ONLY over declared rows (we
  record no 4104). The translator is powershell.exe's argument syntax only: **no list of commands,
  cmdlets or rules, nothing taken from ART**. No SigmaHQ rule is switched on or off for it.
  **Honesty of the alert:** as F7 (cites the powershell.exe start; "declared, not recorded: it may
  not have run"; `details.derived_from = "command_line"`; never stored, never a graph fact).
  **Ground truth, not memory:** what powershell.exe 5.1 makes of a command line was MEASURED on this
  laptop with harmless commands that print their own script block text: the parameter prefixes, the
  dash forms, the joining of arguments, the C-runtime quoting, -EncodedCommand's rules; plus a
  differential oracle (about 175 command lines, real PowerShell vs the translator), kept as a test
  fixture. Defender's ML flagged 5 of the first probes (unknown switch + base64, blocked as
  "Trojan:Win32/Commando.C!ml"; correct behaviour, nothing changed in Defender); after that no
  base64 was sent to a real PowerShell again.
  **Limits (stated):** pwsh.exe (PowerShell 7, not installed here) and `-File` scripts declare
  nothing; code PowerShell builds while running (Invoke-Expression, downloaded code) is not seen;
  the code may fail to parse or be blocked and never run; one row holds what 4104 may split over
  several events; `-Version 2` code is declared although v2 would not log it.
  **Controls (art-prereg Q4):** the harness control T0000 runs `Write-Output "…"` through the same
  `powershell.exe & {…}` form; any script rule that fires on it becomes a control rule at the
  official scoring and never counts. The practice estimate applies the same exclusion to the control
  command lines as the harness writes them.
  **How it is judged before the freeze (seen data only):** learn-half replay (Q1 and Q2 separately,
  none of the F7 state's 105/76 lost); laptop false alarms on data ≤ 2026-11-14 (this is the brake
  that matters: normal programs start PowerShell with inline code); blind runs B1–B17 re-scored;
  tests + sabotage; independent review. **Stopping rule written now:** if the laptop learn period
  shows more than 1 raised declared-script alert per day on average, F8 is NOT switched on as is;
  the per-rule numbers go to Yousif, and any narrowing must be a Sigma filter (F6's tool), decided
  on the laptop numbers alone, never on the learn-half result.
  **Results (2026-11-17 night, all on SEEN data; never v4's result; final translator after review):**
  - *Learn half* (192 executed): Q1 105 → **119**, Q2 76 → **78**, **no test lost** (against F7 or v3).
    All 14 new detections come only through declared script alerts (14 SigmaHQ ps_script rules); 12
    of those rules cite ART, hence Q2 +2 only ("Clearing Windows Console History", "Clear PowerShell
    History - PowerShell"). Phase 1 (normal user): Q1 39 → 50, Q2 27 → 29; phase 2: Q1 66 → 69, Q2 49
    → 49. The control T0000's PowerShell line fires no script rule. Identical before and after the
    review fixes, and with F2 switched on.
  - *Laptop ≤ 2026-11-14* (aggregates): 39,465 powershell.exe starts in 30 days; 37,796 declare code
    (808 `-File`, 761 stdin/empty, 100 interactive; 0 refused for an unknown word); 24,345 visible
    after our own tools are left out, but only **113 distinct texts from 28 programs** (the laptop
    maker's service repeats a handful); **0 declared script alerts at any level** (the 165 rules
    were checked to run over those rows). Brake: 0.00/day against 1/day.
  - *VM seen data* (before 2026-11-14T15:33Z): 474 starts, 52 visible declaring rows, 4 raised alerts:
    3 = blind B14's PowerShell upload ("Usage Of Web Request Commands And Cmdlets", one per run), 1 =
    the ART spike's T1105 download test. None in an S0 boot, an innocent scenario or the harness.
  - *Ground truth:* parameter probe (every prefix of 17 parameters); 174-case oracle (153 agree, 18
    texts PowerShell's own parser rejects, 3 artefacts of the print-yourself payload, 4 unknown words
    compiled as code: each explained in the fixture); after the review 249 more probes (every one
    agrees). SigmaHQ's 4104 samples round trip in both forms (13 file-based samples skipped).
  - *Tests:* `tests/test_pscmd.py`, `tests/test_declared_script.py` (+ report, F7 label); *sabotage:*
    51 single-line breaks, 48 caught; 3 equivalent survivors (missing base64 padding, also refused by
    the strict decoder; Path NULL vs '', the backend's NOT is NULL-safe; a lone dash, also caught by
    the stdin check).
  - *Independent review* (fresh subagent, ~65 probes of the real powershell.exe 5.1): **PASS WITH
    FIXES, all applied and re-probed**: (1) an UNKNOWN dash word starts the code in 5.1 (`-foo <code>`,
    `-x;<code>`, `-ExecutionPolicy:Bypass -c <code>`); F8 declared nothing, so one extra word hid the
    code from every rule, and a test pinned that; now such a word starts the code, and only 5.1's own
    parameters we do not read (probed: -config…, -ea/-encodeda…, -h…, -?, -nam…, -p…, -s/-se…, -so…,
    -wo…) declare nothing; -imp… (ImportSystemModules) is a switch; (2) powershell.exe splits by the
    OLD msvcrt rule (`""` inside quotes ends the quoted part): `split_args(doubled_quote_ends=True)`,
    F7 unchanged; (3) `-c - x` is refused by 5.1, no longer declared; (4) .NET's trim set, not
    Python's (U+001C–001F); (5) values 5.1 refuses (`-w bogus`, `-w 4`, `-v 9`, `-if bogus`) declare
    nothing; -ExecutionPolicy takes any word (probed); (6) the live and demo screens now print
    "(declared on a command line, not recorded)" next to such alerts (also F7's). Not probed and
    kept as limits: `-enc A -enc B` (refused to be safe), a NUL inside decoded text.
- **Pipeline fix: registry add/delete EventType** (changed, `engine/detect.py` `CATEGORY_CONDITIONS`;
  found 2026-11-17 while measuring F7b's ceiling: a SigmaHQ "…Removal of… Keys" rule fired on a key
  being CREATED). SigmaHQ's own Sysmon pipeline (pySigma-pipeline-sysmon,
  `sysmon_generic_logsource_additional_conditions`) adds `EventType = CreateKey` to `registry_add` and
  `EventType in (DeleteKey, DeleteValue)` to `registry_delete`; ours mapped both to event 12 only (since
  v2's registry categories; v3 frozen with it). Now as SigmaHQ's. Effect on seen data: learn-half replay
  unchanged (Q1 119, Q2 78); raised alerts of the 11 add/delete rules on the laptop ≤ 11-14, the
  registry smoke store 11-08..11-12 and the VM before the cut: 0 → 0 in every store. Tests:
  `tests/test_registry_pipeline.py` (recorded and declared rows; the queries carry the condition) and
  the registry-category test now uses Sysmon's real EventTypes; removing the fix fails 7 tests. Reported
  as a v3 bug found during v4 work (v3's results stay as they are).
- **F7b (PowerShell registry cmdlets): measured, NOT built** (2026-11-17). Of the still-missed learn
  tests, 8 change the registry with `Set-ItemProperty` / `New-ItemProperty` / `New-Item`. Written as the
  equivalent `reg add` lines (what a PERFECT F7b would declare) through F7 and every registry rule: 5
  would be caught at Q1, 2 at Q2, and one of those two only through the pipeline bug above; so the real
  ceiling is about 1 test at Q2, for a home-made PowerShell parser. Not worth the risk; not built.
- **F2 learned-normal short beacon test** (planned; *written 2026-11-17 ~00:05 local BEFORE any F2
  code and before the laptop hold-out result*). Learned from B15 (seen): its 8 jittered check-ins
  (18–32 s) pass both of v3's tests on paper (RITA regularity 0.93–0.97 >= 0.9; the registered short
  test crosses at check-in 5–6) but are judged by neither: the RITA gate needs 10 check-ins, and the
  short test only judges programs whose file was written <= 24 h earlier (B15's program runs from the
  scenario CD). Rejected on purpose: "a program run from a CD/removable drive counts as fresh" (that
  is our harness's shape, not an attacker's).
  **What it does:** the v3 short test (Greenwood, alpha 1 %, `short_min` 4 and the registered
  cut-offs, ALL UNCHANGED) also judges series of a program this machine never saw making a network
  connection during its learning period (learned-normal, as `new_listener` and F3; by program NAME;
  own files `laptop-connectors.json` from the laptop <= 2026-11-14 and `vm-connectors.json` from the
  same 3 S0 boots as `vm.json`; the pinned baseline files stay byte-identical). Same alert as a fresh
  drop's short alert, with the reason "a program this machine never saw connecting out before".
  Config switch in `beacon`. No threshold, cut-off or window changes.
  **Brake, measured BEFORE it is switched on (laptop learn data only):** hold-out = learn connectors
  from 10-16..11-07, judge series that start 11-08..11-14. **Stopping rule written now:** more than
  1 new short alert per day in the hold-out = not switched on as is; the per-program numbers go to
  Yousif. Whether shells/script hosts (as F3's never-normal list) are ever "learned" is decided on
  the hold-out numbers alone and written here with them.
  **Judged before the freeze (seen data only):** the hold-out; blind runs B1–B17 re-scored with it on
  and off (B11 and the innocent steps must stay clean; C1, the listed updater, stays informational);
  own scenarios; tests + sabotage; independent review. Flagged as a hard step ("RITA beacon
  adaptation"); built overnight, recorded in the morning notes.
  **Results (2026-11-17 night, SEEN data) and decision: F2 is NOT switched on** (`short_unseen: false`;
  code, learned files and tests kept).
  - *Laptop hold-out* (real code path): learn to 11-07 → 1 F2 alert in 7 days (an unknown process);
    learn only to 10-22 → 11 in 23 days (0.48/day; 10 from one sync app and its helper). Shells never
    learned: the same numbers. Brake (1/day): passed.
  - *Blind B1–B17* (51 runs, three passes: all on / F8 off / F2 off): F2 turns **B15** MISSED →
    DETECTED 3/3 at INCIDENT level (its beacon step is now flagged; the strict verdict stays MISSED,
    two later steps are reached only by follow-through) and turns the innocent **B11** CLEAN → **FALSE
    ALARM in 2 of 3 runs** (its documentation tool polls the test server 4 times at an even 20 s, which
    the short test judges from 4 check-ins; B11 was written as exactly this trap). Every other run is
    unchanged.
  - *Decision, by the rule written above* ("B11 and the innocent steps must stay clean"): F2 fails it.
    Not tuned: keeping B15 and clearing B11 would mean choosing the check-in count from those two
    scenarios' details (B11 polls 4 times, B15 crosses at 5–6): the overfitting already refused for F5
    (S3/B11). Switching it on is Yousif's decision, with these numbers.
    **Yousif decided 2026-11-17 (morning, before the freeze and before any unseen data): F2 stays
    OFF in v4.** Reported in the results as "built, tested, switched off by its own pre-registered
    rule", with the B15/B11 numbers above.
  - *Independent review* (fresh subagent): PASS WITH FIXES, applied (so the code is right if it is ever
    switched on): one new program raised one alert per destination per awake window for ever → now ONE
    raised alert per (machine, program), later series informational (`repeat_of`); a shell on the
    learned list was labelled "never seen" → `eligible = never_normal_program`, honest reason; the
    false-alarm budget silently counted 0 F2 alerts without lists → refuses, reports hosts with/without
    a list, `main()` wiring tested; `null` list loaded as empty → no list; learning used the logged
    time, series the event time → event time; learning ignored `unicast_only` → passed through; live
    loop says how many machines have a list. Wording: the short test judges the FIRST 4–9 check-ins of
    any series (consistent with B2's calibration), not only short series. Stated limit: learned by file
    NAME (a beacon named like a learned program stays silent).
  - *After the fixes* (real code path): hold-out 7 days → 1 F2 alert (now labelled
    `never_normal_program`, an unknown process); 23 days → 5 raised instead of 11 (0.22/day; the sync
    app counts once). The fixed learning reproduces the pinned `laptop-connectors.json` list exactly.
    Tests: `tests/test_f2_unseen.py` (25 cases + budget wiring); sabotage: 16 of 16 breaks caught
    before the review, 25 of 25 after.
- **The seal tool `tools/art_view.py`** (section 2): learn rows only when the parent technique is a
  LEARN parent AND the test GUID is in the split's learn list; TEST half + unknown → totals only;
  refuses a changed split (SHA-256) and an `--out` onto an `official-*` page. 13 tests (incl.
  spelling variants, GUID outside the learn list, the pinned hash = this file's); removing the
  learn filter fails them. Independent review: PASS (fixes applied).
- **Last changes before the freeze (2026-11-17, no unseen data read):** the declared-alert brake
  (section 3c) and its count in `tools/v3_budget.py`; `tools/run_in_vm.py` / `tools/run_blind.py` gained
  `--snapshot` (default `clean`, recorded in each run summary, refused when missing) so blind round 4
  can run on the `lived-in` snapshot from the frozen code. No detector, rule, config or baseline changed
  after the final practice-half replay and blind re-score (`git diff fb7c0cb..freeze-v4 -- engine config
  rules scenarios` is empty). Pre-freeze smoke checks: `art_score.py --label practice --engine-root wt\v4`
  on the practice spike boot (seen) runs; `config.verify_official()` and `evaluation.sigma_problems()`
  report nothing; `experiments.py detection/blind --label practice` run on seen runs.

## 5b. Seal incidents (reported as they happened)

- **2026-11-14/15, date-cut scans touched official ART boots.** Three scratch scans for F3/F4 chose
  VM recordings by FILE DATE (≤ 2026-11-14); the official ART series began 15:33 UTC that day, so the
  scans read phase-1 boots 1 to about 8 (both halves mixed; boots are not split by half). What was
  seen: (a) eight rows of the plain F3 rule, one per boot, all `low`, creator powershell.exe, 3–4
  files, 0 connections (the same in every boot, so the harness itself; no technique, GUID or test
  identity); (b) the plain F3 rule raised no medium alert in those boots; (c) the F4 pattern count
  on VM data stayed 3 (= B17), i.e. 0 in those boots. Nothing per test or per technique was seen and
  no rule was changed because of it (F3's learned-normal change came from the LAPTOP count, F4's
  review fixes from the reviewer). `recordings/scratch/learn/vm-to-1114.db` also holds those boots,
  but `vm-wipers.json` was learned only from the 3 S0 sessions (0 programs). Found by the advisor
  review on 11-15. **Rule from now on:** VM data for v4 work is selected by RUN WINDOW (blind runs,
  own-scenario runs, S0 boots) or by a cut-off before 2026-11-14T15:33Z, never by file date.
- **2026-11-17 ~00:45 local, a scratch comparison ran detection over the whole VM store.** Checking
  whether a pipeline fix (registry_add/delete EventType conditions) changes any alert, a scratch script
  ran the 11 registry add/delete rules over `vm-to-1114.db` INCLUDING the rows after the cut, then kept
  and printed only alerts stamped before 2026-11-14T15:33Z (result printed: 0 -> 0). Nothing from
  after the cut was printed or looked at (no count, rule, test or technique), and no decision depends
  on it, but the rule above says to copy the pre-cut rows first (as every other F7/F8 script does).
  Found by the builder itself the same minute; the check was not repeated on the full store.

## 6. Freeze and pins (filled in at the freeze)

- **Tag `freeze-v4`** = the commit that adds this section (a file cannot hold its own commit's hash or
  its own SHA-256: both are written in the tag message and in VERIFICATION_LOG.md, 2026-11-17).
- **ART split:** `docs/plans/v4/art-split.json` SHA-256
  `0f395a70b1e52a740347cbce8936878514d081448c4188c3a9c2312f433d7fee` (= `tools/art_view.py` SPLIT_SHA256).
- **Decisions taken before the freeze:** F2 OFF (Yousif, 2026-11-17); declared-alert brake 0.1 per awake
  hour (3c); every other switch as in `config/frozen.yaml` at the tag.
- **After the tag:** the seal on v3's official ART tables ends; v4's sealed TEST half is scored with
  `wt\art\tools\art_score.py --label official --engine-root wt\v4`, into its OWN recordings folder (junctions
  to `vm`, `vmruns`, `scenario_runs` only) and its own `--out-md` under `docs/results/v4/`, so v3's
  official ART files are never written (their SHA-256 checked before and after). Laptop week 11-15..11-21
  (3.3, 3c) only from 2026-11-22.