# v4 on v3's week: false-alarm budgets on the v3 laptop test week (pre-registered, section 1.8)

*Made by `tools/v3_budget.py` on the frozen code of the worktree it ran from (v3 or v4); snapshot days 2026-11-15 .. 2026-11-21; awake hours 78.86. Pass/fail fixed before the week was opened; a failed rule is reported, never re-tuned.*

| rule | alerts | per awake hour | budget | result |
|---|---:|---:|---:|---|
| analystlab.embedded_system_name | 1 | 0.013 | 0.1 | PASS |
| analystlab.drop_run_delete | 1 | 0.013 | 0.1 | PASS |

Short check-in test: RITA gate alone 137 alerted series; with the short gate 137; extra 0 (+0.0 %; budget +10 %): **PASS**.

Declared alerts (v4 pre-registration 3c; read from command lines, F7 registry 0 + F8 PowerShell 0): 0 raised = 0.000 per awake hour (budget 0.1): **PASS**.
