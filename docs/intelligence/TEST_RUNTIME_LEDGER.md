# Test Runtime Ledger

| Stage | Tier | Command scope | Result | Pytest duration | Process elapsed | Repeat policy |
| --- | --- | --- | --- | --- | --- | --- |
| A | 2 | approval conditions and Approval Centre | 18 passed | 21.27s | 51.84s | Do not repeat unless affected |
| A | 2 | Machine Oracle | 37 passed | 31.97s | 64.49s | Do not repeat unless affected |
| A | 2/3 | repository coverage and Milestone 27 contracts | 24 passed | 20.29s | 53.72s | Do not repeat unless affected |
| A | 1 | changed-file Ruff | passed | n/a | 1.41s on first clean rerun | Rerun only changed files |
| A | 1 | changed-file format check | 12 files formatted | n/a | 1.36s | Rerun only changed files |
| A | 1 | scoped compileall | passed | n/a | 18.54s | Rerun only changed modules |
| B reconciliation | 2 | canonical coverage generator tests, first harness run | 2 failed (dynamic-module registration) | 7.68s | 51.70s | Corrected; do not repeat |
| B reconciliation | 2 | canonical coverage generator tests, subsection audit | 1 passed, 1 failed (missing subsection row) | 6.00s | 45.65s | Corrected; do not repeat |
| B reconciliation | 2 | canonical coverage generator tests | 2 passed | 4.47s | 31.57s | Do not repeat unless roadmap or generator changes |
| B reconciliation | 1 | coverage generator and test Ruff/format | passed | n/a | included with focused run | Rerun only if these Python files change |
| B reconciliation | 2 | canonical-body/status-appendix boundary tests | 2 passed | 4.71s | 40.48s | Final reconciliation run; do not repeat unless mapper changes |
| B reconciliation | 1 | JSON plus staged/unstaged diff integrity | passed | n/a | 3.99s | Reconciliation checkpoint complete |
| B Wave 1 subtraction | 1 | staged/unstaged diff integrity | passed | n/a | 1.79s | No test run; documentation/evidence task only |
| B Wave 1.1 | 1 | six changed agent/test files Ruff, format, agent compileall | passed | n/a | 15.70s | Rerun only files changed afterward |
| B Wave 1.1 | 2 | agent models, store, and controller | 40 passed | 35.53s | 68.24s | Models/store not repeated after controller-only correction |
| B Wave 1.1 | 1/3 | controller and controller/activity integration after ordering correction | 20 passed | 31.11s | 64.11s | Final affected controller gate |
| B Wave 1.1 | 1 | JSON plus staged/unstaged diff integrity | passed | n/a | 5.50s | Wave 1.1 checkpoint complete |
| B Wave 1.2 | 1/2/3 | agent models, controller, and activity integration | 39 passed | 46.32s | 84.35s | Final operator pause/cancel checkpoint gate |
| B Wave 1.2 | 1 | JSON plus staged/unstaged diff integrity | passed | n/a | 5.31s | Wave 1.2 checkpoint complete |
| B Wave 1.3 | 2/3 | agent model/store/controller/activity Approval Centre integration | 49 passed | 56.42s | 91.18s | Authoritative consumption path passed |
| B Wave 1.3 | 2/3 | controller/policy/activity after forged-reference hardening | 36 passed, 1 failed | 49.94s | 87.06s | Legacy caller-reference expectation corrected; do not repeat |
| B Wave 1.3 | 2 | corrected policy subset | 13 passed | 13.40s | 53.34s | Final policy gate |
| B Wave 1.3 | 1 | JSON plus staged/unstaged diff integrity | passed | n/a | 4.89s | Wave 1.3 checkpoint complete |

The initial literal `python` invocation did not start because `python` was not
on `PATH`; it executed zero tests. Subsequent validation used the existing
project environment at `/mnt/vulnhunter-data/Projects/vulnhunter-ai/.venv`.
