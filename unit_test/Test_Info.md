# Test Info

Test runner, modular integration targets, and fixtures for Penelope.

## Directory Layout

- `scripts/`: Test runner scripts (`run_tests.ps1`).
- `fixtures/`: Shared test datasets (CSV and JSON files).
- `generated/`: Local test output files and generated artifacts.
- `reports/`: Timestamped markdown and JSON test run reports (gitignored).
- `.private_tests/`: Gitignored private integration test vault and local security checks.

## Running Tests

Run the PowerShell test script from the repo root:

```powershell
# run all backend checks (format, clippy, unit, and all db tests)
.\unit_test\scripts\run_tests.ps1 -Suite backend

# run only unit tests
.\unit_test\scripts\run_tests.ps1 -Suite backend -Target unit

# run specific database integration targets
.\unit_test\scripts\run_tests.ps1 -Suite backend -Target role_boundaries
.\unit_test\scripts\run_tests.ps1 -Suite backend -Target concurrency
.\unit_test\scripts\run_tests.ps1 -Suite backend -Target mwa

# run frontend tests
.\unit_test\scripts\run_tests.ps1 -Suite frontend

# run full public suite
.\unit_test\scripts\run_tests.ps1 -Suite full

# run with private checks (isolated integration tests, ai checks, security audit)
.\unit_test\scripts\run_tests.ps1 -Suite backend -Private
```

## Modular Integration Targets

Integration tests live in `backend/tests/`:
- `tests/common/`: Shared database connection pools, actor seeding, and decimal helpers.
- `tests/db_role_boundaries.rs`: Role permissions, table grants, and column-level restrictions.
- `tests/db_concurrency_and_idempotency.rs`: Concurrent idempotency replay and dispatch serialization.
- `tests/db_mwa_and_append_only.rs`: 6-decimal MWA arithmetic, cycle-count valuation, and append-only triggers.

## Notes

- Supported `-Target` values for `-Suite backend`: `unit`, `role_boundaries` (`roles`), `db`, `concurrency` (`idempotency`), and `mwa` (`ledger`, `append_only`). Passing an unknown target or combining `-Target` with `-Private` or `-Suite frontend` fails immediately.
- Reports get saved to `unit_test/reports/` (or `unit_test/.private_tests/reports/` for private runs). Both folders are gitignored.
- If a runner finishes with 0 tests executed, the script treats it as a failure.
- When running with `-Private`, temporary private test files are cleaned up automatically after the run.
