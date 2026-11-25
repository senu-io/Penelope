# Test Info

Test runner, modular integration targets, and fixtures for Penelope.

## Directory Layout

- `scripts/`: PowerShell test runner (`run_tests.ps1`).
- `fixtures/`: Shared CSV and JSON test datasets.
- `generated/`: Local output files created by tests.
- `reports/`: Timestamped markdown and JSON test reports (gitignored).

## Running Tests

Run the test runner from the repository root:

```powershell
# run all backend checks (format, clippy, unit, and database tests)
.\unit_test\scripts\run_tests.ps1 -Suite backend

# run unit tests only
.\unit_test\scripts\run_tests.ps1 -Suite backend -Target unit

# run specific database or http integration targets
.\unit_test\scripts\run_tests.ps1 -Suite backend -Target role_boundaries
.\unit_test\scripts\run_tests.ps1 -Suite backend -Target concurrency
.\unit_test\scripts\run_tests.ps1 -Suite backend -Target mwa
.\unit_test\scripts\run_tests.ps1 -Suite backend -Target health

# run frontend tests
.\unit_test\scripts\run_tests.ps1 -Suite frontend

# run full suite
.\unit_test\scripts\run_tests.ps1 -Suite full
```

## Integration Test Targets

Database integration tests live in `backend/tests/`:

- `tests/common/`: Pool setup (reads `DATABASE_URL` and `MIGRATION_DATABASE_URL` from `.env`), actor seeding, and decimal helpers.
- `tests/db_role_boundaries.rs`: Role isolation, schema privileges, and table/column grants.
- `tests/db_concurrency_and_idempotency.rs`: Concurrent idempotency replay (`P0409`) and dispatch row locking.
- `tests/db_mwa_and_append_only.rs`: Fractional unit rules, 6-decimal MWA arithmetic, cycle-count valuation, and append-only triggers.
- `tests/http_health.rs`: HTTP `/api/v1/health/live` and `/api/v1/health/ready` probe checks.

## Notes

- Supported `-Target` values (requires `-Suite backend`): `unit`, `role_boundaries` (`roles`), `db`, `concurrency` (`idempotency`), `mwa` (`ledger`, `append_only`), and `health` (`http`).
- Test reports are written to `unit_test/reports/` and ignored by Git.
- Any test target exiting with zero executed tests fails automatically.
