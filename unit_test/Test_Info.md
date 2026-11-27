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
.\unit_test\scripts\run_tests.ps1 -Suite backend -Target services
.\unit_test\scripts\run_tests.ps1 -Suite backend -Target health
.\unit_test\scripts\run_tests.ps1 -Suite backend -Target auth
.\unit_test\scripts\run_tests.ps1 -Suite backend -Target rbac
.\unit_test\scripts\run_tests.ps1 -Suite backend -Target admin

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
- `tests/db_services_audit_and_bootstrap.rs`: Transactional `AuditService`, role-scoped audit queries, and advisory-locked initial admin bootstrap.
- `tests/http_health.rs`: HTTP `/api/v1/health/live` and `/api/v1/health/ready` probe checks.
- `tests/http_auth_and_sessions.rs`: HTTP `/api/v1/auth/*` login, HttpOnly cookie attributes, logout, `/auth/me`, idle/absolute session TTL, and API-key no-fallback checks.
- `tests/http_rbac_and_api_keys.rs`: Role permission matrix across `/admin/*` and `/audit-logs`, scoped API key creation, revocation, expiration, and creator deactivation checks.
- `tests/http_admin_and_audit.rs`: User creation, update invariants, self/last-admin guards, immediate session invalidation, and Admin vs Manager audit log scoping.

## Notes

- Supported `-Target` values (requires `-Suite backend`): `unit`, `role_boundaries` (`roles`), `db`, `concurrency` (`idempotency`), `mwa` (`ledger`, `append_only`), `services` (`bootstrap`), `audit` (runs both `db_services_audit_and_bootstrap` and `http_admin_and_audit`), `health`, `auth` (`sessions`), `rbac` (`api_keys`), `admin`, and `http`.
- Test reports are written to `unit_test/reports/` and ignored by Git.
- Any test target exiting with zero executed tests fails automatically.
