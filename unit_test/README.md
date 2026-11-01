# Unit Test Workspace (`unit_test/`)

This directory holds unit and integration test fixtures, generated test outputs, execution scripts, and structured test reports for Penelope.

* **Public Test Execution (`run_tests.ps1 -Suite backend|frontend|full`):**
  * Backend: Runs `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --lib --bins --test db_integrity_and_concurrency -- --nocapture`.
  * Frontend: Runs `npm test` (`vitest run --config vitest.config.ts`), where `vitest.config.ts` explicitly sets `test.exclude` to include `'**/*.private.test.{ts,tsx}'` in addition to `configDefaults.exclude` so private frontend tests are never executed during public runs.
  * Reports are written to `unit_test/reports/`.
* **Private Test Execution (`run_tests.ps1 -Suite backend|frontend|full -Private`):**
  * Backend: Runs the dedicated isolated Cargo integration test target `backend/tests/private_suite.rs` via `cargo test --test private_suite -- --nocapture`. If `backend/tests/private_suite.rs` does not exist on disk yet, `run_tests.ps1` materializes it from `unit_test/.private_tests/backend/private_suite.rs`.
  * Frontend: Runs `npm run test:private` (`vitest run --config vitest.private.config.ts`), where `vitest.private.config.ts` explicitly sets `test.include = ['src/**/*.private.test.{ts,tsx}', 'tests/**/*.private.test.{ts,tsx}']`.
  * Git Boundary: `unit_test/.private_tests/`, `backend/tests/private_suite.rs`, `frontend/**/*.private.test.ts`, and `frontend/**/*.private.test.tsx` are all excluded via `.gitignore` so private test source and reports are never committed to the public repository.
* **Zero-Test Protection:** If any test step exits `0` but executes `0` tests (`0 passed`), `run_tests.ps1` marks the step and report as `FAIL` (`ExitCode = 1`).

## Report Naming Convention

Test reports follow the format:

```text
ut_report_<YYYYMMDD>_<HHMMSS>_<suite>_<PASS|FAIL>.md
ut_report_<YYYYMMDD>_<HHMMSS>_<suite>_<PASS|FAIL>.json
```
