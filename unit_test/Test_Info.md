# Test Info

Test runner and fixtures for Penelope.

## Running Tests

Run the test script from PowerShell:

```powershell
# run public backend tests (fmt, clippy, unit, db tests)
.\unit_test\scripts\run_tests.ps1 -Suite backend

# run frontend tests
.\unit_test\scripts\run_tests.ps1 -Suite frontend

# run everything
.\unit_test\scripts\run_tests.ps1 -Suite full

# include private tests
.\unit_test\scripts\run_tests.ps1 -Suite backend -Private
```

## Notes

- Reports get saved to `unit_test/reports/` (or `unit_test/.private_tests/reports/` for private runs). Both folders are gitignored.
- If a runner finishes with 0 tests executed, the script treats it as a failure.
- When running with `-Private`, temporary test files are cleaned up automatically after the run.
