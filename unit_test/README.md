# Unit Test Workspace (`unit_test/`)

This directory holds unit test fixtures, generated test outputs, execution scripts, and structured test reports for Penelope.

* Public test suites and reports live directly under `unit_test/{fixtures,generated,reports,scripts}/` and are tracked in version control.
* Private test suites and internal verification runs live under `unit_test/.private_tests/` and are excluded via `.gitignore`.

## Report Naming Convention

Test reports follow the format:

```text
ut_report_<YYYYMMDD>_<HHMMSS>_<suite>_<PASS|FAIL>.md
ut_report_<YYYYMMDD>_<HHMMSS>_<suite>_<PASS|FAIL>.json
```
