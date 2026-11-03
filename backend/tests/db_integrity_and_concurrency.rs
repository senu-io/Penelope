//! Public PostgreSQL & Concurrency Integration Test Target (`--test db_integrity_and_concurrency`).

#[test]
fn step_one_scaffold_smoke_test() {
    assert_eq!(penelope_backend::crate_version(), "0.1.0");
}
