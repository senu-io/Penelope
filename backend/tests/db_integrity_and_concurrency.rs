// TODO: add postgres schema, role permission, and concurrency tests in step 2

#[test]
fn step_one_scaffold_smoke_test() {
    assert_eq!(penelope_backend::crate_version(), "0.1.0");
}
