# Penelope Test Report (ut_report_20261103_135059_backend_PASS)

- Timestamp: 2026-11-03 13:51:33
- Suite: backend (Private: False)
- Status: PASS

| Step | Status | Exit Code | Tests Executed | Duration (ms) |
| :--- | :--- | ---: | ---: | ---: |
| Rust Format Check (cargo fmt --check) | PASS | 0 | 0 | 365 |
| Rust Lint Check (cargo clippy -- -D warnings) | PASS | 0 | 0 | 1135 |
| Rust Public Unit & DB Integration Tests (--lib --bins --test db_integrity_and_concurrency) | PASS | 0 | 2 | 32401 |

## Detailed Output

### Rust Format Check (cargo fmt --check) [PASS]
```text

```

### Rust Lint Check (cargo clippy -- -D warnings) [PASS]
```text
cargo :     Checking penelope-backend v0.1.0 (D:\Other\Projects\Penelope\[Penelope]\backend)
At D:\Other\Projects\Penelope\[Penelope]\unit_test\scripts\run_tests.ps1:95 char:13
+             cargo clippy --all-targets -- -D warnings
+             ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (    Checking pe...elope]\backend):String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
 
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.95s
```

### Rust Public Unit & DB Integration Tests (--lib --bins --test db_integrity_and_concurrency) [PASS]
```text
cargo :    Compiling cfg-if v1.0.5
At D:\Other\Projects\Penelope\[Penelope]\unit_test\scripts\run_tests.ps1:118 char:17
+ ...             cargo test --lib --bins --test db_integrity_and_concurren ...
+                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (   Compiling cfg-if v1.0.5:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
 
   Compiling typenum v1.20.1
   Compiling subtle v2.6.1
   Compiling windows-link v0.2.1
   Compiling stable_deref_trait v1.2.1
   Compiling pin-project-lite v0.2.17
   Compiling bytes v1.12.1
   Compiling futures-core v0.3.34
   Compiling once_cell v1.21.4
   Compiling itoa v1.0.18
   Compiling litemap v0.8.3
   Compiling utf_types v1.0.0
   Compiling scopeguard v1.2.0
   Compiling writeable v0.6.4
   Compiling windows_x86_64_msvc v0.52.6
   Compiling serde v1.0.217
   Compiling icu_normalizer_data v2.4.0
   Compiling memchr v2.8.3
   Compiling zerofrom v0.1.8
   Compiling icu_properties_data v2.4.0
   Compiling getrandom v0.2.17
   Compiling windows-sys v0.61.2
   Compiling cpufeatures v0.2.17
   Compiling percent-encoding v2.3.2
   Compiling generic-array v0.14.7
   Compiling windows-targets v0.52.6
   Compiling lock_api v0.4.14
   Compiling num-traits v0.2.19
   Compiling futures-sink v0.3.34
   Compiling yoke v0.8.4
   Compiling untrusted v0.9.0
   Compiling cmov v0.5.4
   Compiling rand_core v0.6.4
   Compiling futures-task v0.3.34
   Compiling utf8_iter v1.1.0
   Compiling slab v0.4.12
   Compiling tinyvec v1.13.3
   Compiling futures-io v0.3.34
   Compiling ring v0.17.14
   Compiling rustls-pki-types v1.15.1
   Compiling windows-sys v0.52.0
   Compiling zeroize v1.8.1
   Compiling zerovec v0.11.9
   Compiling zerotrie v0.2.5
   Compiling ctutils v0.4.8
   Compiling tracing-core v0.1.36
   Compiling unicode-properties v0.1.5
   Compiling ryu v1.0.23
   Compiling unicode-bidi v0.3.18
   Compiling log v0.4.35
   Compiling futures-util v0.3.34
   Compiling unicode-normalization v0.1.26
   Compiling equivalent v1.0.3
   Compiling const-oid v0.10.2
   Compiling zerocopy v0.8.63
   Compiling cpufeatures v0.3.1
   Compiling crypto-common v0.1.7
   Compiling block-buffer v0.10.4
   Compiling hybrid-array v0.4.15
   Compiling arrayvec v0.7.8
   Compiling foldhash v0.1.5
   Compiling rand_core v0.10.1
   Compiling allocator-api2 v0.2.21
   Compiling tracing v0.1.41
   Compiling tinystr v0.8.5
   Compiling potential_utf v0.1.6
   Compiling digest v0.10.7
   Compiling windows_x86_64_msvc v0.48.5
   Compiling icu_collections v2.4.0
   Compiling stringprep v0.1.5
   Compiling crossbeam-utils v0.8.23
   Compiling icu_locale_core v2.4.0
   Compiling hashbrown v0.17.1
   Compiling crc-catalog v2.5.0
   Compiling parking v2.2.1
   Compiling hashbrown v0.15.5
   Compiling thiserror v2.0.11
   Compiling crc v3.4.0
   Compiling windows-targets v0.48.5
   Compiling block-buffer v0.12.1
   Compiling crypto-common v0.2.2
   Compiling socket2 v0.5.10
   Compiling crossbeam-queue v0.3.14
   Compiling event-listener v5.4.2
   Compiling chacha20 v0.10.2
   Compiling getrandom v0.4.3
   Compiling http v1.5.0
   Compiling indexmap v2.14.2
   Compiling rustls-webpki v0.103.16
   Compiling windows-sys v0.48.0
   Compiling webpki-roots v1.0.11
   Compiling hashlink v0.10.0
   Compiling form_urlencoded v1.2.2
   Compiling rand v0.10.3
   Compiling bitflags v2.9.4
   Compiling fallible-iterator v0.2.0
   Compiling byteorder v1.5.0
   Compiling icu_provider v2.4.0
   Compiling base64 v0.22.1
   Compiling digest v0.11.3
   Compiling webpki-roots v0.26.11
   Compiling rustls v0.23.46
   Compiling smallvec v1.16.4
   Compiling mio v1.2.4
   Compiling icu_properties v2.4.0
   Compiling serde_json v1.0.138
   Compiling either v1.19.0
   Compiling parking_lot_core v0.9.12
   Compiling icu_normalizer v2.4.0
   Compiling http-body v1.1.0
   Compiling md-5 v0.11.0
   Compiling hmac v0.13.0
   Compiling sha2 v0.11.1
   Compiling parking_lot v0.12.5
   Compiling home v0.5.12
   Compiling tokio v1.43.0
   Compiling etcetera v0.8.0
   Compiling rust_decimal v1.36.0
   Compiling sha2 v0.10.8
   Compiling hmac v0.12.1
   Compiling chrono v0.4.39
   Compiling atoi v2.0.0
   Compiling rustls-pemfile v2.2.0
   Compiling futures-intrusive v0.5.0
   Compiling futures-channel v0.3.34
   Compiling tower-service v0.3.3
   Compiling hex v0.4.3
   Compiling idna_adapter v1.2.2
   Compiling postgres-protocol v0.6.12
   Compiling dotenvy v0.15.7
   Compiling whoami v1.6.1
   Compiling hkdf v0.12.4
   Compiling idna v1.1.0
   Compiling inout v0.1.4
   Compiling md-5 v0.10.6
   Compiling tower-layer v0.3.3
   Compiling tempfile v3.27.0
   Compiling httparse v1.10.1
   Compiling cipher v0.4.4
   Compiling postgres-types v0.2.14
   Compiling ppv-lite86 v0.2.21
   Compiling url v2.5.8
   Compiling http-body-util v0.1.5
   Compiling uuid v1.12.1
   Compiling universal-hash v0.5.1
   Compiling rand_chacha v0.3.1
   Compiling httpdate v1.0.3
   Compiling regex-syntax v0.6.29
   Compiling sync_wrapper v1.0.2
   Compiling atomic-waker v1.1.2
   Compiling regex-syntax v0.8.11
   Compiling rand v0.8.5
   Compiling opaque-debug v0.3.1
   Compiling winapi v0.3.9
   Compiling polyval v0.6.2
   Compiling overload v0.1.1
   Compiling lazy_static v1.5.1
   Compiling mime v0.3.17
   Compiling base64ct v1.8.3
   Compiling ghash v0.5.1
   Compiling ctr v0.9.2
   Compiling sharded-slab v0.1.7
   Compiling aes v0.8.4
   Compiling axum-core v0.4.5
   Compiling serde_urlencoded v0.7.1
   Compiling serde_path_to_error v0.1.17
   Compiling blake2 v0.10.6
   Compiling aead v0.5.2
   Compiling password-hash v0.5.0
   Compiling tracing-log v0.2.0
   Compiling thread_local v1.1.10
   Compiling matchit v0.7.3
   Compiling aes-gcm v0.10.3
   Compiling tower-http v0.6.2
   Compiling secrecy v0.8.0
   Compiling nu-ansi-term v0.46.0
   Compiling argon2 v0.5.3
   Compiling regex-automata v0.4.18
   Compiling regex-automata v0.1.10
   Compiling tokio-stream v0.1.19
   Compiling matchers v0.1.0
   Compiling sqlx-core v0.8.3
   Compiling hyper v1.12.0
   Compiling tower v0.5.2
   Compiling regex v1.13.1
   Compiling tracing-subscriber v0.3.19
   Compiling hyper-util v0.1.21
   Compiling axum v0.7.9
   Compiling sqlx-postgres v0.8.3
   Compiling sqlx-macros-core v0.8.3
   Compiling sqlx-macros v0.8.3
   Compiling sqlx v0.8.3
   Compiling penelope-backend v0.1.0 (D:\Other\Projects\Penelope\[Penelope]\backend)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 31.83s
     Running unittests src\lib.rs (target\debug\deps\penelope_backend-5a0ddf5f1fe2bec1.exe)

running 1 test
test tests::crate_version_is_non_empty ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running unittests src\main.rs (target\debug\deps\penelope_backend-51a8ed055e20a932.exe)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests\db_integrity_and_concurrency.rs 
(target\debug\deps\db_integrity_and_concurrency-a1739d3f18b484a1.exe)

running 1 test
test step_one_scaffold_smoke_test ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```