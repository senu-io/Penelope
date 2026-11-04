// postgres schema, role permissions, mwa costing, idempotency, and concurrency integration tests

use rust_decimal::Decimal;
use serde_json::json;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Row};
use std::str::FromStr;
use uuid::Uuid;

static MIGRATION_ONCE: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

fn dec(val: &str) -> Decimal {
    Decimal::from_str(val).expect("valid decimal literal")
}

async fn setup_pools() -> (PgPool, PgPool) {
    dotenvy::dotenv().ok();

    let migration_url = std::env::var("MIGRATION_DATABASE_URL").unwrap_or_else(|_| {
        "postgres://penelope_owner:penelope_owner_local_dev_pw_2026@localhost:5432/penelope_db"
            .to_string()
    });
    let app_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://penelope_app:penelope_app_local_dev_pw_2026@localhost:5432/penelope_db"
            .to_string()
    });

    let owner_opts = PgConnectOptions::from_str(&migration_url).expect("valid migration url");
    let app_opts = PgConnectOptions::from_str(&app_url).unwrap_or_else(|_| owner_opts.clone());

    // run migrations via sqlx migrator and re-run raw migration script once before parallel tests
    MIGRATION_ONCE
        .get_or_init(|| {
            let mig_opts = owner_opts.clone();
            async move {
                let mig_pool = PgPoolOptions::new()
                    .max_connections(2)
                    .connect_with(mig_opts)
                    .await
                    .expect("failed to connect migration pool");

                sqlx::migrate!("./migrations")
                    .run(&mig_pool)
                    .await
                    .expect("sqlx migration failed");

                let raw_sql = include_str!("../migrations/0001_initial_schema.sql");
                sqlx::raw_sql(raw_sql)
                    .execute(&mig_pool)
                    .await
                    .expect("idempotent re-execution of 0001_initial_schema.sql failed");

                mig_pool.close().await;
            }
        })
        .await;

    let owner_pool = PgPoolOptions::new()
        .max_connections(8)
        .connect_with(owner_opts)
        .await
        .expect(
            "failed to connect to postgres with MIGRATION_DATABASE_URL (is docker compose up -d running?)",
        );

    let app_pool = PgPoolOptions::new()
        .max_connections(8)
        .connect_with(app_opts)
        .await
        .expect("failed to connect to postgres with DATABASE_URL (penelope_app)");

    (owner_pool, app_pool)
}

async fn seed_actor_and_category(app_pool: &PgPool) -> (Uuid, Uuid) {
    let user_id = Uuid::new_v4();
    let email = format!("op_{}@penelope.local", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO public.users (id, email, full_name, password_hash, role) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(user_id)
    .bind(email)
    .bind("Test Operator")
    .bind("$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g")
    .bind("operator")
    .execute(app_pool)
    .await
    .expect("insert test user");

    let cat_id = Uuid::new_v4();
    let code = format!("CAT-{}", &Uuid::new_v4().simple().to_string()[..8]);
    sqlx::query(
        "INSERT INTO public.categories (id, name, code, description) VALUES ($1, $2, $3, $4)",
    )
    .bind(cat_id)
    .bind(format!("Category {}", code))
    .bind(code)
    .bind("test category")
    .execute(app_pool)
    .await
    .expect("insert test category");

    (user_id, cat_id)
}

async fn insert_test_product(
    app_pool: &PgPool,
    category_id: Uuid,
    base_unit: &str,
    allow_fractional: bool,
) -> (Uuid, String) {
    let product_id = Uuid::new_v4();
    let sku = format!("SKU-{}", &Uuid::new_v4().simple().to_string()[..10]);
    sqlx::query(
        r#"
        INSERT INTO public.products (
            id, sku, barcode, name, description, category_id,
            base_unit, allow_fractional, bin_location, reorder_point,
            currency_code, unit_price_eur, encrypted_notes, is_archived
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'EUR', $11, NULL, FALSE)
        "#,
    )
    .bind(product_id)
    .bind(&sku)
    .bind(Some(format!("BC-{sku}")))
    .bind("Industrial Bearing")
    .bind("Test SKU")
    .bind(category_id)
    .bind(base_unit)
    .bind(allow_fractional)
    .bind("A-01-01")
    .bind(dec("5.0000"))
    .bind(dec("24.99"))
    .execute(app_pool)
    .await
    .expect("insert test product with allowed columns");

    (product_id, sku)
}

#[tokio::test]
async fn role_separation_and_privilege_boundaries_hold() {
    let (owner_pool, app_pool) = setup_pools().await;
    let (user_id, cat_id) = seed_actor_and_category(&app_pool).await;
    let (product_id, _sku) = insert_test_product(&app_pool, cat_id, "ea", false).await;

    // 1. verify neither penelope_owner nor penelope_app is a superuser
    let roles_row = sqlx::query(
        r#"
        SELECT
            (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = 'penelope_owner') AS owner_super,
            (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = 'penelope_app') AS app_super,
            pg_catalog.has_schema_privilege('penelope_app', 'public', 'CREATE') AS app_can_create_in_public,
            pg_catalog.has_function_privilege(
                'public',
                'public.record_stock_movement(uuid, uuid, text, numeric, numeric, text, text, uuid, uuid, text, text)',
                'EXECUTE'
            ) AS public_can_exec_movement,
            pg_catalog.has_function_privilege(
                'public',
                'public.record_audit_event(uuid, uuid, text, text, text, text, text, jsonb)',
                'EXECUTE'
            ) AS public_can_exec_audit
        "#,
    )
    .fetch_one(&owner_pool)
    .await
    .expect("query role attributes");

    assert!(
        !roles_row.get::<bool, _>("owner_super"),
        "penelope_owner must not be superuser"
    );
    assert!(
        !roles_row.get::<bool, _>("app_super"),
        "penelope_app must not be superuser"
    );
    assert!(
        !roles_row.get::<bool, _>("app_can_create_in_public"),
        "penelope_app must not have CREATE privilege on schema public"
    );
    assert!(
        !roles_row.get::<bool, _>("public_can_exec_movement"),
        "PUBLIC must not have EXECUTE on record_stock_movement"
    );
    assert!(
        !roles_row.get::<bool, _>("public_can_exec_audit"),
        "PUBLIC must not have EXECUTE on record_audit_event"
    );

    // 2. penelope_app cannot insert product with non-zero quantity_on_hand or cost
    let bad_insert = sqlx::query(
        r#"
        INSERT INTO public.products (
            id, sku, name, category_id, base_unit, allow_fractional,
            bin_location, quantity_on_hand, total_cost_basis_eur, unit_cost_eur, unit_price_eur
        )
        VALUES ($1, $2, 'Bad Product', $3, 'ea', FALSE, 'A-01-02', 50.0000, 500.000000, 10.000000, 20.00)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(format!("BAD-{}", Uuid::new_v4().simple()))
    .bind(cat_id)
    .execute(&app_pool)
    .await;
    assert!(
        bad_insert.is_err(),
        "penelope_app must be denied INSERT on quantity_on_hand / cost columns"
    );

    // 3. penelope_app cannot directly UPDATE quantity_on_hand, total_cost_basis_eur, or unit_cost_eur
    let bad_update_qty =
        sqlx::query("UPDATE public.products SET quantity_on_hand = 999.0000 WHERE id = $1")
            .bind(product_id)
            .execute(&app_pool)
            .await;
    assert!(
        bad_update_qty.is_err(),
        "penelope_app must be denied direct UPDATE of quantity_on_hand"
    );

    let bad_update_cost =
        sqlx::query("UPDATE public.products SET unit_cost_eur = 99.000000 WHERE id = $1")
            .bind(product_id)
            .execute(&app_pool)
            .await;
    assert!(
        bad_update_cost.is_err(),
        "penelope_app must be denied direct UPDATE of unit_cost_eur"
    );

    // 4. penelope_app cannot directly INSERT into stock_ledger or audit_logs
    let bad_ledger_insert = sqlx::query(
        r#"
        INSERT INTO public.stock_ledger (
            idempotency_key, request_hash, product_id, movement_type,
            previous_qty, delta, new_qty, total_cost_basis_eur_snapshot,
            unit_cost_eur_snapshot, reason, actor_user_id
        )
        VALUES ($1, repeat('a', 64), $2, 'receive', 0.0000, 10.0000, 10.0000, 100.000000, 10.000000, 'bypass', $3)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(product_id)
    .bind(user_id)
    .execute(&app_pool)
    .await;
    assert!(
        bad_ledger_insert.is_err(),
        "penelope_app must be denied direct INSERT on stock_ledger"
    );

    let bad_audit_insert = sqlx::query(
        r#"
        INSERT INTO public.audit_logs (actor_user_id, actor_label, action, entity_type, details)
        VALUES ($1, 'op', 'product.create', 'product', '{}'::jsonb)
        "#,
    )
    .bind(user_id)
    .execute(&app_pool)
    .await;
    assert!(
        bad_audit_insert.is_err(),
        "penelope_app must be denied direct INSERT on audit_logs"
    );

    // 5. actor attribution & api key scope checks in record_stock_movement and record_audit_event
    let write_key_id = Uuid::new_v4();
    let read_only_key_id = Uuid::new_v4();
    let revoked_key_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO public.api_keys (id, name, key_prefix, key_hash, scopes, created_by)
        VALUES
            ($1, 'Scanner Write Key', 'pen_live_0001', $4, ARRAY['read:stock', 'write:stock'], $7),
            ($2, 'Dashboard Read Key', 'pen_live_0002', $5, ARRAY['read:stock'], $7),
            ($3, 'Revoked Write Key', 'pen_live_0003', $6, ARRAY['write:stock'], $7)
        "#,
    )
    .bind(write_key_id)
    .bind(read_only_key_id)
    .bind(revoked_key_id)
    .bind(format!("{:064x}", Uuid::new_v4().as_u128()))
    .bind(format!("{:064x}", Uuid::new_v4().as_u128()))
    .bind(format!("{:064x}", Uuid::new_v4().as_u128()))
    .bind(user_id)
    .execute(&app_pool)
    .await
    .expect("seed test api keys");

    sqlx::query("UPDATE public.api_keys SET revoked_at = now() WHERE id = $1")
        .bind(revoked_key_id)
        .execute(&app_pool)
        .await
        .expect("revoke test api key");

    // 5a. both-null actors on record_stock_movement must fail with P0422 (ACTOR_REQUIRED)
    let both_null_stock = sqlx::query(
        "SELECT * FROM public.record_stock_movement($1, $2, 'receive', 5.0000, 10.000000, 'PO-NULL', 'no actor', NULL, NULL, 'anon', '127.0.0.1')",
    )
    .bind(Uuid::new_v4())
    .bind(product_id)
    .fetch_one(&app_pool)
    .await;
    let both_null_code = both_null_stock
        .expect_err("both-null actors must be rejected")
        .into_database_error()
        .and_then(|e| e.code().map(|c| c.into_owned()));
    assert_eq!(both_null_code.as_deref(), Some("P0422"));

    // 5b. both-present actors on record_stock_movement must fail with P0422 (AMBIGUOUS_ACTOR)
    let both_present_stock = sqlx::query(
        "SELECT * FROM public.record_stock_movement($1, $2, 'receive', 5.0000, 10.000000, 'PO-BOTH', 'dual actor', $3, $4, 'both@test', '127.0.0.1')",
    )
    .bind(Uuid::new_v4())
    .bind(product_id)
    .bind(user_id)
    .bind(write_key_id)
    .fetch_one(&app_pool)
    .await;
    let both_present_code = both_present_stock
        .expect_err("both-present actors must be rejected")
        .into_database_error()
        .and_then(|e| e.code().map(|c| c.into_owned()));
    assert_eq!(both_present_code.as_deref(), Some("P0422"));

    // 5c. api key lacking write:stock scope or revoked must fail with P0403
    let read_only_attempt = sqlx::query(
        "SELECT * FROM public.record_stock_movement($1, $2, 'receive', 5.0000, 10.000000, 'PO-RO', 'readonly key', NULL, $3, 'key:ro', '127.0.0.1')",
    )
    .bind(Uuid::new_v4())
    .bind(product_id)
    .bind(read_only_key_id)
    .fetch_one(&app_pool)
    .await;
    let ro_code = read_only_attempt
        .expect_err("read-only api key must be rejected")
        .into_database_error()
        .and_then(|e| e.code().map(|c| c.into_owned()));
    assert_eq!(ro_code.as_deref(), Some("P0403"));

    let revoked_attempt = sqlx::query(
        "SELECT * FROM public.record_stock_movement($1, $2, 'receive', 5.0000, 10.000000, 'PO-REV', 'revoked key', NULL, $3, 'key:rev', '127.0.0.1')",
    )
    .bind(Uuid::new_v4())
    .bind(product_id)
    .bind(revoked_key_id)
    .fetch_one(&app_pool)
    .await;
    let rev_code = revoked_attempt
        .expect_err("revoked api key must be rejected")
        .into_database_error()
        .and_then(|e| e.code().map(|c| c.into_owned()));
    assert_eq!(rev_code.as_deref(), Some("P0403"));

    // 5d. active api key with write:stock scope succeeds
    let valid_key_recv = sqlx::query(
        "SELECT actor_user_id, actor_api_key_id, new_qty FROM public.record_stock_movement($1, $2, 'receive', 5.0000, 10.000000, 'PO-KEY', 'valid key receive', NULL, $3, 'key:Scanner Write Key', '127.0.0.1')",
    )
    .bind(Uuid::new_v4())
    .bind(product_id)
    .bind(write_key_id)
    .fetch_one(&app_pool)
    .await
    .expect("active write:stock api key should succeed");
    assert_eq!(valid_key_recv.get::<Option<Uuid>, _>("actor_user_id"), None);
    assert_eq!(
        valid_key_recv.get::<Option<Uuid>, _>("actor_api_key_id"),
        Some(write_key_id)
    );
    assert_eq!(valid_key_recv.get::<Decimal, _>("new_qty"), dec("5.0000"));

    // 5e. record_audit_event rejects both-present actors and rejects missing actor on authenticated actions
    let both_present_audit = sqlx::query(
        "SELECT * FROM public.record_audit_event($1, $2, 'both@test', 'product.create', 'product', 'id1', '127.0.0.1', '{}'::jsonb)",
    )
    .bind(user_id)
    .bind(write_key_id)
    .fetch_one(&app_pool)
    .await;
    assert!(
        both_present_audit.is_err(),
        "record_audit_event must reject dual actor attribution"
    );

    let missing_actor_audit = sqlx::query(
        "SELECT * FROM public.record_audit_event(NULL, NULL, 'anon', 'product.create', 'product', 'id1', '127.0.0.1', '{}'::jsonb)",
    )
    .fetch_one(&app_pool)
    .await;
    assert!(
        missing_actor_audit.is_err(),
        "record_audit_event must reject null actors on authenticated actions"
    );
}

#[tokio::test]
async fn mwa_costing_cycle_counts_and_append_only_triggers_work() {
    let (owner_pool, app_pool) = setup_pools().await;
    let (user_id, cat_id) = seed_actor_and_category(&app_pool).await;
    let (discrete_id, _) = insert_test_product(&app_pool, cat_id, "ea", false).await;
    let (frac_id, _) = insert_test_product(&app_pool, cat_id, "kg", true).await;

    // 1. fractional movement on discrete ('ea') product must fail with P0422
    let frac_on_discrete = sqlx::query(
        "SELECT * FROM public.record_stock_movement($1, $2, 'receive', $3, $4, 'PO-1', 'initial recv', $5, NULL, 'op@test', '127.0.0.1')",
    )
    .bind(Uuid::new_v4())
    .bind(discrete_id)
    .bind(dec("1.5000"))
    .bind(dec("10.000000"))
    .bind(user_id)
    .fetch_one(&app_pool)
    .await;
    assert!(
        frac_on_discrete.is_err(),
        "fractional delta on discrete SKU must be rejected"
    );

    // 2. fractional movement on 'kg' product succeeds
    let kg_recv = sqlx::query(
        "SELECT new_qty, total_cost_basis_eur_snapshot, unit_cost_eur_snapshot FROM public.record_stock_movement($1, $2, 'receive', $3, $4, 'PO-KG', 'bulk cable', $5, NULL, 'op@test', '127.0.0.1')",
    )
    .bind(Uuid::new_v4())
    .bind(frac_id)
    .bind(dec("15.5000"))
    .bind(dec("2.000000"))
    .bind(user_id)
    .fetch_one(&app_pool)
    .await
    .expect("fractional receive on kg product");
    assert_eq!(kg_recv.get::<Decimal, _>("new_qty"), dec("15.5000"));
    assert_eq!(
        kg_recv.get::<Decimal, _>("total_cost_basis_eur_snapshot"),
        dec("31.000000")
    );
    assert_eq!(
        kg_recv.get::<Decimal, _>("unit_cost_eur_snapshot"),
        dec("2.000000")
    );

    // 3. MWA 6-decimal precision & authoritative total_cost_basis_eur:
    // receive 3 ea @ 0.100000 EUR -> total_cost_basis = 0.300000, unit_cost = 0.100000
    // receive 1 ea @ 0.110000 EUR -> total_cost_basis = 0.410000, unit_cost = 0.102500
    sqlx::query(
        "SELECT * FROM public.record_stock_movement($1, $2, 'receive', $3, $4, 'PO-101', 'lot 1', $5, NULL, 'op@test', '127.0.0.1')",
    )
    .bind(Uuid::new_v4())
    .bind(discrete_id)
    .bind(dec("3.0000"))
    .bind(dec("0.100000"))
    .bind(user_id)
    .fetch_one(&app_pool)
    .await
    .expect("receive lot 1");

    let lot2 = sqlx::query(
        "SELECT new_qty, total_cost_basis_eur_snapshot, unit_cost_eur_snapshot FROM public.record_stock_movement($1, $2, 'receive', $3, $4, 'PO-102', 'lot 2', $5, NULL, 'op@test', '127.0.0.1')",
    )
    .bind(Uuid::new_v4())
    .bind(discrete_id)
    .bind(dec("1.0000"))
    .bind(dec("0.110000"))
    .bind(user_id)
    .fetch_one(&app_pool)
    .await
    .expect("receive lot 2");

    assert_eq!(lot2.get::<Decimal, _>("new_qty"), dec("4.0000"));
    assert_eq!(
        lot2.get::<Decimal, _>("total_cost_basis_eur_snapshot"),
        dec("0.410000")
    );
    assert_eq!(
        lot2.get::<Decimal, _>("unit_cost_eur_snapshot"),
        dec("0.102500")
    );

    // verify reporting-boundary line-item valuation ROUND(total_cost_basis_eur, 2) = 0.41 EUR
    let val_row = sqlx::query(
        "SELECT pg_catalog.round(total_cost_basis_eur, 2) AS line_valuation_eur FROM public.products WHERE id = $1",
    )
    .bind(discrete_id)
    .fetch_one(&app_pool)
    .await
    .expect("query line valuation");
    assert_eq!(val_row.get::<Decimal, _>("line_valuation_eur"), dec("0.41"));

    // 4. positive cycle count with non-terminating unit cost fraction uses prev_total_cost_basis_eur / prev_qty:
    // create a fresh SKU, receive 3 ea @ 0.3333333? wait: receive 1 ea @ 1.000000 then receive 2 ea @ 0.000000 -> 3 ea with total_cost_basis = 1.000000 and rounded unit_cost = 0.333333
    let (cycle_prod_id, _) = insert_test_product(&app_pool, cat_id, "ea", false).await;

    // positive cycle count on zero stock without inbound cost must fail
    let zero_stock_cycle_err = sqlx::query(
        "SELECT * FROM public.record_stock_movement($1, $2, 'cycle_count', $3, NULL, 'CC-0', 'found on empty bin', $4, NULL, 'op@test', '127.0.0.1')",
    )
    .bind(Uuid::new_v4())
    .bind(cycle_prod_id)
    .bind(dec("2.0000"))
    .bind(user_id)
    .fetch_one(&app_pool)
    .await;
    assert!(
        zero_stock_cycle_err.is_err(),
        "positive cycle count on zero stock without explicit cost must fail"
    );

    // receive 1 ea @ 1.000000 and 2 ea @ 0.000000 so 3 units have total_cost_basis = 1.000000 and unit_cost = 0.333333
    sqlx::query(
        "SELECT * FROM public.record_stock_movement($1, $2, 'receive', $3, $4, 'PO-C1', 'paid unit', $5, NULL, 'op@test', '127.0.0.1')",
    )
    .bind(Uuid::new_v4())
    .bind(cycle_prod_id)
    .bind(dec("1.0000"))
    .bind(dec("1.000000"))
    .bind(user_id)
    .fetch_one(&app_pool)
    .await
    .expect("receive 1 paid unit");

    let after_free = sqlx::query(
        "SELECT new_qty, total_cost_basis_eur_snapshot, unit_cost_eur_snapshot FROM public.record_stock_movement($1, $2, 'receive', $3, $4, 'PO-C2', 'bonus units', $5, NULL, 'op@test', '127.0.0.1')",
    )
    .bind(Uuid::new_v4())
    .bind(cycle_prod_id)
    .bind(dec("2.0000"))
    .bind(dec("0.000000"))
    .bind(user_id)
    .fetch_one(&app_pool)
    .await
    .expect("receive 2 bonus units");
    assert_eq!(after_free.get::<Decimal, _>("new_qty"), dec("3.0000"));
    assert_eq!(
        after_free.get::<Decimal, _>("total_cost_basis_eur_snapshot"),
        dec("1.000000")
    );
    assert_eq!(
        after_free.get::<Decimal, _>("unit_cost_eur_snapshot"),
        dec("0.333333")
    );

    // now positive cycle count of +3 ea with NULL inbound cost must add ROUND(1.000000 * 3 / 3, 6) = 1.000000 -> total 2.000000 (NOT 1.999999)
    let cc_plus = sqlx::query(
        "SELECT new_qty, total_cost_basis_eur_snapshot, unit_cost_eur_snapshot FROM public.record_stock_movement($1, $2, 'cycle_count', $3, NULL, 'CC-1', 'surplus count', $4, NULL, 'op@test', '127.0.0.1')",
    )
    .bind(Uuid::new_v4())
    .bind(cycle_prod_id)
    .bind(dec("3.0000"))
    .bind(user_id)
    .fetch_one(&app_pool)
    .await
    .expect("positive cycle count");
    assert_eq!(cc_plus.get::<Decimal, _>("new_qty"), dec("6.0000"));
    assert_eq!(
        cc_plus.get::<Decimal, _>("total_cost_basis_eur_snapshot"),
        dec("2.000000")
    );
    assert_eq!(
        cc_plus.get::<Decimal, _>("unit_cost_eur_snapshot"),
        dec("0.333333")
    );

    // 5. audit whitelist: record_audit_event allows valid pair, rejects 'stock_ledger' and unknown actions
    let valid_audit = sqlx::query(
        "SELECT id FROM public.record_audit_event($1, NULL, 'op@test', 'product.create', 'product', $2, '127.0.0.1', $3)",
    )
    .bind(user_id)
    .bind(discrete_id.to_string())
    .bind(json!({"sku": "TEST"}))
    .fetch_one(&app_pool)
    .await;
    assert!(valid_audit.is_ok(), "whitelisted audit event must succeed");

    let forged_ledger_audit = sqlx::query(
        "SELECT id FROM public.record_audit_event($1, NULL, 'op@test', 'stock.movement.receive', 'stock_ledger', $2, '127.0.0.1', $3)",
    )
    .bind(user_id)
    .bind(discrete_id.to_string())
    .bind(json!({}))
    .fetch_one(&app_pool)
    .await;
    assert!(
        forged_ledger_audit.is_err(),
        "record_audit_event must reject entity_type = 'stock_ledger'"
    );

    // 6. append-only triggers reject UPDATE, DELETE, and TRUNCATE even when invoked by penelope_owner
    let owner_update_ledger = sqlx::query("UPDATE public.stock_ledger SET reason = 'tampered'")
        .execute(&owner_pool)
        .await;
    assert!(
        owner_update_ledger.is_err(),
        "UPDATE on stock_ledger must be blocked by trigger"
    );

    let owner_delete_ledger = sqlx::query("DELETE FROM public.stock_ledger")
        .execute(&owner_pool)
        .await;
    assert!(
        owner_delete_ledger.is_err(),
        "DELETE on stock_ledger must be blocked by trigger"
    );

    let owner_truncate_ledger = sqlx::query("TRUNCATE TABLE public.stock_ledger")
        .execute(&owner_pool)
        .await;
    assert!(
        owner_truncate_ledger.is_err(),
        "TRUNCATE on stock_ledger must be blocked by trigger"
    );

    let owner_truncate_audit = sqlx::query("TRUNCATE TABLE public.audit_logs")
        .execute(&owner_pool)
        .await;
    assert!(
        owner_truncate_audit.is_err(),
        "TRUNCATE on audit_logs must be blocked by trigger"
    );
}

#[tokio::test]
async fn concurrent_idempotency_and_concurrent_dispatch_races_are_serialized() {
    let (_owner_pool, app_pool) = setup_pools().await;
    let (user_id, cat_id) = seed_actor_and_category(&app_pool).await;
    let (product_id, _) = insert_test_product(&app_pool, cat_id, "ea", false).await;

    // 1. concurrent identical idempotency_key retries under READ COMMITTED:
    // both tasks submit the exact same movement (+15 ea @ 10.000000 EUR) with the same idempotency_key.
    // exactly 1 ledger entry must be created, product balance must be 15.0000 (not 30.0000), and both calls return the same ledger id.
    let shared_idem_key = Uuid::new_v4();
    let pool_a = app_pool.clone();
    let pool_b = app_pool.clone();

    let task_a = tokio::spawn(async move {
        sqlx::query(
            "SELECT id, new_qty FROM public.record_stock_movement($1, $2, 'receive', $3, $4, 'PO-IDEM', 'initial stock', $5, NULL, 'op@test', '127.0.0.1')",
        )
        .bind(shared_idem_key)
        .bind(product_id)
        .bind(dec("15.0000"))
        .bind(dec("10.000000"))
        .bind(user_id)
        .fetch_one(&pool_a)
        .await
    });

    let task_b = tokio::spawn(async move {
        sqlx::query(
            "SELECT id, new_qty FROM public.record_stock_movement($1, $2, 'receive', $3, $4, 'PO-IDEM', 'initial stock', $5, NULL, 'op@test', '127.0.0.1')",
        )
        .bind(shared_idem_key)
        .bind(product_id)
        .bind(dec("15.0000"))
        .bind(dec("10.000000"))
        .bind(user_id)
        .fetch_one(&pool_b)
        .await
    });

    let res_a = task_a.await.unwrap().expect("task_a idempotent receive");
    let res_b = task_b.await.unwrap().expect("task_b idempotent receive");
    assert_eq!(res_a.get::<Uuid, _>("id"), res_b.get::<Uuid, _>("id"));
    assert_eq!(res_a.get::<Decimal, _>("new_qty"), dec("15.0000"));
    assert_eq!(res_b.get::<Decimal, _>("new_qty"), dec("15.0000"));

    // 2. reusing the same idempotency_key with a different delta or reason must fail with SQLSTATE P0409
    let mismatch_err = sqlx::query(
        "SELECT id FROM public.record_stock_movement($1, $2, 'receive', $3, $4, 'PO-IDEM', 'initial stock', $5, NULL, 'op@test', '127.0.0.1')",
    )
    .bind(shared_idem_key)
    .bind(product_id)
    .bind(dec("20.0000")) // different delta!
    .bind(dec("10.000000"))
    .bind(user_id)
    .fetch_one(&app_pool)
    .await
    .expect_err("payload mismatch must fail");

    let db_err = mismatch_err.as_database_error().expect("database error");
    assert_eq!(db_err.code().as_deref(), Some("P0409"));

    // 3. concurrent dispatch race: 15 units on hand, two concurrent transactions each try to dispatch -10.0000.
    // one must commit (leaving 5.0000 on hand) and the other must fail with P0422 (INSUFFICIENT_STOCK).
    let pool_d1 = app_pool.clone();
    let pool_d2 = app_pool.clone();

    let disp_1 = tokio::spawn(async move {
        sqlx::query(
            "SELECT new_qty FROM public.record_stock_movement($1, $2, 'dispatch', $3, NULL, 'SO-1', 'order 1', $4, NULL, 'op@test', '127.0.0.1')",
        )
        .bind(Uuid::new_v4())
        .bind(product_id)
        .bind(dec("-10.0000"))
        .bind(user_id)
        .fetch_one(&pool_d1)
        .await
    });

    let disp_2 = tokio::spawn(async move {
        sqlx::query(
            "SELECT new_qty FROM public.record_stock_movement($1, $2, 'dispatch', $3, NULL, 'SO-2', 'order 2', $4, NULL, 'op@test', '127.0.0.1')",
        )
        .bind(Uuid::new_v4())
        .bind(product_id)
        .bind(dec("-10.0000"))
        .bind(user_id)
        .fetch_one(&pool_d2)
        .await
    });

    let r1 = disp_1.await.unwrap();
    let r2 = disp_2.await.unwrap();
    assert!(
        (r1.is_ok() && r2.is_err()) || (r1.is_err() && r2.is_ok()),
        "exactly one concurrent dispatch of 10 from 15 must succeed and the other must fail"
    );

    let final_prod = sqlx::query(
        "SELECT quantity_on_hand, total_cost_basis_eur, unit_cost_eur FROM public.products WHERE id = $1",
    )
    .bind(product_id)
    .fetch_one(&app_pool)
    .await
    .expect("fetch final product balance");

    assert_eq!(
        final_prod.get::<Decimal, _>("quantity_on_hand"),
        dec("5.0000")
    );
    assert_eq!(
        final_prod.get::<Decimal, _>("total_cost_basis_eur"),
        dec("50.000000")
    );
    assert_eq!(
        final_prod.get::<Decimal, _>("unit_cost_eur"),
        dec("10.000000")
    );
}
