// postgres role separation, least privilege, and function boundary tests

mod common;
use common::*;
use rust_decimal::Decimal;
use sqlx::Row;
use uuid::Uuid;

#[tokio::test]
async fn role_separation_and_privilege_boundaries_hold() {
    let (owner_pool, app_pool) = setup_pools().await;
    let (user_id, cat_id) = seed_actor_and_category(&app_pool).await;
    let (product_id, _sku) = insert_test_product(&app_pool, cat_id, "ea", false).await;

    // verify neither penelope_owner nor penelope_app is a superuser
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

    // penelope_app cannot insert product with non-zero quantity_on_hand or cost
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

    // penelope_app cannot directly update quantity_on_hand, total_cost_basis_eur, or unit_cost_eur
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

    // penelope_app cannot directly insert into stock_ledger or audit_logs
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

    // actor attribution & api key scope checks in record_stock_movement and record_audit_event
    let write_key_id = Uuid::new_v4();
    let read_only_key_id = Uuid::new_v4();
    let revoked_key_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO public.api_keys (id, name, key_prefix, key_hash, role_scope, created_by)
        VALUES
            ($1, 'Scanner Write Key', 'pen_live_0001', $4, 'operator', $7),
            ($2, 'Dashboard Read Key', 'pen_live_0002', $5, 'readonly', $7),
            ($3, 'Revoked Write Key', 'pen_live_0003', $6, 'manager', $7)
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

    // both-null actors on record_stock_movement must fail with P0422 (ACTOR_REQUIRED)
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

    // both-present actors on record_stock_movement must fail with P0422 (AMBIGUOUS_ACTOR)
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

    // api key lacking write scope or revoked must fail with P0403
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

    // active api key with write:stock scope succeeds
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

    // record_audit_event rejects both-present actors and rejects missing actor on authenticated actions
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
