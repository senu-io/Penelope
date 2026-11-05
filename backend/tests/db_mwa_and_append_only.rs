// mwa costing, cycle-count inventory arithmetic, and append-only trigger tests

mod common;
use common::*;
use rust_decimal::Decimal;
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

#[tokio::test]
async fn mwa_costing_cycle_counts_and_append_only_triggers_work() {
    let (owner_pool, app_pool) = setup_pools().await;
    let (user_id, cat_id) = seed_actor_and_category(&app_pool).await;
    let (discrete_id, _) = insert_test_product(&app_pool, cat_id, "ea", false).await;
    let (frac_id, _) = insert_test_product(&app_pool, cat_id, "kg", true).await;

    // fractional movement on discrete ('ea') product must fail with P0422
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

    // fractional movement on 'kg' product succeeds
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

    // mwa 6-decimal precision and exact total_cost_basis_eur:
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

    // verify reporting-boundary line-item valuation round(total_cost_basis_eur, 2) = 0.41 EUR
    let val_row = sqlx::query(
        "SELECT pg_catalog.round(total_cost_basis_eur, 2) AS line_valuation_eur FROM public.products WHERE id = $1",
    )
    .bind(discrete_id)
    .fetch_one(&app_pool)
    .await
    .expect("query line valuation");
    assert_eq!(val_row.get::<Decimal, _>("line_valuation_eur"), dec("0.41"));

    // positive cycle count with non-terminating unit cost fraction uses prev_total_cost_basis_eur / prev_qty
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

    // now positive cycle count of +3 ea with null inbound cost must add round(1.000000 * 3 / 3, 6) = 1.000000 -> total 2.000000 (not 1.999999)
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

    // audit whitelist: record_audit_event allows valid pair, rejects 'stock_ledger' and unknown actions
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

    // append-only triggers reject update, delete, and truncate even when invoked by penelope_owner
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
