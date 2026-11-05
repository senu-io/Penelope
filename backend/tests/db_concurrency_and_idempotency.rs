// idempotency replay, payload hash collision, and concurrent dispatch serialization tests

mod common;
use common::*;
use rust_decimal::Decimal;
use sqlx::Row;
use uuid::Uuid;

#[tokio::test]
async fn concurrent_idempotency_and_concurrent_dispatch_races_are_serialized() {
    let (_owner_pool, app_pool) = setup_pools().await;
    let (user_id, cat_id) = seed_actor_and_category(&app_pool).await;
    let (product_id, _) = insert_test_product(&app_pool, cat_id, "ea", false).await;

    // concurrent identical idempotency_key retries under READ COMMITTED:
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

    // reusing the same idempotency_key with a different delta or reason must fail with SQLSTATE P0409
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

    // concurrent dispatch race: 15 units on hand, two concurrent transactions each try to dispatch -10.0000.
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
