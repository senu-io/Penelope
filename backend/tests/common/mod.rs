// shared test setup, database pool connection, and fixture helpers

use rust_decimal::Decimal;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::str::FromStr;
use uuid::Uuid;

static MIGRATION_ONCE: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

pub fn dec(val: &str) -> Decimal {
    Decimal::from_str(val).expect("valid decimal literal")
}

pub async fn setup_pools() -> (PgPool, PgPool) {
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

                let raw_sql = include_str!("../../migrations/0001_initial_schema.sql");
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

pub async fn seed_actor_and_category(app_pool: &PgPool) -> (Uuid, Uuid) {
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

pub async fn insert_test_product(
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
