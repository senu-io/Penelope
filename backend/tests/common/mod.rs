use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use penelope_backend::config::{verify_pool_role, AppConfig};
use penelope_backend::crypto;
use rust_decimal::Decimal;
use secrecy::SecretString;
use serde_json::{json, Value};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::str::FromStr;
use tower::ServiceExt;
use uuid::Uuid;

static MIGRATION_ONCE: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

#[allow(dead_code)]
pub fn dec(val: &str) -> Decimal {
    Decimal::from_str(val).expect("valid decimal literal")
}

pub async fn setup_pools() -> (PgPool, PgPool) {
    dotenvy::dotenv().ok();

    let migration_url = std::env::var("MIGRATION_DATABASE_URL")
        .expect("MIGRATION_DATABASE_URL must be set in .env");
    let app_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env");

    let owner_opts = PgConnectOptions::from_str(&migration_url).expect("valid migration url");
    let app_opts =
        PgConnectOptions::from_str(&app_url).expect("valid DATABASE_URL for penelope_app");

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

                verify_pool_role(&mig_pool, "penelope_owner")
                    .await
                    .expect("mig_pool must connect as penelope_owner before running migrations");

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

    // verify connection role identities before running any test queries
    verify_pool_role(&owner_pool, "penelope_owner")
        .await
        .expect("owner_pool must connect as penelope_owner");
    verify_pool_role(&app_pool, "penelope_app")
        .await
        .expect("app_pool must connect as penelope_app");

    (owner_pool, app_pool)
}

#[allow(dead_code)]
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

#[allow(dead_code)]
pub async fn insert_test_product(
    app_pool: &PgPool,
    category_id: Uuid,
    base_unit: &str,
    allow_fractional: bool,
) -> (Uuid, String) {
    let product_id = Uuid::new_v4();
    let sku = format!("SKU-{}", &Uuid::new_v4().simple().to_string()[..10]).to_uppercase();
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

#[allow(dead_code)]
pub fn test_app_config(cookie_secure: bool) -> AppConfig {
    let key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let session_hex = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    AppConfig::from_pairs([
        (
            "DATABASE_URL",
            "postgres://penelope_app:penelope_app_password@127.0.0.1:5432/penelope_db".to_string(),
        ),
        ("FRONTEND_ORIGIN", "http://localhost:5173".to_string()),
        ("SESSION_SECRET", session_hex.to_string()),
        ("PENELOPE_ACTIVE_KEY_ID", "1".to_string()),
        ("PENELOPE_ENCRYPTION_KEYS", format!("1:{key_hex}")),
        (
            "COOKIE_SECURE",
            if cookie_secure { "true" } else { "false" }.to_string(),
        ),
        ("RATE_LIMIT_AUTH_PER_MIN", "60".to_string()),
        ("RATE_LIMIT_API_PER_MIN", "500".to_string()),
    ])
    .expect("valid test config")
}

#[allow(dead_code)]
pub async fn seed_user(pool: &PgPool, role: &str, is_active: bool, raw_pw: &str) -> (Uuid, String) {
    let user_id = Uuid::new_v4();
    let email = format!("{role}_{}@penelope.local", Uuid::new_v4().simple());
    let password = SecretString::new(raw_pw.to_string());
    let hash = crypto::hash_password(&password).expect("hash user password");

    sqlx::query(
        r#"
        INSERT INTO public.users (id, email, full_name, password_hash, role, is_active)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(user_id)
    .bind(&email)
    .bind(format!("Test {}", role))
    .bind(&hash)
    .bind(role)
    .bind(is_active)
    .execute(pool)
    .await
    .expect("insert seeded user");

    (user_id, email)
}

#[allow(dead_code)]
pub async fn seed_api_key(pool: &PgPool, created_by: Uuid, role_scope: &str) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let (raw_key, key_hash) = crypto::generate_api_key();
    let key_prefix = &raw_key[..17];
    sqlx::query(
        r#"
        INSERT INTO public.api_keys (id, name, key_prefix, key_hash, role_scope, created_by)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(id)
    .bind(format!("Test Key {role_scope}"))
    .bind(key_prefix)
    .bind(&key_hash)
    .bind(role_scope)
    .bind(created_by)
    .execute(pool)
    .await
    .expect("seed api key");

    (id, raw_key)
}

#[allow(dead_code)]
pub fn extract_cookie_pair(set_cookie: &str) -> String {
    set_cookie
        .split(';')
        .next()
        .map(str::trim)
        .expect("cookie pair")
        .to_string()
}

#[allow(dead_code)]
pub async fn login_cookie(app: &axum::Router, email: &str, password: &str) -> String {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "email": email, "password": password }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    extract_cookie_pair(
        res.headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap(),
    )
}

#[allow(dead_code)]
pub async fn json_body(res: axum::response::Response) -> Value {
    let bytes = to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("parse json body")
}
