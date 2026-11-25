// stock ledger persistence records and public api responses

use crate::error::AppError;
use crate::models::product::CurrencyCode;
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MovementType {
    Initial,
    Receive,
    Dispatch,
    CycleCount,
    Damage,
}

impl MovementType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::Receive => "receive",
            Self::Dispatch => "dispatch",
            Self::CycleCount => "cycle_count",
            Self::Damage => "damage",
        }
    }
}

impl fmt::Display for MovementType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for MovementType {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "initial" => Ok(Self::Initial),
            "receive" => Ok(Self::Receive),
            "dispatch" => Ok(Self::Dispatch),
            "cycle_count" => Ok(Self::CycleCount),
            "damage" => Ok(Self::Damage),
            _ => Err(AppError::validation(
                "INVALID_MOVEMENT_TYPE",
                "Movement type must be one of: initial, receive, dispatch, cycle_count, damage.",
            )),
        }
    }
}

// persistence-only record (never derives Serialize; omits internal request_hash from api dto)
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct StockLedgerRecord {
    pub id: Uuid,
    pub idempotency_key: Uuid,
    pub request_hash: String,
    pub product_id: Uuid,
    pub movement_type: String,
    pub previous_qty: Decimal,
    pub delta: Decimal,
    pub new_qty: Decimal,
    pub currency_code: String,
    pub total_cost_basis_eur_snapshot: Decimal,
    pub unit_cost_eur_snapshot: Decimal,
    pub reference_code: Option<String>,
    pub reason: String,
    pub actor_user_id: Option<Uuid>,
    pub actor_api_key_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StockLedgerResponse {
    pub id: Uuid,
    pub idempotency_key: Uuid,
    pub product_id: Uuid,
    pub movement_type: MovementType,
    #[serde(with = "rust_decimal::serde::str")]
    pub previous_qty: Decimal,
    #[serde(with = "rust_decimal::serde::str")]
    pub delta: Decimal,
    #[serde(with = "rust_decimal::serde::str")]
    pub new_qty: Decimal,
    pub currency_code: CurrencyCode,
    #[serde(with = "rust_decimal::serde::str")]
    pub total_cost_basis_eur_snapshot: Decimal,
    #[serde(with = "rust_decimal::serde::str")]
    pub unit_cost_eur_snapshot: Decimal,
    pub reference_code: Option<String>,
    pub reason: String,
    pub actor_user_id: Option<Uuid>,
    pub actor_api_key_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

impl TryFrom<StockLedgerRecord> for StockLedgerResponse {
    type Error = AppError;

    fn try_from(record: StockLedgerRecord) -> Result<Self, Self::Error> {
        let movement_type = MovementType::from_str(&record.movement_type).map_err(|_| {
            AppError::internal(format!(
                "unexpected movement_type in db: {}",
                record.movement_type
            ))
        })?;
        let currency_code = CurrencyCode::from_str(&record.currency_code).map_err(|_| {
            AppError::internal(format!(
                "unexpected currency_code in db: {}",
                record.currency_code
            ))
        })?;

        Ok(Self {
            id: record.id,
            idempotency_key: record.idempotency_key,
            product_id: record.product_id,
            movement_type,
            previous_qty: record.previous_qty,
            delta: record.delta,
            new_qty: record.new_qty,
            currency_code,
            total_cost_basis_eur_snapshot: record.total_cost_basis_eur_snapshot,
            unit_cost_eur_snapshot: record.unit_cost_eur_snapshot,
            reference_code: record.reference_code,
            reason: record.reason,
            actor_user_id: record.actor_user_id,
            actor_api_key_id: record.actor_api_key_id,
            created_at: record.created_at,
        })
    }
}
