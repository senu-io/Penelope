use crate::error::AppError;
use crate::models::round_line_valuation_eur;
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BaseUnit {
    Ea,
    Box,
    Pallet,
    Kg,
    L,
    M,
}

impl BaseUnit {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ea => "ea",
            Self::Box => "box",
            Self::Pallet => "pallet",
            Self::Kg => "kg",
            Self::L => "l",
            Self::M => "m",
        }
    }

    pub fn supports_fractional(&self) -> bool {
        matches!(self, Self::Kg | Self::L | Self::M)
    }
}

impl fmt::Display for BaseUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for BaseUnit {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ea" => Ok(Self::Ea),
            "box" => Ok(Self::Box),
            "pallet" => Ok(Self::Pallet),
            "kg" => Ok(Self::Kg),
            "l" => Ok(Self::L),
            "m" => Ok(Self::M),
            _ => Err(AppError::validation(
                "INVALID_BASE_UNIT",
                "Base unit must be one of: ea, box, pallet, kg, l, m.",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CurrencyCode {
    Eur,
}

impl CurrencyCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Eur => "EUR",
        }
    }
}

impl fmt::Display for CurrencyCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CurrencyCode {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_uppercase().as_str() {
            "EUR" => Ok(Self::Eur),
            _ => Err(AppError::validation(
                "UNSUPPORTED_CURRENCY",
                "Only EUR currency is supported.",
            )),
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CategoryRecord {
    pub id: Uuid,
    pub name: String,
    pub code: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CategoryResponse {
    pub id: Uuid,
    pub name: String,
    pub code: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
}

impl From<CategoryRecord> for CategoryResponse {
    fn from(record: CategoryRecord) -> Self {
        Self {
            id: record.id,
            name: record.name,
            code: record.code,
            description: record.description,
            created_at: record.created_at,
        }
    }
}

// persistence-only record (never derives Serialize so encrypted_notes ciphertext cannot leak)
#[derive(Clone, sqlx::FromRow)]
pub struct ProductRecord {
    pub id: Uuid,
    pub sku: String,
    pub barcode: Option<String>,
    pub name: String,
    pub description: String,
    pub category_id: Uuid,
    pub base_unit: String,
    pub allow_fractional: bool,
    pub bin_location: String,
    pub quantity_on_hand: Decimal,
    pub reorder_point: Decimal,
    pub currency_code: String,
    pub total_cost_basis_eur: Decimal,
    pub unit_cost_eur: Decimal,
    pub unit_price_eur: Decimal,
    pub encrypted_notes: Option<Vec<u8>>,
    pub is_archived: bool,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl fmt::Debug for ProductRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProductRecord")
            .field("id", &self.id)
            .field("sku", &self.sku)
            .field("name", &self.name)
            .field("quantity_on_hand", &self.quantity_on_hand)
            .field(
                "encrypted_notes_len",
                &self.encrypted_notes.as_ref().map(Vec::len),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductResponse {
    pub id: Uuid,
    pub sku: String,
    pub barcode: Option<String>,
    pub name: String,
    pub description: String,
    pub category_id: Uuid,
    pub base_unit: BaseUnit,
    pub allow_fractional: bool,
    pub bin_location: String,
    #[serde(with = "rust_decimal::serde::str")]
    pub quantity_on_hand: Decimal,
    #[serde(with = "rust_decimal::serde::str")]
    pub reorder_point: Decimal,
    pub currency_code: CurrencyCode,
    #[serde(with = "rust_decimal::serde::str")]
    pub total_cost_basis_eur: Decimal,
    #[serde(with = "rust_decimal::serde::str")]
    pub line_valuation_eur: Decimal,
    #[serde(with = "rust_decimal::serde::str")]
    pub unit_cost_eur: Decimal,
    #[serde(with = "rust_decimal::serde::str")]
    pub unit_price_eur: Decimal,
    pub has_encrypted_notes: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub is_archived: bool,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl ProductResponse {
    // notes should only be passed after decrypting for authorized roles (Admin / Manager)
    pub fn from_record(
        record: ProductRecord,
        decrypted_notes: Option<String>,
    ) -> Result<Self, AppError> {
        let base_unit = BaseUnit::from_str(&record.base_unit).map_err(|_| {
            AppError::internal(format!("unexpected base_unit in db: {}", record.base_unit))
        })?;
        let currency_code = CurrencyCode::from_str(&record.currency_code).map_err(|_| {
            AppError::internal(format!(
                "unexpected currency_code in db: {}",
                record.currency_code
            ))
        })?;
        let line_valuation_eur = round_line_valuation_eur(record.total_cost_basis_eur);
        let has_encrypted_notes = record.encrypted_notes.is_some();

        Ok(Self {
            id: record.id,
            sku: record.sku,
            barcode: record.barcode,
            name: record.name,
            description: record.description,
            category_id: record.category_id,
            base_unit,
            allow_fractional: record.allow_fractional,
            bin_location: record.bin_location,
            quantity_on_hand: record.quantity_on_hand,
            reorder_point: record.reorder_point,
            currency_code,
            total_cost_basis_eur: record.total_cost_basis_eur,
            line_valuation_eur,
            unit_cost_eur: record.unit_cost_eur,
            unit_price_eur: record.unit_price_eur,
            has_encrypted_notes,
            notes: decrypted_notes,
            is_archived: record.is_archived,
            updated_at: record.updated_at,
            created_at: record.created_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn dec(s: &str) -> Decimal {
        Decimal::from_str(s).expect("valid decimal")
    }

    #[test]
    fn base_unit_fractional_rules_hold() {
        assert!(!BaseUnit::Ea.supports_fractional());
        assert!(!BaseUnit::Box.supports_fractional());
        assert!(!BaseUnit::Pallet.supports_fractional());
        assert!(BaseUnit::Kg.supports_fractional());
        assert!(BaseUnit::L.supports_fractional());
        assert!(BaseUnit::M.supports_fractional());
    }

    #[test]
    fn product_response_computes_line_valuation_and_hides_raw_ciphertext() {
        let now = Utc::now();
        let rec = ProductRecord {
            id: Uuid::new_v4(),
            sku: "HV-204-BRG".to_string(),
            barcode: Some("890142500192".to_string()),
            name: "Sealed Roller Bearing 6204".to_string(),
            description: "High-load radial bearing".to_string(),
            category_id: Uuid::new_v4(),
            base_unit: "ea".to_string(),
            allow_fractional: false,
            bin_location: "A-04-02".to_string(),
            quantity_on_hand: dec("14.0000"),
            reorder_point: dec("20.0000"),
            currency_code: "EUR".to_string(),
            total_cost_basis_eur: dec("258.305000"),
            unit_cost_eur: dec("18.450357"),
            unit_price_eur: dec("34.50"),
            encrypted_notes: Some(vec![0x01, 0x00, 0x01, 0xAA, 0xBB, 0xCC]),
            is_archived: false,
            updated_at: now,
            created_at: now,
        };

        let res_operator = ProductResponse::from_record(rec.clone(), None).expect("operator dto");
        assert_eq!(res_operator.line_valuation_eur, dec("258.31"));
        assert!(res_operator.has_encrypted_notes);
        assert!(res_operator.notes.is_none());

        let json_op = serde_json::to_string(&res_operator).expect("serialize product dto");
        assert!(!json_op.contains("\"encrypted_notes\""));
        assert!(!json_op.contains("\"notes\""));
        assert!(json_op.contains("\"line_valuation_eur\":\"258.31\""));

        let res_manager =
            ProductResponse::from_record(rec, Some("Supplier contract #42".to_string()))
                .expect("manager dto");
        assert_eq!(res_manager.notes.as_deref(), Some("Supplier contract #42"));
    }
}
