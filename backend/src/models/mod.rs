// persistence records (*Record) and public api dtos (*Response) with normalized decimal validators

pub mod audit;
pub mod ledger;
pub mod product;
pub mod user;

use crate::error::AppError;
use rust_decimal::{Decimal, RoundingStrategy};

pub use audit::{AuditLogRecord, AuditLogResponse};
pub use ledger::{MovementType, StockLedgerRecord, StockLedgerResponse};
pub use product::{
    BaseUnit, CategoryRecord, CategoryResponse, CurrencyCode, ProductRecord, ProductResponse,
};
pub use user::{
    ApiKeyRecord, ApiKeyResponse, ApiKeyScope, Role, SessionRecord, UserRecord, UserResponse,
};

fn max_quantity() -> Decimal {
    Decimal::from(1_000_000_000i64)
}

fn max_unit_amount() -> Decimal {
    Decimal::from(10_000_000_000i64)
}

// normalize trailing zeroes and verify quantity scale (<= 4 decimals, or integer for discrete units)
pub fn validate_quantity(val: Decimal, allow_fractional: bool) -> Result<Decimal, AppError> {
    if val < Decimal::ZERO || val > max_quantity() {
        return Err(AppError::validation(
            "INVALID_QUANTITY",
            "Quantity must be between 0 and 1,000,000,000.",
        ));
    }

    let mut norm = val.normalize();
    if norm.is_zero() {
        norm = Decimal::ZERO;
    }
    if norm.scale() > 4 {
        return Err(AppError::validation(
            "PRECISION_EXCEEDED",
            "Quantity cannot exceed 4 decimal places.",
        ));
    }
    if !allow_fractional && norm.scale() > 0 {
        return Err(AppError::validation(
            "FRACTIONAL_NOT_ALLOWED",
            "Discrete unit of measure requires a whole number quantity.",
        ));
    }
    Ok(norm)
}

// normalize trailing zeroes and verify non-zero stock movement delta
pub fn validate_movement_delta(val: Decimal, allow_fractional: bool) -> Result<Decimal, AppError> {
    if val.is_zero() || val.abs() > max_quantity() {
        return Err(AppError::validation(
            "INVALID_MOVEMENT_DELTA",
            "Movement delta must be non-zero and within +/- 1,000,000,000.",
        ));
    }

    let norm = val.normalize();
    if norm.scale() > 4 {
        return Err(AppError::validation(
            "PRECISION_EXCEEDED",
            "Quantity delta cannot exceed 4 decimal places.",
        ));
    }
    if !allow_fractional && norm.scale() > 0 {
        return Err(AppError::validation(
            "FRACTIONAL_NOT_ALLOWED",
            "Discrete unit of measure does not allow fractional movements.",
        ));
    }
    Ok(norm)
}

// normalize trailing zeroes and verify unit cost scale (<= 6 decimals in eur)
pub fn validate_unit_cost_eur(val: Decimal) -> Result<Decimal, AppError> {
    if val < Decimal::ZERO || val > max_unit_amount() {
        return Err(AppError::validation(
            "INVALID_INBOUND_COST",
            "Unit cost must be between 0 and 10,000,000,000 EUR.",
        ));
    }

    let mut norm = val.normalize();
    if norm.is_zero() {
        norm = Decimal::ZERO;
    }
    if norm.scale() > 6 {
        return Err(AppError::validation(
            "COST_PRECISION_EXCEEDED",
            "Unit cost cannot exceed 6 decimal places.",
        ));
    }
    Ok(norm)
}

// normalize trailing zeroes and verify selling price scale (<= 2 decimals in eur)
pub fn validate_unit_price_eur(val: Decimal) -> Result<Decimal, AppError> {
    if val < Decimal::ZERO || val > max_unit_amount() {
        return Err(AppError::validation(
            "INVALID_UNIT_PRICE",
            "Unit price must be between 0 and 10,000,000,000 EUR.",
        ));
    }

    let mut norm = val.normalize();
    if norm.is_zero() {
        norm = Decimal::ZERO;
    }
    if norm.scale() > 2 {
        return Err(AppError::validation(
            "PRICE_PRECISION_EXCEEDED",
            "Unit price cannot exceed 2 decimal places.",
        ));
    }
    Ok(norm)
}

// round line-item cost basis to 2 decimal places using half-away-from-zero
pub fn round_line_valuation_eur(total_cost_basis_eur: Decimal) -> Decimal {
    total_cost_basis_eur.round_dp_with_strategy(2, RoundingStrategy::MidpointAwayFromZero)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn dec(s: &str) -> Decimal {
        Decimal::from_str(s).expect("valid decimal")
    }

    #[test]
    fn quantity_validation_normalizes_trailing_zeroes() {
        // 1.23000 normalizes to scale 2 and passes fractional check
        let q = validate_quantity(dec("1.23000"), true).expect("trailing zeroes accepted");
        assert_eq!(q, dec("1.23"));

        // 15.0000 normalizes to scale 0 and passes discrete check
        let discrete = validate_quantity(dec("15.0000"), false).expect("whole number accepted");
        assert_eq!(discrete, dec("15"));

        // 1.23456 has 5 significant decimals -> PRECISION_EXCEEDED
        let (_, code, _, _) = validate_quantity(dec("1.23456"), true)
            .unwrap_err()
            .to_error_payload();
        assert_eq!(code, "PRECISION_EXCEEDED");

        // 1.5000 on discrete unit -> FRACTIONAL_NOT_ALLOWED
        let (_, code_disc, _, _) = validate_quantity(dec("1.5000"), false)
            .unwrap_err()
            .to_error_payload();
        assert_eq!(code_disc, "FRACTIONAL_NOT_ALLOWED");

        // negative quantity rejected
        let (_, code_neg, _, _) = validate_quantity(dec("-1"), true)
            .unwrap_err()
            .to_error_payload();
        assert_eq!(code_neg, "INVALID_QUANTITY");
    }

    #[test]
    fn movement_delta_validation_checks_zero_and_scale() {
        let (_, zero_code, _, _) = validate_movement_delta(dec("0.0000"), true)
            .unwrap_err()
            .to_error_payload();
        assert_eq!(zero_code, "INVALID_MOVEMENT_DELTA");

        let neg = validate_movement_delta(dec("-2.50000"), true).expect("valid negative delta");
        assert_eq!(neg, dec("-2.5"));

        let (_, disc_code, _, _) = validate_movement_delta(dec("-0.5"), false)
            .unwrap_err()
            .to_error_payload();
        assert_eq!(disc_code, "FRACTIONAL_NOT_ALLOWED");
    }

    #[test]
    fn unit_cost_and_price_validation_enforce_scales() {
        assert_eq!(
            validate_unit_cost_eur(dec("0.33333300")).expect("6 decimals after normalize"),
            dec("0.333333")
        );
        let (_, cost_code, _, _) = validate_unit_cost_eur(dec("0.1234567"))
            .unwrap_err()
            .to_error_payload();
        assert_eq!(cost_code, "COST_PRECISION_EXCEEDED");

        assert_eq!(
            validate_unit_price_eur(dec("19.9900")).expect("2 decimals after normalize"),
            dec("19.99")
        );
        let (_, price_code, _, _) = validate_unit_price_eur(dec("19.999"))
            .unwrap_err()
            .to_error_payload();
        assert_eq!(price_code, "PRICE_PRECISION_EXCEEDED");
    }

    #[test]
    fn line_valuation_rounds_half_away_from_zero() {
        assert_eq!(round_line_valuation_eur(dec("0.410000")), dec("0.41"));
        assert_eq!(round_line_valuation_eur(dec("1.005000")), dec("1.01"));
        assert_eq!(round_line_valuation_eur(dec("2.025000")), dec("2.03"));
    }

    #[test]
    fn negative_zero_normalizes_to_zero_while_negative_values_fail() {
        let neg_zero = dec("-0.00");
        let q = validate_quantity(neg_zero, false).expect("-0.00 should be valid zero");
        assert!(!q.is_sign_negative());
        assert_eq!(q, Decimal::ZERO);

        let c = validate_unit_cost_eur(neg_zero).expect("-0.00 cost should be valid zero");
        assert!(!c.is_sign_negative());
        assert_eq!(c, Decimal::ZERO);

        let p = validate_unit_price_eur(neg_zero).expect("-0.00 price should be valid zero");
        assert!(!p.is_sign_negative());
        assert_eq!(p, Decimal::ZERO);

        assert!(validate_quantity(dec("-0.01"), true).is_err());
        assert!(validate_unit_cost_eur(dec("-0.01")).is_err());
        assert!(validate_unit_price_eur(dec("-0.01")).is_err());
    }
}
