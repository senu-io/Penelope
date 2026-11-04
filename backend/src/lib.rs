pub mod config;
pub mod error;

pub use config::{AppConfig, KeyRing};
pub use error::AppError;

pub fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_version_is_non_empty() {
        assert_eq!(crate_version(), "0.1.0");
    }
}
