//! API key handling.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A provider API key.
///
/// The `Debug` implementation never reveals the key material, so a key cannot leak
/// through a derived debug log line or a panic message.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ApiKey(String);

impl ApiKey {
    /// Wraps key material.
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    /// Returns the key material for use in an outbound request header.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiKey([redacted])")
    }
}

impl fmt::Display for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl From<String> for ApiKey {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for ApiKey {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::ApiKey;

    #[test]
    fn debug_output_hides_key_material() {
        let key = ApiKey::new("super-secret-value");
        let rendered = format!("{key:?}");
        assert!(!rendered.contains("super-secret-value"));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn display_output_hides_key_material() {
        let key = ApiKey::new("super-secret-value");
        assert_eq!(key.to_string(), "[redacted]");
    }

    #[test]
    fn exposes_key_material_on_demand() {
        let key = ApiKey::new("super-secret-value");
        assert_eq!(key.expose(), "super-secret-value");
    }
}
