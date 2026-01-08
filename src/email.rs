//! Email validation and normalization.

use crate::error::AuthError;
use email_address::EmailAddress;
use std::str::FromStr;

/// Validate and normalize an email address.
///
/// - Trims whitespace
/// - Validates RFC 5322 compliance
/// - Lowercases the domain (and local part for consistency)
///
/// Returns the normalized email string.
pub fn email_normalize(email: &str) -> Result<String, AuthError> {
    let trimmed = email.trim();

    // Validate using email_address crate (RFC 5322 compliant)
    let parsed = EmailAddress::from_str(trimmed).map_err(|_| AuthError::InvalidEmail)?;

    // Normalize: lowercase the entire email for consistent lookups
    // Note: technically only domain should be case-insensitive per RFC,
    // but most providers treat local parts as case-insensitive too
    let normalized = parsed.as_str().to_lowercase();

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_email() {
        let result = email_normalize("user@example.com");
        assert_eq!(result.unwrap(), "user@example.com");
    }

    #[test]
    fn test_normalizes_case() {
        let result = email_normalize("User@Example.COM");
        assert_eq!(result.unwrap(), "user@example.com");
    }

    #[test]
    fn test_trims_whitespace() {
        let result = email_normalize("  user@example.com  ");
        assert_eq!(result.unwrap(), "user@example.com");
    }

    #[test]
    fn test_rejects_invalid_no_at() {
        let result = email_normalize("userexample.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_invalid_no_domain() {
        let result = email_normalize("user@");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_invalid_no_local() {
        let result = email_normalize("@example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_multiple_at() {
        let result = email_normalize("user@@example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_empty() {
        let result = email_normalize("");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_whitespace_only() {
        let result = email_normalize("   ");
        assert!(result.is_err());
    }
}
