//! Verification token utilities for email confirmation and password reset.

use crate::config::AuthConfig;

/// Type of verification token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationTokenType {
    /// Email confirmation token.
    EmailConfirm,
    /// Password reset token.
    PasswordReset,
}

impl VerificationTokenType {
    /// Convert to string for database storage.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EmailConfirm => "email_confirm",
            Self::PasswordReset => "password_reset",
        }
    }
}

/// Build a verification link URL for email templates.
///
/// If `email_link_base_url` is set in config, returns `{base_url}{path}?token={token}`.
/// Otherwise returns `{path}?token={token}`.
pub fn verification_link_build(config: &AuthConfig, path: &str, token: &str) -> String {
    if let Some(ref base_url) = config.email_link_base_url {
        format!("{}{}?token={}", base_url, path, token)
    } else {
        format!("{}?token={}", path, token)
    }
}
