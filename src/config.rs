use std::{env, time::Duration};
use thiserror::Error;

/// Errors when loading or validating authentication configuration.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthConfigError {
    /// Required environment variable was not provided.
    #[error("missing env var {0}")]
    MissingEnv(&'static str),

    /// Configuration failed validation checks.
    #[error("invalid auth config: {0}")]
    Invalid(String),
}

/// Cookie SameSite policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieSameSite {
    /// Cookies are sent in all contexts
    None,
    /// Cookies are sent in same-site and cross-site top-level navigations
    Lax,
    /// Cookies are only sent in same-site contexts
    Strict,
}

/// Authentication configuration
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Secret key for signing JWTs
    pub jwt_secret: String,

    /// Access token expiry duration (default: 15 minutes)
    pub access_token_expiry: Duration,

    /// Refresh token expiry duration (default: 7 days)
    pub refresh_token_expiry: Duration,

    /// JWT issuer claim (default: "auth")
    pub jwt_issuer: String,

    /// JWT audience claim (default: "authenticated")
    pub jwt_audience: String,

    /// Minimum password length (default: 8)
    pub password_min_length: usize,

    /// Maximum password length (default: 128)
    pub password_max_length: usize,

    /// Whether passwords must contain at least one letter (default: true)
    pub password_require_letter: bool,

    /// Whether passwords must contain at least one number (default: true)
    pub password_require_number: bool,

    /// Cookie name for access token (default: "access_token")
    pub cookie_access_token_name: String,

    /// Cookie name for refresh token (default: "refresh_token")
    pub cookie_refresh_token_name: String,

    /// Cookie domain (optional, default: None)
    pub cookie_domain: Option<String>,

    /// Cookie path (default: "/")
    pub cookie_path: String,

    /// Cookie secure flag - only send over HTTPS (default: true in production, false in debug)
    pub cookie_secure: bool,

    /// Cookie SameSite policy (default: Lax)
    pub cookie_same_site: CookieSameSite,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt_secret: String::new(), // Must be provided by user
            access_token_expiry: Duration::from_secs(15 * 60), // 15 minutes
            refresh_token_expiry: Duration::from_secs(7 * 24 * 60 * 60), // 7 days
            jwt_issuer: "fast-auth".to_string(),
            jwt_audience: "authenticated".to_string(),
            password_min_length: 8,
            password_max_length: 128,
            password_require_letter: true,
            password_require_number: true,
            cookie_access_token_name: "access_token".to_string(),
            cookie_refresh_token_name: "refresh_token".to_string(),
            cookie_domain: None,
            cookie_path: "/".to_string(),
            cookie_secure: !cfg!(debug_assertions), // true in release, false in debug
            cookie_same_site: CookieSameSite::Lax,
        }
    }
}

impl AuthConfig {
    /// Load configuration from environment variables and validate it.
    pub fn from_env() -> Result<Self, AuthConfigError> {
        let jwt_secret = env::var("AUTH_JWT_SECRET")
            .map_err(|_| AuthConfigError::MissingEnv("AUTH_JWT_SECRET"))?;

        let config = Self {
            jwt_secret,
            ..Self::default()
        };

        config.validate()?;
        Ok(config)
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), AuthConfigError> {
        if self.jwt_secret.is_empty() {
            return Err(AuthConfigError::Invalid(
                "JWT secret cannot be empty".to_string(),
            ));
        }

        if self.jwt_secret.len() < 32 {
            return Err(AuthConfigError::Invalid(
                "JWT secret must be at least 32 characters".to_string(),
            ));
        }

        if self.access_token_expiry.as_secs() == 0 {
            return Err(AuthConfigError::Invalid(
                "Access token expiry must be greater than 0".to_string(),
            ));
        }

        if self.refresh_token_expiry.as_secs() == 0 {
            return Err(AuthConfigError::Invalid(
                "Refresh token expiry must be greater than 0".to_string(),
            ));
        }

        if self.password_min_length == 0 {
            return Err(AuthConfigError::Invalid(
                "Minimum password length must be greater than 0".to_string(),
            ));
        }

        if self.password_max_length < self.password_min_length {
            return Err(AuthConfigError::Invalid(
                "Maximum password length must be greater than or equal to minimum password length"
                    .to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn with_env<F: FnOnce()>(key: &str, value: Option<&str>, f: F) {
        let original = env::var(key).ok();
        match value {
            Some(v) => unsafe { env::set_var(key, v) },
            None => unsafe { env::remove_var(key) },
        }
        f();
        match original {
            Some(v) => unsafe { env::set_var(key, v) },
            None => unsafe { env::remove_var(key) },
        }
    }

    #[test]
    #[serial]
    fn from_env_loads_secret_and_validates() {
        with_env("AUTH_JWT_SECRET", Some(&"a".repeat(32)), || {
            let cfg = AuthConfig::from_env().unwrap();
            assert_eq!(cfg.jwt_secret.len(), 32);
        });
    }

    #[test]
    #[serial]
    fn from_env_errors_when_missing_secret() {
        with_env("AUTH_JWT_SECRET", None, || {
            let err = AuthConfig::from_env().unwrap_err();
            assert_eq!(err, AuthConfigError::MissingEnv("AUTH_JWT_SECRET"));
        });
    }
}
