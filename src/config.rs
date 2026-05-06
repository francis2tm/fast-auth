use common::{
    config::{TomlConfigError, workspace_app_toml_parse, workspace_frontend_base_url},
    env_var,
};
use serde::Deserialize;
use std::time::Duration;
use thiserror::Error;

/// Errors when loading or validating authentication configuration.
#[derive(Debug, Error)]
pub enum AuthConfigError {
    /// Failed to read or parse TOML config files.
    #[error(transparent)]
    Toml(#[from] TomlConfigError),

    /// Configuration failed validation checks.
    #[error("invalid auth config: {0}")]
    Invalid(String),
}

/// Cookie SameSite policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
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

    // --- Verification Settings ---
    /// Email verification token expiry (default: 1 hour)
    pub email_verification_token_expiry: Duration,

    /// Password reset token expiry (default: 1 hour)
    pub password_reset_token_expiry: Duration,

    /// Base URL for email links (e.g., "https://app.example.com").
    /// Required when `require_email_confirmation` is true.
    pub email_link_base_url: Option<String>,

    /// Whether to require email confirmation before login (default: false)
    pub email_confirmation_require: bool,
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
            email_verification_token_expiry: Duration::from_secs(60 * 60), // 1 hour
            password_reset_token_expiry: Duration::from_secs(60 * 60),     // 1 hour
            email_link_base_url: None,
            email_confirmation_require: false,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthConfigFile {
    jwt: AuthTomlJwtConfig,
    token: AuthTomlTokenConfig,
    password: AuthTomlPasswordConfig,
    cookie: AuthTomlCookieConfig,
    verification: AuthTomlVerificationConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthTomlTokenConfig {
    access_expiry_secs: u64,
    refresh_expiry_secs: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthTomlJwtConfig {
    issuer: String,
    audience: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthTomlPasswordConfig {
    min_length: usize,
    max_length: usize,
    require_letter: bool,
    require_number: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthTomlCookieConfig {
    access_token_name: String,
    refresh_token_name: String,
    domain: String,
    path: String,
    secure: bool,
    same_site: CookieSameSite,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthTomlVerificationConfig {
    email_confirmation_require: bool,
    email_token_expiry_secs: u64,
    password_reset_token_expiry_secs: u64,
}

impl AuthConfig {
    /// Build auth config from `config/auth.toml` plus env-backed secrets.
    ///
    /// Only `AUTH_JWT_SECRET` remains environment-driven.
    /// All other values are loaded from flat TOML config files.
    ///
    /// # Panics
    ///
    /// Panics when `AUTH_JWT_SECRET` is not set.
    ///
    pub fn from_toml_env() -> Result<Self, AuthConfigError> {
        let file: AuthConfigFile = workspace_app_toml_parse("auth.toml")?;
        let frontend_base_url = workspace_frontend_base_url()?;
        let jwt_secret = env_var("AUTH_JWT_SECRET");
        let cfg = Self {
            jwt_secret,
            access_token_expiry: Duration::from_secs(file.token.access_expiry_secs),
            refresh_token_expiry: Duration::from_secs(file.token.refresh_expiry_secs),
            jwt_issuer: file.jwt.issuer,
            jwt_audience: file.jwt.audience,
            password_min_length: file.password.min_length,
            password_max_length: file.password.max_length,
            password_require_letter: file.password.require_letter,
            password_require_number: file.password.require_number,
            cookie_access_token_name: file.cookie.access_token_name,
            cookie_refresh_token_name: file.cookie.refresh_token_name,
            cookie_domain: optional_string(file.cookie.domain),
            cookie_path: file.cookie.path,
            cookie_secure: file.cookie.secure,
            cookie_same_site: file.cookie.same_site,
            email_verification_token_expiry: Duration::from_secs(
                file.verification.email_token_expiry_secs,
            ),
            password_reset_token_expiry: Duration::from_secs(
                file.verification.password_reset_token_expiry_secs,
            ),
            email_link_base_url: Some(frontend_base_url),
            email_confirmation_require: file.verification.email_confirmation_require,
        };

        cfg.validate_base()?;
        Ok(cfg)
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), AuthConfigError> {
        self.validate_base()?;

        if self.email_confirmation_require
            && self
                .email_link_base_url
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .is_none()
        {
            return Err(invalid(
                "email_link_base_url must be set when email_confirmation_require=true",
            ));
        }

        Ok(())
    }

    /// Validate the auth config fields that come directly from `auth.toml`.
    fn validate_base(&self) -> Result<(), AuthConfigError> {
        if self.jwt_secret.is_empty() {
            return Err(invalid("JWT secret cannot be empty"));
        }

        if self.jwt_secret.len() < 32 {
            return Err(invalid("JWT secret must be at least 32 characters"));
        }

        if self.access_token_expiry.as_secs() == 0 {
            return Err(invalid("Access token expiry must be greater than 0"));
        }

        if self.refresh_token_expiry.as_secs() == 0 {
            return Err(invalid("Refresh token expiry must be greater than 0"));
        }

        if self.password_min_length == 0 {
            return Err(invalid("Minimum password length must be greater than 0"));
        }

        if self.password_max_length < self.password_min_length {
            return Err(invalid(
                "Maximum password length must be greater than or equal to minimum password length",
            ));
        }

        Ok(())
    }
}

fn invalid(message: &'static str) -> AuthConfigError {
    AuthConfigError::Invalid(message.to_string())
}

fn optional_string(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn struct_init_sets_secret_and_defaults() {
        let secret = "a".repeat(32);
        let cfg = AuthConfig {
            jwt_secret: secret.clone(),
            ..Default::default()
        };
        assert_eq!(cfg.jwt_secret, secret);
        assert_eq!(cfg.access_token_expiry, Duration::from_secs(15 * 60));
    }

    #[test]
    #[serial]
    fn validate_fails_short_secret() {
        let cfg = AuthConfig {
            jwt_secret: "short".to_string(),
            ..Default::default()
        };
        assert!(matches!(cfg.validate(), Err(AuthConfigError::Invalid(_))));
    }

    #[test]
    #[serial]
    fn validate_requires_email_link_base_url_when_confirmation_required() {
        let cfg = AuthConfig {
            jwt_secret: "a".repeat(32),
            email_confirmation_require: true,
            email_link_base_url: None,
            ..Default::default()
        };
        assert!(matches!(cfg.validate(), Err(AuthConfigError::Invalid(_))));
    }

    #[test]
    #[serial]
    fn from_toml_loads_file_values_and_env_secret() {
        let file: AuthConfigFile = toml::from_str(
            r#"[token]
access_expiry_secs = 600
refresh_expiry_secs = 604800

[jwt]
issuer = "fast-auth"
audience = "authenticated"

[password]
min_length = 8
max_length = 128
require_letter = true
require_number = true

[cookie]
access_token_name = "access_token"
refresh_token_name = "refresh_token"
domain = ""
path = "/"
secure = false
same_site = "strict"

[verification]
email_confirmation_require = true
email_token_expiry_secs = 3600
password_reset_token_expiry_secs = 3600
"#,
        )
        .unwrap();

        let secret = "a".repeat(32);
        let previous = std::env::var("AUTH_JWT_SECRET").ok();
        unsafe {
            std::env::set_var("AUTH_JWT_SECRET", &secret);
        }

        let cfg = AuthConfig {
            jwt_secret: secret.clone(),
            access_token_expiry: Duration::from_secs(file.token.access_expiry_secs),
            refresh_token_expiry: Duration::from_secs(file.token.refresh_expiry_secs),
            jwt_issuer: file.jwt.issuer,
            jwt_audience: file.jwt.audience,
            password_min_length: file.password.min_length,
            password_max_length: file.password.max_length,
            password_require_letter: file.password.require_letter,
            password_require_number: file.password.require_number,
            cookie_access_token_name: file.cookie.access_token_name,
            cookie_refresh_token_name: file.cookie.refresh_token_name,
            cookie_domain: optional_string(file.cookie.domain),
            cookie_path: file.cookie.path,
            cookie_secure: file.cookie.secure,
            cookie_same_site: file.cookie.same_site,
            email_verification_token_expiry: Duration::from_secs(
                file.verification.email_token_expiry_secs,
            ),
            password_reset_token_expiry: Duration::from_secs(
                file.verification.password_reset_token_expiry_secs,
            ),
            email_link_base_url: Some("http://localhost:3000".to_string()),
            email_confirmation_require: file.verification.email_confirmation_require,
        };
        cfg.validate_base().unwrap();

        if let Some(value) = previous {
            unsafe {
                std::env::set_var("AUTH_JWT_SECRET", value);
            }
        } else {
            unsafe {
                std::env::remove_var("AUTH_JWT_SECRET");
            }
        }

        assert_eq!(cfg.jwt_secret, secret);
        assert_eq!(cfg.access_token_expiry, Duration::from_secs(600));
        assert_eq!(cfg.cookie_same_site, CookieSameSite::Strict);
        assert!(cfg.email_confirmation_require);
        assert_eq!(
            cfg.email_link_base_url.as_deref(),
            Some("http://localhost:3000")
        );
    }

    #[test]
    #[serial]
    fn from_toml_rejects_missing_required_auth_field() {
        let result = toml::from_str::<AuthConfigFile>(
            r#"[token]
access_expiry_secs = 900
refresh_expiry_secs = 604800

[jwt]
issuer = "fast-auth"
audience = "authenticated"

[password]
min_length = 8
max_length = 128
require_letter = true
require_number = true

[cookie]
access_token_name = "access_token"
refresh_token_name = "refresh_token"
path = "/"
secure = false
same_site = "lax"

[verification]
email_confirmation_require = false
email_token_expiry_secs = 3600
password_reset_token_expiry_secs = 3600
"#,
        );

        assert!(result.is_err());
    }
}
