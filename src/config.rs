use std::time::Duration;
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

impl AuthConfig {
    /// Build auth config from environment variables.
    ///
    /// Required:
    /// - `AUTH_JWT_SECRET`
    /// - `AUTH_EMAIL_CONFIRMATION_REQUIRE`
    ///
    /// Optional variables fall back to `Default` values when not provided.
    ///
    pub fn from_env() -> Result<Self, AuthConfigError> {
        let mut cfg = Self::default();
        cfg.jwt_secret = env_var_required("AUTH_JWT_SECRET")?;
        cfg.access_token_expiry = Duration::from_secs(env_var_parse_or_default(
            "AUTH_ACCESS_TOKEN_EXPIRY_SECS",
            cfg.access_token_expiry.as_secs(),
            "u64",
        )?);
        cfg.refresh_token_expiry = Duration::from_secs(env_var_parse_or_default(
            "AUTH_REFRESH_TOKEN_EXPIRY_SECS",
            cfg.refresh_token_expiry.as_secs(),
            "u64",
        )?);
        cfg.password_min_length =
            env_var_parse_or_default("AUTH_PASSWORD_MIN_LENGTH", cfg.password_min_length, "usize")?;
        cfg.password_max_length =
            env_var_parse_or_default("AUTH_PASSWORD_MAX_LENGTH", cfg.password_max_length, "usize")?;
        cfg.password_require_letter =
            env_var_bool_or_default("AUTH_PASSWORD_REQUIRE_LETTER", cfg.password_require_letter)?;
        cfg.password_require_number =
            env_var_bool_or_default("AUTH_PASSWORD_REQUIRE_NUMBER", cfg.password_require_number)?;
        cfg.cookie_secure = env_var_bool_or_default("AUTH_COOKIE_SECURE", cfg.cookie_secure)?;
        cfg.cookie_same_site =
            env_var_cookie_same_site_or_default("AUTH_COOKIE_SAME_SITE", cfg.cookie_same_site)?;
        cfg.email_verification_token_expiry = Duration::from_secs(env_var_parse_or_default(
            "AUTH_EMAIL_VERIFICATION_TOKEN_EXPIRY_SECS",
            cfg.email_verification_token_expiry.as_secs(),
            "u64",
        )?);
        cfg.password_reset_token_expiry = Duration::from_secs(env_var_parse_or_default(
            "AUTH_PASSWORD_RESET_TOKEN_EXPIRY_SECS",
            cfg.password_reset_token_expiry.as_secs(),
            "u64",
        )?);
        cfg.email_confirmation_require = env_var_bool_required("AUTH_EMAIL_CONFIRMATION_REQUIRE")?;

        if let Some(v) = env_var_optional("AUTH_JWT_ISSUER") {
            cfg.jwt_issuer = v;
        }
        if let Some(v) = env_var_optional("AUTH_JWT_AUDIENCE") {
            cfg.jwt_audience = v;
        }
        if let Some(v) = env_var_optional("AUTH_COOKIE_ACCESS_TOKEN_NAME") {
            cfg.cookie_access_token_name = v;
        }
        if let Some(v) = env_var_optional("AUTH_COOKIE_REFRESH_TOKEN_NAME") {
            cfg.cookie_refresh_token_name = v;
        }
        if let Some(v) = env_var_optional("AUTH_COOKIE_PATH") {
            cfg.cookie_path = v;
        }
        cfg.cookie_domain = env_var_optional("AUTH_COOKIE_DOMAIN");
        cfg.email_link_base_url = env_var_optional("AUTH_EMAIL_LINK_BASE_URL");

        cfg.validate()?;
        Ok(cfg)
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

        if self.email_confirmation_require
            && self
                .email_link_base_url
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .is_none()
        {
            return Err(AuthConfigError::Invalid(
                "AUTH_EMAIL_LINK_BASE_URL must be set when AUTH_EMAIL_CONFIRMATION_REQUIRE=true"
                    .to_string(),
            ));
        }

        Ok(())
    }
}

fn env_var_required(key: &'static str) -> Result<String, AuthConfigError> {
    std::env::var(key).map_err(|_| AuthConfigError::MissingEnv(key))
}

fn env_var_optional(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn env_var_parse_or_default<T: std::str::FromStr>(
    key: &str,
    default: T,
    type_name: &str,
) -> Result<T, AuthConfigError> {
    match env_var_optional(key) {
        Some(v) => v
            .parse::<T>()
            .map_err(|_| AuthConfigError::Invalid(format!("{key} must be a valid {type_name}"))),
        _ => Ok(default),
    }
}

fn env_var_bool_or_default(key: &str, default: bool) -> Result<bool, AuthConfigError> {
    match env_var_optional(key) {
        Some(v) => match v.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => Err(AuthConfigError::Invalid(format!(
                "{key} must be a valid boolean"
            ))),
        },
        _ => Ok(default),
    }
}

fn env_var_bool_required(key: &'static str) -> Result<bool, AuthConfigError> {
    match env_var_required(key)?.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(AuthConfigError::Invalid(format!(
            "{key} must be a valid boolean"
        ))),
    }
}

fn env_var_cookie_same_site_or_default(
    key: &str,
    default: CookieSameSite,
) -> Result<CookieSameSite, AuthConfigError> {
    match env_var_optional(key) {
        Some(v) => match v.trim().to_ascii_lowercase().as_str() {
            "none" => Ok(CookieSameSite::None),
            "lax" => Ok(CookieSameSite::Lax),
            "strict" => Ok(CookieSameSite::Strict),
            _ => Err(AuthConfigError::Invalid(format!(
                "{key} must be one of: none, lax, strict"
            ))),
        },
        _ => Ok(default),
    }
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
    fn env_var_bool_required_returns_missing_env_error() {
        let key = "AUTH_EMAIL_CONFIRMATION_REQUIRE_MISSING_TEST";
        assert!(matches!(
            env_var_bool_required(key),
            Err(AuthConfigError::MissingEnv(
                "AUTH_EMAIL_CONFIRMATION_REQUIRE_MISSING_TEST"
            ))
        ));
    }
}
