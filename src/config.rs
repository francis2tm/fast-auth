use serde::{Deserialize, de::DeserializeOwned};
use std::{path::Path, time::Duration};
use thiserror::Error;

/// Errors when loading or validating authentication configuration.
#[derive(Debug, Error)]
pub enum AuthConfigError {
    /// Required environment variable was not provided.
    #[error("missing env var {0}")]
    MissingEnv(&'static str),

    /// Failed to read TOML config file.
    #[error("failed to read auth config file '{path}': {source}")]
    ConfigFileRead {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// Failed to parse TOML config file.
    #[error("failed to parse auth config file '{path}': {source}")]
    ConfigFileParse {
        path: String,
        #[source]
        source: toml::de::Error,
    },

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
    frontend: AuthTomlFrontendConfig,
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthTomlFrontendConfig {
    base_url: String,
}

impl AuthConfigFile {
    fn auth_config_build(self, jwt_secret: String) -> AuthConfig {
        AuthConfig {
            jwt_secret,
            access_token_expiry: Duration::from_secs(self.token.access_expiry_secs),
            refresh_token_expiry: Duration::from_secs(self.token.refresh_expiry_secs),
            jwt_issuer: self.jwt.issuer,
            jwt_audience: self.jwt.audience,
            password_min_length: self.password.min_length,
            password_max_length: self.password.max_length,
            password_require_letter: self.password.require_letter,
            password_require_number: self.password.require_number,
            cookie_access_token_name: self.cookie.access_token_name,
            cookie_refresh_token_name: self.cookie.refresh_token_name,
            cookie_domain: optional_string(self.cookie.domain),
            cookie_path: self.cookie.path,
            cookie_secure: self.cookie.secure,
            cookie_same_site: self.cookie.same_site,
            email_verification_token_expiry: Duration::from_secs(
                self.verification.email_token_expiry_secs,
            ),
            password_reset_token_expiry: Duration::from_secs(
                self.verification.password_reset_token_expiry_secs,
            ),
            email_link_base_url: optional_string(self.frontend.base_url),
            email_confirmation_require: self.verification.email_confirmation_require,
        }
    }
}

impl AuthConfig {
    /// Build auth config from a TOML file.
    ///
    /// Only `AUTH_JWT_SECRET` remains environment-driven.
    /// All other values are loaded from `path` root sections.
    ///
    pub fn from_toml<P: AsRef<Path>>(path: P) -> Result<Self, AuthConfigError> {
        let file: AuthConfigFile = config_toml_parse(path)?;
        let jwt_secret = env_var_required("AUTH_JWT_SECRET")?;
        let cfg = file.auth_config_build(jwt_secret);

        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), AuthConfigError> {
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
}

fn env_var_required(key: &'static str) -> Result<String, AuthConfigError> {
    std::env::var(key).map_err(|_| AuthConfigError::MissingEnv(key))
}

fn optional_string(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}

fn invalid(message: &'static str) -> AuthConfigError {
    AuthConfigError::Invalid(message.to_string())
}

/// Parse a TOML config file into a strict typed structure.
pub fn config_toml_parse<P: AsRef<Path>, T: DeserializeOwned>(
    path: P,
) -> Result<T, AuthConfigError> {
    let path = path.as_ref();
    let path_display = path.display().to_string();
    let content =
        std::fs::read_to_string(path).map_err(|source| AuthConfigError::ConfigFileRead {
            path: path_display.clone(),
            source,
        })?;

    toml::from_str::<T>(&content).map_err(|source| AuthConfigError::ConfigFileParse {
        path: path_display,
        source,
    })
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
    fn from_toml_requires_jwt_secret_env_var() {
        let path = std::env::temp_dir().join(format!(
            "fast-auth-config-{}-missing-secret.toml",
            std::process::id()
        ));
        std::fs::write(
            &path,
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
domain = ""
path = "/"
secure = false
same_site = "lax"

[verification]
email_confirmation_require = false
email_token_expiry_secs = 3600
password_reset_token_expiry_secs = 3600

[frontend]
base_url = ""
"#,
        )
        .unwrap();

        let previous = std::env::var("AUTH_JWT_SECRET").ok();
        unsafe {
            std::env::remove_var("AUTH_JWT_SECRET");
        }

        let result = AuthConfig::from_toml(&path);
        let _ = std::fs::remove_file(&path);

        if let Some(value) = previous {
            unsafe {
                std::env::set_var("AUTH_JWT_SECRET", value);
            }
        }

        assert!(matches!(
            result,
            Err(AuthConfigError::MissingEnv("AUTH_JWT_SECRET"))
        ));
    }

    #[test]
    #[serial]
    fn from_toml_loads_file_values_and_env_secret() {
        let path =
            std::env::temp_dir().join(format!("fast-auth-config-{}-load.toml", std::process::id()));
        std::fs::write(
            &path,
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

[frontend]
base_url = "http://localhost:3000"
"#,
        )
        .unwrap();

        let secret = "a".repeat(32);
        let previous = std::env::var("AUTH_JWT_SECRET").ok();
        unsafe {
            std::env::set_var("AUTH_JWT_SECRET", &secret);
        }

        let cfg = AuthConfig::from_toml(&path).unwrap();
        let _ = std::fs::remove_file(&path);

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
            cfg.email_link_base_url,
            Some("http://localhost:3000".to_string())
        );
    }

    #[test]
    #[serial]
    fn from_toml_rejects_missing_required_auth_field() {
        let path = std::env::temp_dir().join(format!(
            "fast-auth-config-{}-missing-field.toml",
            std::process::id()
        ));
        std::fs::write(
            &path,
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

[frontend]
base_url = ""
"#,
        )
        .unwrap();

        let previous = std::env::var("AUTH_JWT_SECRET").ok();
        unsafe {
            std::env::set_var("AUTH_JWT_SECRET", "a".repeat(32));
        }

        let result = AuthConfig::from_toml(&path);
        let _ = std::fs::remove_file(&path);

        if let Some(value) = previous {
            unsafe {
                std::env::set_var("AUTH_JWT_SECRET", value);
            }
        } else {
            unsafe {
                std::env::remove_var("AUTH_JWT_SECRET");
            }
        }

        assert!(matches!(
            result,
            Err(AuthConfigError::ConfigFileParse { .. })
        ));
    }
}
