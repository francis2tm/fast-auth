//! Token generation and validation utilities.

use crate::{
    Auth, AuthBackend, AuthHooks, EmailSender,
    config::AuthConfig,
    cookies::{access_token_cookie_create, refresh_token_cookie_create},
    error::AuthError,
};
use axum_extra::extract::cookie::CookieJar;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// JWT Claims structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Subject (user ID).
    pub sub: String,
    /// Issued at (Unix timestamp).
    pub iat: i64,
    /// Expiration time (Unix timestamp).
    pub exp: i64,
    /// Issuer.
    pub iss: String,
    /// Audience.
    pub aud: String,
    /// Role for RLS (always "authenticated" for logged-in users).
    pub role: String,
    /// User email.
    pub email: String,
}

/// Generate an access token (JWT).
pub fn access_token_generate(
    user_id: Uuid,
    email: String,
    config: &AuthConfig,
) -> Result<String, AuthError> {
    let now = Utc::now();
    let access_expiry = Duration::from_std(config.access_token_expiry)
        .map_err(|_| AuthError::Internal("access token expiry overflow".to_string()))?;
    let expiry = now + access_expiry;

    let claims = AccessTokenClaims {
        sub: user_id.to_string(),
        iat: now.timestamp(),
        exp: expiry.timestamp(),
        iss: config.jwt_issuer.clone(),
        aud: config.jwt_audience.clone(),
        role: "authenticated".to_string(),
        email,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )?;

    Ok(token)
}

/// Validate and decode an access token.
pub fn access_token_validate(
    token: &str,
    config: &AuthConfig,
) -> Result<AccessTokenClaims, AuthError> {
    let mut validation = Validation::default();
    validation.set_issuer(&[&config.jwt_issuer]);
    validation.set_audience(&[&config.jwt_audience]);

    let token_data = decode::<AccessTokenClaims>(
        token,
        &DecodingKey::from_secret(config.jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|e| {
        // Map ExpiredSignature to TokenExpired so middleware can fall through to refresh
        if matches!(e.kind(), jsonwebtoken::errors::ErrorKind::ExpiredSignature) {
            AuthError::TokenExpired
        } else {
            AuthError::from(e)
        }
    })?;

    Ok(token_data.claims)
}

// =============================================================================
// Token Utilities
// =============================================================================

/// Hash a string using SHA-256. Used for storing tokens securely.
pub fn token_hash_sha256(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate a cryptographically random 32-byte token as hex string.
pub fn token_generate() -> String {
    let mut rng = rand::rng();
    let token: [u8; 32] = rng.random();
    hex::encode(token)
}

/// Calculate expiration time from a duration.
pub fn token_expiry_calculate(duration: std::time::Duration) -> DateTime<Utc> {
    let chrono_duration = Duration::from_std(duration).unwrap_or_else(|_| Duration::hours(1));
    Utc::now() + chrono_duration
}

/// Generate a random token and its hash.
///
/// Returns `(token, hash)` where token is shared and hash is stored.
pub fn token_with_hash_generate() -> (String, String) {
    let token = token_generate();
    let hash = token_hash_sha256(&token);
    (token, hash)
}

/// Persist a refresh token and emit the matching cookie pair.
///
/// To enforce single-session semantics, this revokes every previously active
/// refresh token for the user and creates a new one.
pub async fn token_cookies_generate<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>(
    auth: &Auth<B, H, E>,
    user_id: Uuid,
    email: &str,
) -> Result<CookieJar, AuthError> {
    let access_token = access_token_generate(user_id, email.to_owned(), auth.config())?;
    let (refresh_token, refresh_token_hash) = token_with_hash_generate();
    let refresh_token_expiry = token_expiry_calculate(auth.config().refresh_token_expiry);

    // Atomically revoke old tokens and create new one
    auth.backend()
        .refresh_token_rotate_atomic(user_id, &refresh_token_hash, refresh_token_expiry)
        .await
        .map_err(|e| AuthError::Backend(e.to_string()))?;

    let jar = CookieJar::new()
        .add(access_token_cookie_create(access_token, auth.config()))
        .add(refresh_token_cookie_create(refresh_token, auth.config()));

    Ok(jar)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AuthConfig {
        AuthConfig {
            jwt_secret: "test_secret_key_at_least_32_chars_long_for_security".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_generate_and_validate_access_token() {
        let config = test_config();
        let user_id = Uuid::new_v4();
        let email = "test@example.com".to_string();

        let token = access_token_generate(user_id, email.clone(), &config).unwrap();
        let claims = access_token_validate(&token, &config).unwrap();

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.email, email);
        assert_eq!(claims.role, "authenticated");
        assert_eq!(claims.iss, config.jwt_issuer);
        assert_eq!(claims.aud, config.jwt_audience);
    }

    #[test]
    fn test_invalid_token_fails() {
        let config = test_config();
        let result = access_token_validate("invalid_token", &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_token_with_wrong_secret_fails() {
        let config = test_config();
        let user_id = Uuid::new_v4();
        let email = "test@example.com".to_string();

        let token = access_token_generate(user_id, email, &config).unwrap();

        let mut wrong_config = config;
        wrong_config.jwt_secret =
            "wrong_secret_key_at_least_32_chars_long_for_security".to_string();

        let result = access_token_validate(&token, &wrong_config);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_random_token() {
        let token1 = token_generate();
        let token2 = token_generate();

        // Tokens should be different
        assert_ne!(token1, token2);

        // Tokens should be 64 characters (32 bytes in hex)
        assert_eq!(token1.len(), 64);
        assert_eq!(token2.len(), 64);
    }

    #[test]
    fn test_sha256_hash() {
        let token = token_generate();
        let hash1 = token_hash_sha256(&token);
        let hash2 = token_hash_sha256(&token);

        // Same token should produce same hash
        assert_eq!(hash1, hash2);

        // Hash should be 64 characters (SHA-256 in hex)
        assert_eq!(hash1.len(), 64);

        // Different token should produce different hash
        let different_token = token_generate();
        let different_hash = token_hash_sha256(&different_token);
        assert_ne!(hash1, different_hash);
    }
}
