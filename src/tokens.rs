//! Token generation and validation utilities.

use crate::{
    Auth, AuthBackend, AuthHooks,
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

/// Generate a random refresh token.
pub fn refresh_token_generate() -> String {
    let mut rng = rand::rng();
    let token: [u8; 32] = rng.random();

    // Encode as hex string (64 characters)
    hex::encode(token)
}

/// Hash a refresh token for storage (SHA-256).
pub fn refresh_token_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Calculate expiration time for refresh token.
pub fn refresh_token_calculate_expiry(config: &AuthConfig) -> Result<DateTime<Utc>, AuthError> {
    let refresh = Duration::from_std(config.refresh_token_expiry)
        .map_err(|_| AuthError::Internal("refresh token expiry overflow".to_string()))?;
    Ok(Utc::now() + refresh)
}

/// Persist a refresh token and emit the matching cookie pair.
///
/// To enforce single-session semantics, this revokes every previously active
/// refresh token for the user and creates a new one.
pub async fn token_cookies_generate<B: AuthBackend, H: AuthHooks<B::User>>(
    auth: &Auth<B, H>,
    user_id: Uuid,
    email: &str,
) -> Result<CookieJar, AuthError> {
    let access_token = access_token_generate(user_id, email.to_owned(), auth.config())?;
    let refresh_token = refresh_token_generate();
    let refresh_token_hash = refresh_token_hash(&refresh_token);
    let refresh_token_expiry = refresh_token_calculate_expiry(auth.config())?;

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
    fn test_generate_refresh_token() {
        let token1 = refresh_token_generate();
        let token2 = refresh_token_generate();

        // Tokens should be different
        assert_ne!(token1, token2);

        // Tokens should be 64 characters (32 bytes in hex)
        assert_eq!(token1.len(), 64);
        assert_eq!(token2.len(), 64);
    }

    #[test]
    fn test_hash_refresh_token() {
        let token = refresh_token_generate();
        let hash1 = refresh_token_hash(&token);
        let hash2 = refresh_token_hash(&token);

        // Same token should produce same hash
        assert_eq!(hash1, hash2);

        // Hash should be 64 characters (SHA-256 in hex)
        assert_eq!(hash1.len(), 64);

        // Different token should produce different hash
        let different_token = refresh_token_generate();
        let different_hash = refresh_token_hash(&different_token);
        assert_ne!(hash1, different_hash);
    }
}
