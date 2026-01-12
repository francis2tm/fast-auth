use crate::{config::AuthConfig, error::AuthError};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

/// Validate password strength based on configuration
pub fn password_validate(password: &str, config: &AuthConfig) -> Result<(), AuthError> {
    if password.len() < config.password_min_length {
        return Err(AuthError::WeakPassword(format!(
            "Password must be at least {} characters",
            config.password_min_length
        )));
    }

    if password.len() > config.password_max_length {
        return Err(AuthError::WeakPassword(format!(
            "Password must not exceed {} characters",
            config.password_max_length
        )));
    }

    if config.password_require_letter {
        let has_letter = password.chars().any(|c| c.is_alphabetic());
        if !has_letter {
            return Err(AuthError::WeakPassword(
                "Password must contain at least one letter".to_string(),
            ));
        }
    }

    if config.password_require_number {
        let has_number = password.chars().any(|c| c.is_numeric());
        if !has_number {
            return Err(AuthError::WeakPassword(
                "Password must contain at least one number".to_string(),
            ));
        }
    }

    Ok(())
}

/// Hash a password using Argon2id
pub fn password_hash(password: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let hashed = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AuthError::PasswordHash(e.to_string()))?;

    Ok(hashed.to_string())
}

/// Verify a password against a hash using constant-time comparison
pub fn password_verify(password: &str, hash: &str) -> Result<bool, AuthError> {
    let parsed_hash =
        PasswordHash::new(hash).map_err(|e| AuthError::PasswordHash(e.to_string()))?;

    let argon2 = Argon2::default();

    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> AuthConfig {
        AuthConfig::default()
    }

    #[test]
    fn test_password_validate() {
        let config = default_config();

        // Valid passwords
        assert!(password_validate("password123", &config).is_ok());
        assert!(password_validate("SecurePass123", &config).is_ok());

        // Too short
        assert!(password_validate("pass1", &config).is_err());

        // No number
        assert!(password_validate("password", &config).is_err());

        // No letter
        assert!(password_validate("12345678", &config).is_err());

        // Too long
        let long_pass = "a".repeat(129) + "1";
        assert!(password_validate(&long_pass, &config).is_err());
    }

    #[test]
    fn test_password_hash_and_verify() {
        let password = "TestPassword123";
        let hash = password_hash(password).unwrap();

        // Correct password
        assert!(password_verify(password, &hash).unwrap());

        // Wrong password
        assert!(!password_verify("WrongPassword123", &hash).unwrap());
    }

    #[test]
    fn test_password_hash_produces_different_salts() {
        let password = "TestPassword123";
        let hash1 = password_hash(password).unwrap();
        let hash2 = password_hash(password).unwrap();

        // Hashes should be different due to different salts
        assert_ne!(hash1, hash2);

        // But both should verify correctly
        assert!(password_verify(password, &hash1).unwrap());
        assert!(password_verify(password, &hash2).unwrap());
    }
}
