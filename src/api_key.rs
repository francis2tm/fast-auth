//! API key generation, parsing, and creation helpers.

use crate::{
    ApiKeyWithSecret, AuthBackend, error::AuthError, password::password_hash,
    tokens::token_generate,
};
use uuid::Uuid;

/// Number of visible characters copied into the stored API key prefix.
pub const API_KEY_PREFIX_LEN: usize = 12;

/// Generate one API key and its visible prefix.
pub fn api_key_generate() -> (String, String) {
    let token = token_generate();
    let prefix = token[..API_KEY_PREFIX_LEN].to_string();
    (format!("sk-{token}"), prefix)
}

/// Extract the visible prefix from one presented API key.
pub fn api_key_prefix_extract(api_key: &str) -> Option<&str> {
    let token = api_key.strip_prefix("sk-")?;
    (token.len() == 64).then(|| &token[..API_KEY_PREFIX_LEN])
}

/// Hash API key material using the same Argon2 policy as passwords.
pub fn api_key_hash(api_key: &str) -> Result<String, AuthError> {
    password_hash(api_key)
}

/// Create and persist one API key, returning the plaintext secret once.
pub async fn api_key_issue<B: AuthBackend>(
    backend: &B,
    organization_id: Uuid,
    created_by_user_id: Uuid,
    name: &str,
) -> Result<ApiKeyWithSecret, AuthError> {
    let (key, key_prefix) = api_key_generate();
    let key_hash = api_key_hash(&key)?;
    let api_key = backend
        .api_key_create(
            organization_id,
            created_by_user_id,
            name,
            &key_prefix,
            &key_hash,
        )
        .await
        .map_err(AuthError::from_backend)?;

    Ok(ApiKeyWithSecret {
        id: api_key.id,
        organization_id: api_key.organization_id,
        name: api_key.name,
        created_by_user_id: api_key.created_by_user_id,
        key,
        key_prefix: api_key.key_prefix,
        created_at: api_key.created_at,
        last_used_at: api_key.last_used_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_roundtrip() {
        let (api_key, prefix) = api_key_generate();
        assert_eq!(api_key_prefix_extract(&api_key), Some(prefix.as_str()));
    }
}
