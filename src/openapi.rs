//! OpenAPI generation for fast-auth endpoints.

use std::path::{Path, PathBuf};

use crate::handlers;
use thiserror::Error;
use utoipa::OpenApi;

/// OpenAPI document for all public fast-auth HTTP endpoints.
#[derive(OpenApi)]
#[openapi(
    nest(
        (path = handlers::SIGN_UP_PATH, api = handlers::sign_up::SignUpApi, tags = ["auth"]),
        (path = handlers::SIGN_IN_PATH, api = handlers::sign_in::SignInApi, tags = ["auth"]),
        (path = handlers::SIGN_OUT_PATH, api = handlers::sign_out::SignOutApi, tags = ["auth"]),
        (path = handlers::ME_PATH, api = handlers::me::MeApi, tags = ["auth"]),
        (
            path = handlers::EMAIL_CONFIRM_PATH,
            api = handlers::email::EmailConfirmApi,
            tags = ["auth"]
        ),
        (
            path = handlers::PASSWORD_PATH,
            api = handlers::password::PasswordApi,
            tags = ["auth"]
        )
    ),
    tags((name = "auth", description = "Authentication management"))
)]
pub struct AuthApiDoc;

/// OpenAPI generation and file-write errors.
#[derive(Debug, Error)]
pub enum OpenApiError {
    /// OpenAPI serialization failed.
    #[error("failed to serialize openapi spec: {0}")]
    Serialize(#[from] serde_yaml::Error),

    /// Creating the docs directory failed.
    #[error("failed to create docs directory at {path}: {source}")]
    CreateDir {
        /// Target directory path.
        path: PathBuf,
        /// I/O source error.
        #[source]
        source: std::io::Error,
    },

    /// Writing the OpenAPI file failed.
    #[error("failed to write openapi spec at {path}: {source}")]
    WriteFile {
        /// Target file path.
        path: PathBuf,
        /// I/O source error.
        #[source]
        source: std::io::Error,
    },
}

/// Build the OpenAPI document for fast-auth.
pub fn openapi_build() -> utoipa::openapi::OpenApi {
    AuthApiDoc::openapi()
}

/// Generate the OpenAPI document as YAML.
pub fn openapi_yaml_generate() -> Result<String, OpenApiError> {
    Ok(serde_yaml::to_string(&openapi_build())?)
}

/// Write the OpenAPI YAML document to an arbitrary path.
pub fn openapi_yaml_write(path: impl AsRef<Path>) -> Result<(), OpenApiError> {
    let path = path.as_ref();
    let docs_dir = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    std::fs::create_dir_all(&docs_dir).map_err(|source| OpenApiError::CreateDir {
        path: docs_dir.clone(),
        source,
    })?;

    let spec = openapi_yaml_generate()?;
    std::fs::write(path, spec).map_err(|source| OpenApiError::WriteFile {
        path: path.to_path_buf(),
        source,
    })?;

    Ok(())
}

/// Write `fast-auth/docs/openapi.yml` and return the written path.
pub fn openapi_yaml_write_default() -> Result<PathBuf, OpenApiError> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs")
        .join("openapi.yml");
    openapi_yaml_write(&path)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openapi_yaml_generate_includes_auth_paths() {
        let yaml = openapi_yaml_generate().expect("openapi yaml");
        assert!(yaml.contains("/auth/sign-in"));
        assert!(yaml.contains("/auth/sign-up"));
    }
}
