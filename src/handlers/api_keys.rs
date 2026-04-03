//! Handlers for user API key management.

use crate::{
    Auth, AuthApiKey, AuthApiKeyWithSecret, AuthBackend, AuthHooks, CurrentUser, EmailSender,
    api_key_issue, error::AuthError,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{delete, post},
};
use chrono::{DateTime, Utc};
use common::list::{ListPageParams, ListPageResult};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

/// Base path for API key management.
pub const API_KEYS_PATH: &str = "/auth/api-keys";

#[derive(OpenApi)]
#[openapi(
    paths(api_key_create, api_keys_list, api_key_delete),
    components(schemas(
        ApiKeyCreateRequest,
        ApiKeyCreateResponse,
        ApiKeySummary,
        ListPageResult<ApiKeySummary>,
        crate::error::AuthErrorResponse
    ))
)]
pub(crate) struct ApiKeyApi;

/// Create/list/revoke API key routes.
pub fn api_key_routes<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>()
-> Router<Auth<B, H, E>> {
    Router::new()
        .route(
            API_KEYS_PATH,
            post(api_key_create::<B, H, E>).get(api_keys_list::<B, H, E>),
        )
        .route(
            &format!("{API_KEYS_PATH}/{{api_key_id}}"),
            delete(api_key_delete::<B, H, E>),
        )
}

/// Request body for API key creation.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ApiKeyCreateRequest {
    /// User-defined API key name.
    pub name: String,
}

/// API key summary returned by list and delete endpoints.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ApiKeySummary {
    /// API key identifier.
    pub id: Uuid,
    /// User-defined display name.
    pub name: String,
    /// Stable visible key prefix.
    pub key_prefix: String,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last successful use timestamp.
    pub last_used_at: Option<DateTime<Utc>>,
}

/// API key creation response with one-time plaintext key.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ApiKeyCreateResponse {
    /// API key identifier.
    pub id: Uuid,
    /// User-defined display name.
    pub name: String,
    /// Plaintext key returned once.
    pub key: String,
    /// Stable visible key prefix.
    pub key_prefix: String,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last successful use timestamp.
    pub last_used_at: Option<DateTime<Utc>>,
}

impl From<AuthApiKey> for ApiKeySummary {
    fn from(value: AuthApiKey) -> Self {
        Self {
            id: value.id,
            name: value.name,
            key_prefix: value.key_prefix,
            created_at: value.created_at,
            last_used_at: value.last_used_at,
        }
    }
}

impl From<AuthApiKeyWithSecret> for ApiKeyCreateResponse {
    fn from(value: AuthApiKeyWithSecret) -> Self {
        Self {
            id: value.id,
            name: value.name,
            key: value.key,
            key_prefix: value.key_prefix,
            created_at: value.created_at,
            last_used_at: value.last_used_at,
        }
    }
}

/// Create one API key for the current user.
#[utoipa::path(
    post,
    path = "",
    security(("sessionCookie" = []), ("bearerApiKey" = [])),
    request_body = ApiKeyCreateRequest,
    responses(
        (status = OK, body = ApiKeyCreateResponse),
        (status = BAD_REQUEST, body = crate::error::AuthErrorResponse),
        (status = UNAUTHORIZED, body = crate::error::AuthErrorResponse),
        (status = INTERNAL_SERVER_ERROR, body = crate::error::AuthErrorResponse)
    )
)]
pub async fn api_key_create<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>(
    current_user: CurrentUser,
    State(auth): State<Auth<B, H, E>>,
    Json(request): Json<ApiKeyCreateRequest>,
) -> Result<Json<ApiKeyCreateResponse>, AuthError> {
    let name = request.name.trim();
    if name.is_empty() {
        return Err(AuthError::BadRequest(
            "API key name must not be empty".to_string(),
        ));
    }

    Ok(Json(
        api_key_issue(auth.backend(), current_user.user_id, name)
            .await?
            .into(),
    ))
}

/// List API keys owned by the current user.
#[utoipa::path(
    get,
    path = "",
    params(ListPageParams),
    security(("sessionCookie" = []), ("bearerApiKey" = [])),
    responses(
        (status = OK, body = ListPageResult<ApiKeySummary>),
        (status = BAD_REQUEST, body = crate::error::AuthErrorResponse),
        (status = UNAUTHORIZED, body = crate::error::AuthErrorResponse),
        (status = INTERNAL_SERVER_ERROR, body = crate::error::AuthErrorResponse)
    )
)]
pub async fn api_keys_list<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>(
    current_user: CurrentUser,
    State(auth): State<Auth<B, H, E>>,
    Query(page): Query<ListPageParams>,
) -> Result<Json<ListPageResult<ApiKeySummary>>, AuthError> {
    page.validate()
        .map_err(|error| AuthError::InvalidListPage(error.to_string()))?;
    let api_keys = auth
        .backend()
        .api_keys_list(current_user.user_id, page)
        .await
        .map_err(AuthError::from_backend)?;
    Ok(Json(ListPageResult::new(
        api_keys.items.into_iter().map(Into::into).collect(),
        api_keys.total,
        page,
    )))
}

/// Delete one API key owned by the current user.
#[utoipa::path(
    delete,
    path = "/{api_key_id}",
    params(("api_key_id" = Uuid, Path, description = "API key id")),
    security(("sessionCookie" = []), ("bearerApiKey" = [])),
    responses(
        (status = OK, body = ApiKeySummary),
        (status = UNAUTHORIZED, body = crate::error::AuthErrorResponse),
        (status = NOT_FOUND, body = crate::error::AuthErrorResponse),
        (status = INTERNAL_SERVER_ERROR, body = crate::error::AuthErrorResponse)
    )
)]
pub async fn api_key_delete<B: AuthBackend, H: AuthHooks<B::User>, E: EmailSender>(
    current_user: CurrentUser,
    State(auth): State<Auth<B, H, E>>,
    Path(api_key_id): Path<Uuid>,
) -> Result<Json<ApiKeySummary>, AuthError> {
    let api_key = auth
        .backend()
        .api_key_delete(current_user.user_id, api_key_id)
        .await
        .map_err(AuthError::from_backend)?;
    Ok(Json(api_key.into()))
}
