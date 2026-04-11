//! Organization, membership, and invitation handlers.

use crate::{
    Auth, AuthBackend, AuthHooks, CurrentAdmin, CurrentOwner, EmailSender, Organization,
    OrganizationInvite, OrganizationInviteWithSecret, OrganizationMember, OrganizationRole,
    RequestUser, auth_response_with_cookies_build, error::AuthError,
    tokens::token_cookies_generate,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    response::Response,
    routing::{delete, get, patch, post},
};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

/// Base path for organization routes.
pub const ORGANIZATIONS_PATH: &str = "/auth/organizations";

#[derive(OpenApi)]
#[openapi(
    paths(
        organizations_list,
        organizations_create,
        organizations_get,
        organizations_update,
        organizations_delete,
        organizations_switch,
        organization_members_list,
        organization_member_update,
        organization_member_delete,
        organization_invites_list,
        organization_invite_create,
        organization_invite_revoke,
        organization_invite_accept
    ),
    components(schemas(
        crate::Organization,
        crate::OrganizationMember,
        crate::OrganizationInvite,
        crate::OrganizationInviteWithSecret,
        OrganizationCreateRequest,
        OrganizationUpdateRequest,
        OrganizationSwitchRequest,
        OrganizationRoleUpdateRequest,
        OrganizationInviteCreateRequest,
        OrganizationInviteAcceptRequest,
        crate::error::AuthErrorResponse
    ))
)]
pub(crate) struct OrganizationApi;

/// Organization create request.
#[derive(Debug, serde::Deserialize, ToSchema)]
pub struct OrganizationCreateRequest {
    /// Organization name.
    pub name: String,
}

/// Organization update request.
#[derive(Debug, serde::Deserialize, ToSchema)]
pub struct OrganizationUpdateRequest {
    /// Updated organization name.
    pub name: String,
}

/// Active organization switch request.
#[derive(Debug, serde::Deserialize, ToSchema)]
pub struct OrganizationSwitchRequest {
    /// Next active organization id.
    pub organization_id: Uuid,
}

/// Membership role update request.
#[derive(Debug, serde::Deserialize, ToSchema)]
pub struct OrganizationRoleUpdateRequest {
    /// New organization role.
    pub role: OrganizationRole,
}

/// Invitation create request.
#[derive(Debug, serde::Deserialize, ToSchema)]
pub struct OrganizationInviteCreateRequest {
    /// Invited email.
    pub email: String,
    /// Invited role.
    pub role: OrganizationRole,
}

/// Invitation accept request.
#[derive(Debug, serde::Deserialize, ToSchema)]
pub struct OrganizationInviteAcceptRequest {
    /// Plaintext invitation token.
    pub token: String,
}

/// Build organization routes.
pub fn organization_routes<B: AuthBackend, H: AuthHooks, E: EmailSender>() -> Router<Auth<B, H, E>>
{
    Router::new()
        .route(
            ORGANIZATIONS_PATH,
            get(organizations_list::<B, H, E>).post(organizations_create::<B, H, E>),
        )
        .route(
            &format!("{ORGANIZATIONS_PATH}/{{organization_id}}"),
            get(organizations_get::<B, H, E>)
                .patch(organizations_update::<B, H, E>)
                .delete(organizations_delete::<B, H, E>),
        )
        .route(
            &format!("{ORGANIZATIONS_PATH}/current"),
            post(organizations_switch::<B, H, E>),
        )
        .route(
            &format!("{ORGANIZATIONS_PATH}/{{organization_id}}/members"),
            get(organization_members_list::<B, H, E>),
        )
        .route(
            &format!("{ORGANIZATIONS_PATH}/{{organization_id}}/members/{{member_user_id}}"),
            patch(organization_member_update::<B, H, E>)
                .delete(organization_member_delete::<B, H, E>),
        )
        .route(
            &format!("{ORGANIZATIONS_PATH}/{{organization_id}}/invites"),
            get(organization_invites_list::<B, H, E>).post(organization_invite_create::<B, H, E>),
        )
        .route(
            &format!("{ORGANIZATIONS_PATH}/{{organization_id}}/invites/{{invite_id}}"),
            delete(organization_invite_revoke::<B, H, E>),
        )
        .route(
            &format!("{ORGANIZATIONS_PATH}/invites/accept"),
            post(organization_invite_accept::<B, H, E>),
        )
}

#[utoipa::path(get, path = "", security(("sessionCookie" = []), ("bearerApiKey" = [])))]
async fn organizations_list<B: AuthBackend, H: AuthHooks, E: EmailSender>(
    request_user: RequestUser,
    State(auth): State<Auth<B, H, E>>,
) -> Result<Json<Vec<OrganizationMember>>, AuthError> {
    Ok(Json(
        auth.backend()
            .organizations_list(request_user.user_id)
            .await
            .map_err(AuthError::from_backend)?,
    ))
}

#[utoipa::path(post, path = "", security(("sessionCookie" = []), ("bearerApiKey" = [])))]
async fn organizations_create<B: AuthBackend, H: AuthHooks, E: EmailSender>(
    request_user: RequestUser,
    State(auth): State<Auth<B, H, E>>,
    Json(request): Json<OrganizationCreateRequest>,
) -> Result<Json<OrganizationMember>, AuthError> {
    Ok(Json(
        auth.backend()
            .organization_create(request_user.user_id, request.name.trim())
            .await
            .map_err(AuthError::from_backend)?,
    ))
}

#[utoipa::path(get, path = "/{organization_id}", security(("sessionCookie" = []), ("bearerApiKey" = [])))]
async fn organizations_get<B: AuthBackend, H: AuthHooks, E: EmailSender>(
    request_user: RequestUser,
    State(auth): State<Auth<B, H, E>>,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<OrganizationMember>, AuthError> {
    let member = auth
        .backend()
        .organization_get(request_user.user_id, organization_id)
        .await
        .map_err(AuthError::from_backend)?
        .ok_or(AuthError::OrganizationNotFound)?;
    Ok(Json(member))
}

#[utoipa::path(patch, path = "/{organization_id}", security(("sessionCookie" = []), ("bearerApiKey" = [])))]
async fn organizations_update<B: AuthBackend, H: AuthHooks, E: EmailSender>(
    current_admin: CurrentAdmin,
    State(auth): State<Auth<B, H, E>>,
    Path(organization_id): Path<Uuid>,
    Json(request): Json<OrganizationUpdateRequest>,
) -> Result<Json<OrganizationMember>, AuthError> {
    Ok(Json(
        auth.backend()
            .organization_update(current_admin.user_id, organization_id, request.name.trim())
            .await
            .map_err(AuthError::from_backend)?,
    ))
}

#[utoipa::path(delete, path = "/{organization_id}", security(("sessionCookie" = []), ("bearerApiKey" = [])))]
async fn organizations_delete<B: AuthBackend, H: AuthHooks, E: EmailSender>(
    current_owner: CurrentOwner,
    State(auth): State<Auth<B, H, E>>,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Organization>, AuthError> {
    Ok(Json(
        auth.backend()
            .organization_delete(current_owner.user_id, organization_id)
            .await
            .map_err(AuthError::from_backend)?,
    ))
}

#[utoipa::path(
    post,
    path = "/current",
    security(("sessionCookie" = []), ("bearerApiKey" = [])),
    responses(
        (status = OK, body = crate::AuthResponse),
        (status = UNAUTHORIZED, body = crate::error::AuthErrorResponse),
        (status = NOT_FOUND, body = crate::error::AuthErrorResponse),
        (status = INTERNAL_SERVER_ERROR, body = crate::error::AuthErrorResponse)
    )
)]
async fn organizations_switch<B: AuthBackend, H: AuthHooks, E: EmailSender>(
    request_user: RequestUser,
    State(auth): State<Auth<B, H, E>>,
    Json(request): Json<OrganizationSwitchRequest>,
) -> Result<Response, AuthError> {
    let hydrated_user = auth
        .backend()
        .organization_switch(request_user.user_id, request.organization_id)
        .await
        .map_err(AuthError::from_backend)?;
    let jar = token_cookies_generate(&auth, &hydrated_user).await?;
    Ok(auth_response_with_cookies_build(jar, &hydrated_user))
}

#[utoipa::path(get, path = "/{organization_id}/members", security(("sessionCookie" = []), ("bearerApiKey" = [])))]
async fn organization_members_list<B: AuthBackend, H: AuthHooks, E: EmailSender>(
    current_admin: CurrentAdmin,
    State(auth): State<Auth<B, H, E>>,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<OrganizationMember>>, AuthError> {
    Ok(Json(
        auth.backend()
            .organization_members_list(current_admin.user_id, organization_id)
            .await
            .map_err(AuthError::from_backend)?,
    ))
}

#[utoipa::path(patch, path = "/{organization_id}/members/{member_user_id}", security(("sessionCookie" = []), ("bearerApiKey" = [])))]
async fn organization_member_update<B: AuthBackend, H: AuthHooks, E: EmailSender>(
    current_owner: CurrentOwner,
    State(auth): State<Auth<B, H, E>>,
    Path((organization_id, member_user_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<OrganizationRoleUpdateRequest>,
) -> Result<Json<OrganizationMember>, AuthError> {
    Ok(Json(
        auth.backend()
            .organization_member_update_role(
                current_owner.user_id,
                organization_id,
                member_user_id,
                request.role,
            )
            .await
            .map_err(AuthError::from_backend)?,
    ))
}

#[utoipa::path(delete, path = "/{organization_id}/members/{member_user_id}", security(("sessionCookie" = []), ("bearerApiKey" = [])))]
async fn organization_member_delete<B: AuthBackend, H: AuthHooks, E: EmailSender>(
    current_admin: CurrentAdmin,
    State(auth): State<Auth<B, H, E>>,
    Path((organization_id, member_user_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<OrganizationMember>, AuthError> {
    Ok(Json(
        auth.backend()
            .organization_member_delete(current_admin.user_id, organization_id, member_user_id)
            .await
            .map_err(AuthError::from_backend)?,
    ))
}

#[utoipa::path(get, path = "/{organization_id}/invites", security(("sessionCookie" = []), ("bearerApiKey" = [])))]
async fn organization_invites_list<B: AuthBackend, H: AuthHooks, E: EmailSender>(
    current_admin: CurrentAdmin,
    State(auth): State<Auth<B, H, E>>,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<OrganizationInvite>>, AuthError> {
    Ok(Json(
        auth.backend()
            .organization_invites_list(current_admin.user_id, organization_id)
            .await
            .map_err(AuthError::from_backend)?,
    ))
}

#[utoipa::path(post, path = "/{organization_id}/invites", security(("sessionCookie" = []), ("bearerApiKey" = [])))]
async fn organization_invite_create<B: AuthBackend, H: AuthHooks, E: EmailSender>(
    current_admin: CurrentAdmin,
    State(auth): State<Auth<B, H, E>>,
    Path(organization_id): Path<Uuid>,
    Json(request): Json<OrganizationInviteCreateRequest>,
) -> Result<Json<OrganizationInviteWithSecret>, AuthError> {
    Ok(Json(
        auth.backend()
            .organization_invite_create(
                current_admin.user_id,
                organization_id,
                request.email.trim(),
                request.role,
            )
            .await
            .map_err(AuthError::from_backend)?,
    ))
}

#[utoipa::path(delete, path = "/{organization_id}/invites/{invite_id}", security(("sessionCookie" = []), ("bearerApiKey" = [])))]
async fn organization_invite_revoke<B: AuthBackend, H: AuthHooks, E: EmailSender>(
    current_admin: CurrentAdmin,
    State(auth): State<Auth<B, H, E>>,
    Path((organization_id, invite_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<OrganizationInvite>, AuthError> {
    Ok(Json(
        auth.backend()
            .organization_invite_revoke(current_admin.user_id, organization_id, invite_id)
            .await
            .map_err(AuthError::from_backend)?,
    ))
}

#[utoipa::path(
    post,
    path = "/invites/accept",
    security(("sessionCookie" = []), ("bearerApiKey" = [])),
    responses(
        (status = OK, body = crate::AuthResponse),
        (status = BAD_REQUEST, body = crate::error::AuthErrorResponse),
        (status = UNAUTHORIZED, body = crate::error::AuthErrorResponse),
        (status = NOT_FOUND, body = crate::error::AuthErrorResponse),
        (status = INTERNAL_SERVER_ERROR, body = crate::error::AuthErrorResponse)
    )
)]
async fn organization_invite_accept<B: AuthBackend, H: AuthHooks, E: EmailSender>(
    request_user: RequestUser,
    State(auth): State<Auth<B, H, E>>,
    Json(request): Json<OrganizationInviteAcceptRequest>,
) -> Result<Response, AuthError> {
    let hydrated_user = auth
        .backend()
        .organization_invite_accept(request_user.user_id, &request.token)
        .await
        .map_err(AuthError::from_backend)?;
    let jar = token_cookies_generate(&auth, &hydrated_user).await?;
    Ok(auth_response_with_cookies_build(jar, &hydrated_user))
}
