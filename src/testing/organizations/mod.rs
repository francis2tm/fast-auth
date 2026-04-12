//! Organization, membership, and invite test functions.

mod basics;
mod invites;
mod permissions;

pub use self::basics::{
    organization_create_returns_shared_kind,
    organization_delete_active_org_preserves_auth_or_is_rejected,
    organization_delete_personal_org_when_inactive_is_rejected,
    organization_get_rejects_non_member,
    organization_switch_between_personal_and_shared_updates_kind,
    organization_switch_rejects_non_member_organization,
    organization_switch_then_refresh_keeps_selected_org,
    organization_switch_updates_active_auth_context,
    organizations_include_default_membership_and_support_crud,
};
pub use self::invites::{
    organization_invite_accept_adds_membership_and_switches_context,
    organization_invite_accept_and_revoke_race_has_single_winner,
    organization_invite_accept_race_has_single_winner,
    organization_invite_accept_rejects_personal_workspace_even_if_invite_exists,
    organization_invite_accept_rejects_reuse, organization_invite_accept_rejects_wrong_email,
    organization_invite_accept_supports_user_created_after_invite,
    organization_invite_create_race_keeps_single_active_invite,
    organization_invite_create_replaces_existing_active_invite,
    organization_invite_revoke_prevents_acceptance,
};
pub use self::permissions::{
    organization_admin_can_manage_members_and_invites, organization_admin_cannot_delete_owner,
    organization_admin_cannot_invite_owner, organization_cross_org_admin_routes_return_not_found,
    organization_last_owner_cannot_be_demoted_or_removed,
    organization_member_delete_active_membership_preserves_auth_or_clears_session_consistently,
    organization_member_role_gates_admin_routes, organization_member_role_update_requires_owner,
    organization_personal_workspace_rejects_collaboration_routes,
    organization_role_change_is_visible_after_refresh_and_sign_in,
};

use reqwest::{Client, Response, StatusCode, header};
use serde::de::DeserializeOwned;
use serde_json::json;
use uuid::Uuid;

use crate::handlers::ORGANIZATIONS_PATH;
use crate::{
    AuthResponse, Organization, OrganizationInvite, OrganizationInviteWithSecret, OrganizationKind,
    OrganizationMember, OrganizationRole,
};

use super::{
    TestContext, TestUser, auth_refresh, auth_response_assert, auth_response_with_cookie_update,
    auth_sign_in, me_get,
};

/// Return the path for one organization resource.
fn organization_path(organization_id: Uuid) -> String {
    format!("{ORGANIZATIONS_PATH}/{organization_id}")
}

/// Return the path for one organization member collection.
fn organization_members_path(organization_id: Uuid) -> String {
    format!("{ORGANIZATIONS_PATH}/{organization_id}/members")
}

/// Return the path for one organization member resource.
fn organization_member_path(organization_id: Uuid, member_user_id: Uuid) -> String {
    format!("{ORGANIZATIONS_PATH}/{organization_id}/members/{member_user_id}")
}

/// Return the path for one organization invite collection.
fn organization_invites_path(organization_id: Uuid) -> String {
    format!("{ORGANIZATIONS_PATH}/{organization_id}/invites")
}

/// Return the path for one organization invite resource.
fn organization_invite_path(organization_id: Uuid, invite_id: Uuid) -> String {
    format!("{ORGANIZATIONS_PATH}/{organization_id}/invites/{invite_id}")
}

/// Return the path for switching the active organization.
fn organization_current_path() -> String {
    format!("{ORGANIZATIONS_PATH}/current")
}

/// Return the path for accepting one organization invite.
fn organization_invite_accept_path() -> String {
    format!("{ORGANIZATIONS_PATH}/invites/accept")
}

/// Parse one JSON response body.
async fn response_json<T: DeserializeOwned>(response: Response) -> T {
    response.json().await.expect("json response")
}

/// List visible organizations for one authenticated user.
async fn organizations_list(
    base_url: &str,
    client: &Client,
    user: &TestUser,
    config: &crate::AuthConfig,
) -> Vec<OrganizationMember> {
    let response = client
        .get(format!("{base_url}{ORGANIZATIONS_PATH}"))
        .header(header::COOKIE, user.cookie_header(config))
        .send()
        .await
        .expect("organizations list request");
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await
}

/// Create one organization for one authenticated user.
async fn organization_create(
    base_url: &str,
    client: &Client,
    user: &TestUser,
    config: &crate::AuthConfig,
    name: &str,
) -> OrganizationMember {
    let response = client
        .post(format!("{base_url}{ORGANIZATIONS_PATH}"))
        .header(header::COOKIE, user.cookie_header(config))
        .json(&json!({ "name": name }))
        .send()
        .await
        .expect("organization create request");
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await
}

/// Create one shared organization and return its organization payload.
async fn shared_organization_create(
    base_url: &str,
    client: &Client,
    user: &TestUser,
    config: &crate::AuthConfig,
    name: &str,
) -> Organization {
    let member = organization_create(base_url, client, user, config, name).await;
    assert_eq!(member.organization.kind, OrganizationKind::Shared);
    member.organization
}

/// Create one invite inside one organization.
async fn organization_invite_create(
    base_url: &str,
    client: &Client,
    user: &TestUser,
    config: &crate::AuthConfig,
    organization_id: Uuid,
    email: &str,
    role: OrganizationRole,
) -> OrganizationInviteWithSecret {
    let response = client
        .post(format!(
            "{base_url}{}",
            organization_invites_path(organization_id)
        ))
        .header(header::COOKIE, user.cookie_header(config))
        .json(&json!({ "email": email, "role": role }))
        .send()
        .await
        .expect("organization invite create request");
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await
}

/// List invites inside one organization.
async fn organization_invites_list(
    base_url: &str,
    client: &Client,
    user: &TestUser,
    config: &crate::AuthConfig,
    organization_id: Uuid,
) -> Vec<OrganizationInvite> {
    let response = client
        .get(format!(
            "{base_url}{}",
            organization_invites_path(organization_id)
        ))
        .header(header::COOKIE, user.cookie_header(config))
        .send()
        .await
        .expect("organization invites list request");
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await
}

/// List members inside one organization.
async fn organization_members_list(
    base_url: &str,
    client: &Client,
    user: &TestUser,
    config: &crate::AuthConfig,
    organization_id: Uuid,
) -> Vec<OrganizationMember> {
    let response = client
        .get(format!(
            "{base_url}{}",
            organization_members_path(organization_id)
        ))
        .header(header::COOKIE, user.cookie_header(config))
        .send()
        .await
        .expect("organization members list request");
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await
}

/// Accept one organization invite and return the updated auth response.
async fn organization_invite_accept(
    base_url: &str,
    client: &Client,
    user: &mut TestUser,
    config: &crate::AuthConfig,
    token: &str,
) -> AuthResponse {
    let response = client
        .post(format!("{base_url}{}", organization_invite_accept_path()))
        .header(header::COOKIE, user.cookie_header(config))
        .json(&json!({ "token": token }))
        .send()
        .await
        .expect("organization invite accept request");
    assert_eq!(response.status(), StatusCode::OK);
    auth_response_with_cookie_update(response, user, config).await
}
