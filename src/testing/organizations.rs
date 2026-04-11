//! Organization, membership, and invite test functions.

use reqwest::{Client, Response, StatusCode, header};
use serde::de::DeserializeOwned;
use serde_json::json;
use uuid::Uuid;

use crate::handlers::ORGANIZATIONS_PATH;
use crate::{
    AuthResponse, Organization, OrganizationInvite, OrganizationInviteWithSecret,
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

/// Organizations should include the default membership and support CRUD.
pub async fn organizations_include_default_membership_and_support_crud<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let user = TestUser::new(&base_url, &client, auth_config).await;

    let me = me_get(&base_url, &client, &user, auth_config).await;
    auth_response_assert(&me, &user.email, OrganizationRole::Owner);

    let organizations = organizations_list(&base_url, &client, &user, auth_config).await;
    assert_eq!(
        organizations.len(),
        1,
        "sign-up should provision one organization"
    );
    assert_eq!(organizations[0].email, user.email);
    assert_eq!(organizations[0].role, OrganizationRole::Owner);
    assert_eq!(
        organizations[0].organization.id.to_string(),
        me.organization.id
    );
    assert_eq!(organizations[0].organization.name, me.organization.name);

    let created = organization_create(&base_url, &client, &user, auth_config, "Platform").await;
    assert_eq!(created.email, user.email);
    assert_eq!(created.role, OrganizationRole::Owner);
    assert_eq!(created.organization.name, "Platform");

    let get_response = client
        .get(format!(
            "{base_url}{}",
            organization_path(created.organization.id)
        ))
        .header(header::COOKIE, user.cookie_header(auth_config))
        .send()
        .await
        .expect("organization get request");
    assert_eq!(get_response.status(), StatusCode::OK);
    let fetched: OrganizationMember = response_json(get_response).await;
    assert_eq!(fetched.organization.id, created.organization.id);
    assert_eq!(fetched.organization.name, created.organization.name);

    let update_response = client
        .patch(format!(
            "{base_url}{}",
            organization_path(created.organization.id)
        ))
        .header(header::COOKIE, user.cookie_header(auth_config))
        .json(&json!({ "name": "Platform Ops" }))
        .send()
        .await
        .expect("organization update request");
    assert_eq!(update_response.status(), StatusCode::OK);
    let updated: OrganizationMember = response_json(update_response).await;
    assert_eq!(updated.organization.id, created.organization.id);
    assert_eq!(updated.organization.name, "Platform Ops");

    let delete_response = client
        .delete(format!(
            "{base_url}{}",
            organization_path(created.organization.id)
        ))
        .header(header::COOKIE, user.cookie_header(auth_config))
        .send()
        .await
        .expect("organization delete request");
    assert_eq!(delete_response.status(), StatusCode::OK);
    let deleted: Organization = response_json(delete_response).await;
    assert_eq!(deleted.id, created.organization.id);

    let organizations_after = organizations_list(&base_url, &client, &user, auth_config).await;
    assert_eq!(
        organizations_after.len(),
        1,
        "delete should remove the new organization"
    );
    assert_eq!(
        organizations_after[0].organization.id.to_string(),
        me.organization.id
    );
}

/// Non-members must not be able to load one organization.
pub async fn organization_get_rejects_non_member<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let owner = TestUser::new(&base_url, &client, auth_config).await;
    let stranger = TestUser::new(&base_url, &client, auth_config).await;
    let organization_id = Uuid::parse_str(
        &me_get(&base_url, &client, &owner, auth_config)
            .await
            .organization
            .id,
    )
    .expect("organization id");

    let response = client
        .get(format!("{base_url}{}", organization_path(organization_id)))
        .header(header::COOKIE, stranger.cookie_header(auth_config))
        .send()
        .await
        .expect("organization get request");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Switching organizations should update cookies and `/auth/me`.
pub async fn organization_switch_updates_active_auth_context<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let mut user = TestUser::new(&base_url, &client, auth_config).await;
    let organization = organization_create(&base_url, &client, &user, auth_config, "Secondary")
        .await
        .organization;

    let response = client
        .post(format!("{base_url}{}", organization_current_path()))
        .header(header::COOKIE, user.cookie_header(auth_config))
        .json(&json!({ "organization_id": organization.id }))
        .send()
        .await
        .expect("organization switch request");
    assert_eq!(response.status(), StatusCode::OK);

    let headers = response.headers().clone();
    let payload: AuthResponse = response_json(response).await;
    user.auth_cookies_replace(&headers, auth_config);

    auth_response_assert(&payload, &user.email, OrganizationRole::Owner);
    assert_eq!(payload.organization.id, organization.id.to_string());
    assert_eq!(payload.organization.name, organization.name);

    let me = me_get(&base_url, &client, &user, auth_config).await;
    assert_eq!(me.organization.id, organization.id.to_string());
    assert_eq!(me.organization.name, organization.name);
    assert_eq!(me.organization.role, OrganizationRole::Owner);
}

/// Switching to an organization outside the caller membership must fail.
pub async fn organization_switch_rejects_non_member_organization<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let owner = TestUser::new(&base_url, &client, auth_config).await;
    let stranger = TestUser::new(&base_url, &client, auth_config).await;
    let organization_id = Uuid::parse_str(
        &me_get(&base_url, &client, &owner, auth_config)
            .await
            .organization
            .id,
    )
    .expect("organization id");

    let response = client
        .post(format!("{base_url}{}", organization_current_path()))
        .header(header::COOKIE, stranger.cookie_header(auth_config))
        .json(&json!({ "organization_id": organization_id }))
        .send()
        .await
        .expect("organization switch request");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Switching organizations must survive refresh and sign-in.
pub async fn organization_switch_then_refresh_keeps_selected_org<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let mut user = TestUser::new(&base_url, &client, auth_config).await;
    let organization = organization_create(&base_url, &client, &user, auth_config, "Secondary")
        .await
        .organization;

    let switch_response = client
        .post(format!("{base_url}{}", organization_current_path()))
        .header(header::COOKIE, user.cookie_header(auth_config))
        .json(&json!({ "organization_id": organization.id }))
        .send()
        .await
        .expect("organization switch request");
    assert_eq!(switch_response.status(), StatusCode::OK);
    let switch_payload =
        auth_response_with_cookie_update(switch_response, &mut user, auth_config).await;

    auth_response_assert(&switch_payload, &user.email, OrganizationRole::Owner);
    assert_eq!(switch_payload.organization.id, organization.id.to_string());

    let refresh_payload = auth_refresh(&base_url, &client, &mut user, auth_config).await;
    auth_response_assert(&refresh_payload, &user.email, OrganizationRole::Owner);
    assert_eq!(refresh_payload.organization.id, organization.id.to_string());

    let sign_in_payload = auth_sign_in(&base_url, &client, &mut user, auth_config).await;
    auth_response_assert(&sign_in_payload, &user.email, OrganizationRole::Owner);
    assert_eq!(sign_in_payload.organization.id, organization.id.to_string());

    let me = me_get(&base_url, &client, &user, auth_config).await;
    assert_eq!(me.organization.id, organization.id.to_string());
    assert_eq!(me.organization.role, OrganizationRole::Owner);
}

/// Invite acceptance should add membership and switch the active organization.
pub async fn organization_invite_accept_adds_membership_and_switches_context<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let owner = TestUser::new(&base_url, &client, auth_config).await;
    let mut invitee = TestUser::new(&base_url, &client, auth_config).await;
    let organization_id = Uuid::parse_str(
        &me_get(&base_url, &client, &owner, auth_config)
            .await
            .organization
            .id,
    )
    .expect("organization id");

    let invite = organization_invite_create(
        &base_url,
        &client,
        &owner,
        auth_config,
        organization_id,
        &invitee.email,
        OrganizationRole::Member,
    )
    .await;

    let invites =
        organization_invites_list(&base_url, &client, &owner, auth_config, organization_id).await;
    assert!(
        invites
            .iter()
            .any(|candidate| candidate.id == invite.invite.id),
        "created invite should appear in list",
    );

    let payload =
        organization_invite_accept(&base_url, &client, &mut invitee, auth_config, &invite.token)
            .await;
    auth_response_assert(&payload, &invitee.email, OrganizationRole::Member);
    assert_eq!(payload.organization.id, organization_id.to_string());

    let memberships = organizations_list(&base_url, &client, &invitee, auth_config).await;
    assert_eq!(
        memberships.len(),
        2,
        "invitee should see both organizations"
    );
    assert!(
        memberships.iter().any(|membership| {
            membership.organization.id == organization_id
                && membership.email == invitee.email
                && membership.role == OrganizationRole::Member
        }),
        "invitee should gain member access to the invited organization",
    );

    let members =
        organization_members_list(&base_url, &client, &owner, auth_config, organization_id).await;
    assert!(
        members.iter().any(|member| {
            member.email == invitee.email && member.role == OrganizationRole::Member
        }),
        "owner should see the accepted member",
    );

    let me = me_get(&base_url, &client, &invitee, auth_config).await;
    assert_eq!(me.organization.id, organization_id.to_string());
    assert_eq!(me.organization.role, OrganizationRole::Member);
}

/// Revoked invites must not be accepted.
pub async fn organization_invite_revoke_prevents_acceptance<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let owner = TestUser::new(&base_url, &client, auth_config).await;
    let invitee = TestUser::new(&base_url, &client, auth_config).await;
    let organization_id = Uuid::parse_str(
        &me_get(&base_url, &client, &owner, auth_config)
            .await
            .organization
            .id,
    )
    .expect("organization id");

    let invite = organization_invite_create(
        &base_url,
        &client,
        &owner,
        auth_config,
        organization_id,
        &invitee.email,
        OrganizationRole::Member,
    )
    .await;

    let revoke_response = client
        .delete(format!(
            "{base_url}{}",
            organization_invite_path(organization_id, invite.invite.id)
        ))
        .header(header::COOKIE, owner.cookie_header(auth_config))
        .send()
        .await
        .expect("organization invite revoke request");
    assert_eq!(revoke_response.status(), StatusCode::OK);
    let revoked: OrganizationInvite = response_json(revoke_response).await;
    assert!(
        revoked.revoked_at.is_some(),
        "revoke should timestamp the invite"
    );

    let accept_response = client
        .post(format!("{base_url}{}", organization_invite_accept_path()))
        .header(header::COOKIE, invitee.cookie_header(auth_config))
        .json(&json!({ "token": invite.token }))
        .send()
        .await
        .expect("organization invite accept request");
    assert_eq!(accept_response.status(), StatusCode::NOT_FOUND);
}

/// Invites must reject authenticated users with the wrong email.
pub async fn organization_invite_accept_rejects_wrong_email<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let owner = TestUser::new(&base_url, &client, auth_config).await;
    let invitee = TestUser::new(&base_url, &client, auth_config).await;
    let stranger = TestUser::new(&base_url, &client, auth_config).await;
    let organization_id = Uuid::parse_str(
        &me_get(&base_url, &client, &owner, auth_config)
            .await
            .organization
            .id,
    )
    .expect("organization id");

    let invite = organization_invite_create(
        &base_url,
        &client,
        &owner,
        auth_config,
        organization_id,
        &invitee.email,
        OrganizationRole::Member,
    )
    .await;

    let response = client
        .post(format!("{base_url}{}", organization_invite_accept_path()))
        .header(header::COOKIE, stranger.cookie_header(auth_config))
        .json(&json!({ "token": invite.token }))
        .send()
        .await
        .expect("organization invite accept request");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// Invites must become single-use after one successful acceptance.
pub async fn organization_invite_accept_rejects_reuse<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let owner = TestUser::new(&base_url, &client, auth_config).await;
    let mut invitee = TestUser::new(&base_url, &client, auth_config).await;
    let organization_id = Uuid::parse_str(
        &me_get(&base_url, &client, &owner, auth_config)
            .await
            .organization
            .id,
    )
    .expect("organization id");

    let invite = organization_invite_create(
        &base_url,
        &client,
        &owner,
        auth_config,
        organization_id,
        &invitee.email,
        OrganizationRole::Member,
    )
    .await;

    organization_invite_accept(&base_url, &client, &mut invitee, auth_config, &invite.token).await;

    let replay = client
        .post(format!("{base_url}{}", organization_invite_accept_path()))
        .header(header::COOKIE, invitee.cookie_header(auth_config))
        .json(&json!({ "token": invite.token }))
        .send()
        .await
        .expect("organization invite replay request");
    assert_eq!(replay.status(), StatusCode::NOT_FOUND);
}

/// Member sessions must be denied from admin-only organization routes.
pub async fn organization_member_role_gates_admin_routes<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let owner = TestUser::new(&base_url, &client, auth_config).await;
    let mut member = TestUser::new(&base_url, &client, auth_config).await;
    let organization_id = Uuid::parse_str(
        &me_get(&base_url, &client, &owner, auth_config)
            .await
            .organization
            .id,
    )
    .expect("organization id");

    let member_invite = organization_invite_create(
        &base_url,
        &client,
        &owner,
        auth_config,
        organization_id,
        &member.email,
        OrganizationRole::Member,
    )
    .await;
    let pending_invite = organization_invite_create(
        &base_url,
        &client,
        &owner,
        auth_config,
        organization_id,
        &format!("pending+{}@example.com", Uuid::new_v4()),
        OrganizationRole::Member,
    )
    .await;

    organization_invite_accept(
        &base_url,
        &client,
        &mut member,
        auth_config,
        &member_invite.token,
    )
    .await;

    let members_response = client
        .get(format!(
            "{base_url}{}",
            organization_members_path(organization_id)
        ))
        .header(header::COOKIE, member.cookie_header(auth_config))
        .send()
        .await
        .expect("member list members request");
    assert_eq!(members_response.status(), StatusCode::FORBIDDEN);

    let invites_response = client
        .get(format!(
            "{base_url}{}",
            organization_invites_path(organization_id)
        ))
        .header(header::COOKIE, member.cookie_header(auth_config))
        .send()
        .await
        .expect("member list invites request");
    assert_eq!(invites_response.status(), StatusCode::FORBIDDEN);

    let create_response = client
        .post(format!(
            "{base_url}{}",
            organization_invites_path(organization_id)
        ))
        .header(header::COOKIE, member.cookie_header(auth_config))
        .json(&json!({
            "email": format!("blocked+{}@example.com", Uuid::new_v4()),
            "role": OrganizationRole::Member,
        }))
        .send()
        .await
        .expect("member create invite request");
    assert_eq!(create_response.status(), StatusCode::FORBIDDEN);

    let revoke_response = client
        .delete(format!(
            "{base_url}{}",
            organization_invite_path(organization_id, pending_invite.invite.id)
        ))
        .header(header::COOKIE, member.cookie_header(auth_config))
        .send()
        .await
        .expect("member revoke invite request");
    assert_eq!(revoke_response.status(), StatusCode::FORBIDDEN);

    let delete_response = client
        .delete(format!("{base_url}{}", organization_path(organization_id)))
        .header(header::COOKIE, member.cookie_header(auth_config))
        .send()
        .await
        .expect("member delete organization request");
    assert_eq!(delete_response.status(), StatusCode::FORBIDDEN);
}

/// Deleting the active organization must not leave auth in an invalid state.
pub async fn organization_delete_active_org_preserves_auth_or_is_rejected<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let mut user = TestUser::new(&base_url, &client, auth_config).await;
    let organization = organization_create(&base_url, &client, &user, auth_config, "Secondary")
        .await
        .organization;

    let switch_response = client
        .post(format!("{base_url}{}", organization_current_path()))
        .header(header::COOKIE, user.cookie_header(auth_config))
        .json(&json!({ "organization_id": organization.id }))
        .send()
        .await
        .expect("organization switch request");
    assert_eq!(switch_response.status(), StatusCode::OK);
    let _: AuthResponse =
        auth_response_with_cookie_update(switch_response, &mut user, auth_config).await;

    let delete_response = client
        .delete(format!("{base_url}{}", organization_path(organization.id)))
        .header(header::COOKIE, user.cookie_header(auth_config))
        .send()
        .await
        .expect("organization delete request");
    assert_eq!(delete_response.status(), StatusCode::FORBIDDEN);

    let me = me_get(&base_url, &client, &user, auth_config).await;
    assert_eq!(me.organization.id, organization.id.to_string());
    assert_eq!(me.organization.role, OrganizationRole::Owner);

    let refresh_payload = auth_refresh(&base_url, &client, &mut user, auth_config).await;
    assert_eq!(refresh_payload.organization.id, organization.id.to_string());

    let sign_in_payload = auth_sign_in(&base_url, &client, &mut user, auth_config).await;
    assert_eq!(sign_in_payload.organization.id, organization.id.to_string());
}

/// Deleting the default personal organization must fail even when inactive.
pub async fn organization_delete_personal_org_when_inactive_is_rejected<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let mut user = TestUser::new(&base_url, &client, auth_config).await;
    let personal_organization_id = Uuid::parse_str(
        &me_get(&base_url, &client, &user, auth_config)
            .await
            .organization
            .id,
    )
    .expect("personal organization id");
    let organization = organization_create(&base_url, &client, &user, auth_config, "Secondary")
        .await
        .organization;

    let switch_response = client
        .post(format!("{base_url}{}", organization_current_path()))
        .header(header::COOKIE, user.cookie_header(auth_config))
        .json(&json!({ "organization_id": organization.id }))
        .send()
        .await
        .expect("organization switch request");
    assert_eq!(switch_response.status(), StatusCode::OK);
    let _: AuthResponse =
        auth_response_with_cookie_update(switch_response, &mut user, auth_config).await;

    let delete_response = client
        .delete(format!(
            "{base_url}{}",
            organization_path(personal_organization_id)
        ))
        .header(header::COOKIE, user.cookie_header(auth_config))
        .send()
        .await
        .expect("personal organization delete request");
    assert_eq!(delete_response.status(), StatusCode::FORBIDDEN);
}

/// Cross-organization admin access should resolve as not found.
pub async fn organization_cross_org_admin_routes_return_not_found<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let owner_one = TestUser::new(&base_url, &client, auth_config).await;
    let owner_two = TestUser::new(&base_url, &client, auth_config).await;
    let organization_id = Uuid::parse_str(
        &me_get(&base_url, &client, &owner_one, auth_config)
            .await
            .organization
            .id,
    )
    .expect("organization id");

    let members_response = client
        .get(format!(
            "{base_url}{}",
            organization_members_path(organization_id)
        ))
        .header(header::COOKIE, owner_two.cookie_header(auth_config))
        .send()
        .await
        .expect("cross-org members request");
    assert_eq!(members_response.status(), StatusCode::NOT_FOUND);

    let update_response = client
        .patch(format!("{base_url}{}", organization_path(organization_id)))
        .header(header::COOKIE, owner_two.cookie_header(auth_config))
        .json(&json!({ "name": "nope" }))
        .send()
        .await
        .expect("cross-org update request");
    assert_eq!(update_response.status(), StatusCode::NOT_FOUND);

    let invite_response = client
        .post(format!(
            "{base_url}{}",
            organization_invites_path(organization_id)
        ))
        .header(header::COOKIE, owner_two.cookie_header(auth_config))
        .json(&json!({
            "email": format!("missing+{}@example.com", Uuid::new_v4()),
            "role": OrganizationRole::Member,
        }))
        .send()
        .await
        .expect("cross-org invite request");
    assert_eq!(invite_response.status(), StatusCode::NOT_FOUND);

    let delete_response = client
        .delete(format!("{base_url}{}", organization_path(organization_id)))
        .header(header::COOKIE, owner_two.cookie_header(auth_config))
        .send()
        .await
        .expect("cross-org delete request");
    assert_eq!(delete_response.status(), StatusCode::NOT_FOUND);
}

/// Only organization owners should be able to change member roles.
pub async fn organization_member_role_update_requires_owner<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let owner = TestUser::new(&base_url, &client, auth_config).await;
    let mut admin = TestUser::new(&base_url, &client, auth_config).await;
    let mut member = TestUser::new(&base_url, &client, auth_config).await;
    let owner_me = me_get(&base_url, &client, &owner, auth_config).await;
    let organization_id = Uuid::parse_str(&owner_me.organization.id).expect("organization id");

    let admin_invite = organization_invite_create(
        &base_url,
        &client,
        &owner,
        auth_config,
        organization_id,
        &admin.email,
        OrganizationRole::Admin,
    )
    .await;
    let member_invite = organization_invite_create(
        &base_url,
        &client,
        &owner,
        auth_config,
        organization_id,
        &member.email,
        OrganizationRole::Member,
    )
    .await;

    organization_invite_accept(
        &base_url,
        &client,
        &mut admin,
        auth_config,
        &admin_invite.token,
    )
    .await;
    let member_payload = organization_invite_accept(
        &base_url,
        &client,
        &mut member,
        auth_config,
        &member_invite.token,
    )
    .await;
    let member_user_id = Uuid::parse_str(&member_payload.user.id).expect("member user id");

    let admin_update_response = client
        .patch(format!(
            "{base_url}{}",
            organization_member_path(organization_id, member_user_id)
        ))
        .header(header::COOKIE, admin.cookie_header(auth_config))
        .json(&json!({ "role": OrganizationRole::Admin }))
        .send()
        .await
        .expect("admin update member role request");
    assert_eq!(admin_update_response.status(), StatusCode::FORBIDDEN);

    let owner_update_response = client
        .patch(format!(
            "{base_url}{}",
            organization_member_path(organization_id, member_user_id)
        ))
        .header(header::COOKIE, owner.cookie_header(auth_config))
        .json(&json!({ "role": OrganizationRole::Admin }))
        .send()
        .await
        .expect("owner update member role request");
    assert_eq!(owner_update_response.status(), StatusCode::OK);
    let updated_member: OrganizationMember = response_json(owner_update_response).await;
    assert_eq!(updated_member.user_id, member_user_id);
    assert_eq!(updated_member.role, OrganizationRole::Admin);
}

/// Admins must not be able to invite new owners.
pub async fn organization_admin_cannot_invite_owner<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let owner = TestUser::new(&base_url, &client, auth_config).await;
    let mut admin = TestUser::new(&base_url, &client, auth_config).await;
    let organization_id = Uuid::parse_str(
        &me_get(&base_url, &client, &owner, auth_config)
            .await
            .organization
            .id,
    )
    .expect("organization id");

    let admin_invite = organization_invite_create(
        &base_url,
        &client,
        &owner,
        auth_config,
        organization_id,
        &admin.email,
        OrganizationRole::Admin,
    )
    .await;
    organization_invite_accept(
        &base_url,
        &client,
        &mut admin,
        auth_config,
        &admin_invite.token,
    )
    .await;

    let response = client
        .post(format!(
            "{base_url}{}",
            organization_invites_path(organization_id)
        ))
        .header(header::COOKIE, admin.cookie_header(auth_config))
        .json(&json!({
            "email": format!("owner+{}@example.com", Uuid::new_v4()),
            "role": OrganizationRole::Owner,
        }))
        .send()
        .await
        .expect("admin invite owner request");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// Role changes must be reflected by later refresh and sign-in flows.
pub async fn organization_role_change_is_visible_after_refresh_and_sign_in<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let owner = TestUser::new(&base_url, &client, auth_config).await;
    let mut admin = TestUser::new(&base_url, &client, auth_config).await;
    let owner_me = me_get(&base_url, &client, &owner, auth_config).await;
    let organization_id = Uuid::parse_str(&owner_me.organization.id).expect("organization id");

    let admin_invite = organization_invite_create(
        &base_url,
        &client,
        &owner,
        auth_config,
        organization_id,
        &admin.email,
        OrganizationRole::Admin,
    )
    .await;
    let admin_payload = organization_invite_accept(
        &base_url,
        &client,
        &mut admin,
        auth_config,
        &admin_invite.token,
    )
    .await;
    auth_response_assert(&admin_payload, &admin.email, OrganizationRole::Admin);
    let admin_user_id = Uuid::parse_str(&admin_payload.user.id).expect("admin user id");

    let demote_response = client
        .patch(format!(
            "{base_url}{}",
            organization_member_path(organization_id, admin_user_id)
        ))
        .header(header::COOKIE, owner.cookie_header(auth_config))
        .json(&json!({ "role": OrganizationRole::Member }))
        .send()
        .await
        .expect("demote admin request");
    assert_eq!(demote_response.status(), StatusCode::OK);
    let demoted_member: OrganizationMember = response_json(demote_response).await;
    assert_eq!(demoted_member.role, OrganizationRole::Member);

    let refresh_payload = auth_refresh(&base_url, &client, &mut admin, auth_config).await;
    auth_response_assert(&refresh_payload, &admin.email, OrganizationRole::Member);
    assert_eq!(refresh_payload.organization.id, organization_id.to_string());

    let sign_in_payload = auth_sign_in(&base_url, &client, &mut admin, auth_config).await;
    auth_response_assert(&sign_in_payload, &admin.email, OrganizationRole::Member);
    assert_eq!(sign_in_payload.organization.id, organization_id.to_string());

    let members_response = client
        .get(format!(
            "{base_url}{}",
            organization_members_path(organization_id)
        ))
        .header(header::COOKIE, admin.cookie_header(auth_config))
        .send()
        .await
        .expect("member list members request");
    assert_eq!(members_response.status(), StatusCode::FORBIDDEN);
}

/// Admin sessions should still manage invites and member deletion inside their organization.
pub async fn organization_admin_can_manage_members_and_invites<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let owner = TestUser::new(&base_url, &client, auth_config).await;
    let mut admin = TestUser::new(&base_url, &client, auth_config).await;
    let mut member = TestUser::new(&base_url, &client, auth_config).await;
    let owner_me = me_get(&base_url, &client, &owner, auth_config).await;
    let organization_id = Uuid::parse_str(&owner_me.organization.id).expect("organization id");

    let admin_invite = organization_invite_create(
        &base_url,
        &client,
        &owner,
        auth_config,
        organization_id,
        &admin.email,
        OrganizationRole::Admin,
    )
    .await;
    let member_invite = organization_invite_create(
        &base_url,
        &client,
        &owner,
        auth_config,
        organization_id,
        &member.email,
        OrganizationRole::Member,
    )
    .await;

    let admin_payload = organization_invite_accept(
        &base_url,
        &client,
        &mut admin,
        auth_config,
        &admin_invite.token,
    )
    .await;
    auth_response_assert(&admin_payload, &admin.email, OrganizationRole::Admin);
    let admin_user_id = Uuid::parse_str(&admin_payload.user.id).expect("admin user id");

    let member_payload = organization_invite_accept(
        &base_url,
        &client,
        &mut member,
        auth_config,
        &member_invite.token,
    )
    .await;
    auth_response_assert(&member_payload, &member.email, OrganizationRole::Member);
    let member_user_id = Uuid::parse_str(&member_payload.user.id).expect("member user id");

    let admin_created_invite = organization_invite_create(
        &base_url,
        &client,
        &admin,
        auth_config,
        organization_id,
        &format!("admin-pending+{}@example.com", Uuid::new_v4()),
        OrganizationRole::Member,
    )
    .await;
    assert_eq!(
        admin_created_invite.invite.invited_by_user_id,
        admin_user_id
    );

    let invites =
        organization_invites_list(&base_url, &client, &admin, auth_config, organization_id).await;
    assert!(
        invites
            .iter()
            .any(|invite| invite.id == admin_created_invite.invite.id),
        "admin-created invite should be listable",
    );

    let revoke_response = client
        .delete(format!(
            "{base_url}{}",
            organization_invite_path(organization_id, admin_created_invite.invite.id)
        ))
        .header(header::COOKIE, admin.cookie_header(auth_config))
        .send()
        .await
        .expect("admin revoke invite request");
    assert_eq!(revoke_response.status(), StatusCode::OK);
    let revoked: OrganizationInvite = response_json(revoke_response).await;
    assert!(revoked.revoked_at.is_some());

    let delete_response = client
        .delete(format!(
            "{base_url}{}",
            organization_member_path(organization_id, member_user_id)
        ))
        .header(header::COOKIE, admin.cookie_header(auth_config))
        .send()
        .await
        .expect("admin delete member request");
    assert_eq!(delete_response.status(), StatusCode::OK);
    let deleted_member: OrganizationMember = response_json(delete_response).await;
    assert_eq!(deleted_member.user_id, member_user_id);

    let members =
        organization_members_list(&base_url, &client, &owner, auth_config, organization_id).await;
    assert!(
        members
            .iter()
            .all(|member| member.user_id != member_user_id),
        "deleted member should no longer appear in the organization roster",
    );
}

/// Deleting one active membership must not strand the affected auth context.
pub async fn organization_member_delete_active_membership_preserves_auth_or_clears_session_consistently<
    C: TestContext,
>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let owner = TestUser::new(&base_url, &client, auth_config).await;
    let mut member = TestUser::new(&base_url, &client, auth_config).await;
    let owner_me = me_get(&base_url, &client, &owner, auth_config).await;
    let organization_id = Uuid::parse_str(&owner_me.organization.id).expect("organization id");

    let member_invite = organization_invite_create(
        &base_url,
        &client,
        &owner,
        auth_config,
        organization_id,
        &member.email,
        OrganizationRole::Member,
    )
    .await;
    let member_payload = organization_invite_accept(
        &base_url,
        &client,
        &mut member,
        auth_config,
        &member_invite.token,
    )
    .await;
    let member_user_id = Uuid::parse_str(&member_payload.user.id).expect("member user id");

    let delete_response = client
        .delete(format!(
            "{base_url}{}",
            organization_member_path(organization_id, member_user_id)
        ))
        .header(header::COOKIE, owner.cookie_header(auth_config))
        .send()
        .await
        .expect("delete active membership request");
    assert_eq!(delete_response.status(), StatusCode::FORBIDDEN);

    let me = me_get(&base_url, &client, &member, auth_config).await;
    assert_eq!(me.organization.id, organization_id.to_string());
    assert_eq!(me.organization.role, OrganizationRole::Member);

    let refresh_payload = auth_refresh(&base_url, &client, &mut member, auth_config).await;
    assert_eq!(refresh_payload.organization.id, organization_id.to_string());

    let sign_in_payload = auth_sign_in(&base_url, &client, &mut member, auth_config).await;
    assert_eq!(sign_in_payload.organization.id, organization_id.to_string());
}

/// Admins must not be able to delete owner memberships.
pub async fn organization_admin_cannot_delete_owner<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let owner = TestUser::new(&base_url, &client, auth_config).await;
    let mut admin = TestUser::new(&base_url, &client, auth_config).await;
    let mut co_owner = TestUser::new(&base_url, &client, auth_config).await;
    let owner_me = me_get(&base_url, &client, &owner, auth_config).await;
    let organization_id = Uuid::parse_str(&owner_me.organization.id).expect("organization id");

    let admin_invite = organization_invite_create(
        &base_url,
        &client,
        &owner,
        auth_config,
        organization_id,
        &admin.email,
        OrganizationRole::Admin,
    )
    .await;
    let owner_invite = organization_invite_create(
        &base_url,
        &client,
        &owner,
        auth_config,
        organization_id,
        &co_owner.email,
        OrganizationRole::Owner,
    )
    .await;

    organization_invite_accept(
        &base_url,
        &client,
        &mut admin,
        auth_config,
        &admin_invite.token,
    )
    .await;
    let owner_payload = organization_invite_accept(
        &base_url,
        &client,
        &mut co_owner,
        auth_config,
        &owner_invite.token,
    )
    .await;
    let co_owner_user_id = Uuid::parse_str(&owner_payload.user.id).expect("co-owner user id");

    let delete_response = client
        .delete(format!(
            "{base_url}{}",
            organization_member_path(organization_id, co_owner_user_id)
        ))
        .header(header::COOKIE, admin.cookie_header(auth_config))
        .send()
        .await
        .expect("admin delete owner request");
    assert_eq!(delete_response.status(), StatusCode::FORBIDDEN);

    let members =
        organization_members_list(&base_url, &client, &owner, auth_config, organization_id).await;
    assert!(
        members
            .iter()
            .any(|member| member.user_id == co_owner_user_id),
        "owner membership should remain present",
    );
}

/// A user must remain owner/member of their own personal organization.
pub async fn organization_personal_org_membership_cannot_be_demoted_or_removed<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let owner = TestUser::new(&base_url, &client, auth_config).await;
    let mut co_owner = TestUser::new(&base_url, &client, auth_config).await;
    let owner_me = me_get(&base_url, &client, &owner, auth_config).await;
    let organization_id = Uuid::parse_str(&owner_me.organization.id).expect("organization id");
    let owner_user_id = Uuid::parse_str(&owner_me.user.id).expect("owner user id");

    let owner_invite = organization_invite_create(
        &base_url,
        &client,
        &owner,
        auth_config,
        organization_id,
        &co_owner.email,
        OrganizationRole::Owner,
    )
    .await;

    organization_invite_accept(
        &base_url,
        &client,
        &mut co_owner,
        auth_config,
        &owner_invite.token,
    )
    .await;

    let demote_response = client
        .patch(format!(
            "{base_url}{}",
            organization_member_path(organization_id, owner_user_id)
        ))
        .header(header::COOKIE, co_owner.cookie_header(auth_config))
        .json(&json!({ "role": OrganizationRole::Admin }))
        .send()
        .await
        .expect("personal owner demote request");
    assert_eq!(demote_response.status(), StatusCode::FORBIDDEN);

    let delete_response = client
        .delete(format!(
            "{base_url}{}",
            organization_member_path(organization_id, owner_user_id)
        ))
        .header(header::COOKIE, co_owner.cookie_header(auth_config))
        .send()
        .await
        .expect("personal owner delete request");
    assert_eq!(delete_response.status(), StatusCode::FORBIDDEN);

    let members =
        organization_members_list(&base_url, &client, &owner, auth_config, organization_id).await;
    assert!(
        members
            .iter()
            .any(|member| member.user_id == owner_user_id && member.role == OrganizationRole::Owner),
        "personal owner membership should remain present and owned",
    );
}

/// The final remaining owner must not be demoted or removed.
pub async fn organization_last_owner_cannot_be_demoted_or_removed<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let owner = TestUser::new(&base_url, &client, auth_config).await;
    let owner_me = me_get(&base_url, &client, &owner, auth_config).await;
    let organization_id = Uuid::parse_str(&owner_me.organization.id).expect("organization id");
    let owner_user_id = Uuid::parse_str(&owner_me.user.id).expect("owner user id");

    let demote_response = client
        .patch(format!(
            "{base_url}{}",
            organization_member_path(organization_id, owner_user_id)
        ))
        .header(header::COOKIE, owner.cookie_header(auth_config))
        .json(&json!({ "role": OrganizationRole::Admin }))
        .send()
        .await
        .expect("last owner demote request");
    assert_eq!(demote_response.status(), StatusCode::FORBIDDEN);

    let delete_response = client
        .delete(format!(
            "{base_url}{}",
            organization_member_path(organization_id, owner_user_id)
        ))
        .header(header::COOKIE, owner.cookie_header(auth_config))
        .send()
        .await
        .expect("last owner delete request");
    assert_eq!(delete_response.status(), StatusCode::FORBIDDEN);

    let me = me_get(&base_url, &client, &owner, auth_config).await;
    assert_eq!(me.organization.id, organization_id.to_string());
    assert_eq!(me.organization.role, OrganizationRole::Owner);
}
