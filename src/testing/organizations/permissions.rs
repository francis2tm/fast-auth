use super::*;

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
