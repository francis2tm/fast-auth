use super::*;

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
