use super::*;

/// Invites should be creatable before the invited user signs up.
pub async fn organization_invite_accept_supports_user_created_after_invite<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let owner = TestUser::new(&base_url, &client, auth_config).await;
    let invitee_email = format!("invited+{}@example.com", Uuid::new_v4());
    let invitee_password = "SecurePass123";
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
        &invitee_email,
        OrganizationRole::Member,
    )
    .await;

    let sign_up_response = client
        .post(format!("{}{}", base_url, crate::handlers::SIGN_UP_PATH))
        .json(&json!({
            "email": invitee_email,
            "password": invitee_password,
        }))
        .send()
        .await
        .expect("invitee sign-up request");
    assert_eq!(sign_up_response.status(), StatusCode::OK);

    let mut invitee = TestUser {
        email: invitee_email.clone(),
        password: invitee_password.to_string(),
        access_token: TestUser::extract_cookie(
            sign_up_response.headers(),
            &auth_config.cookie_access_token_name,
        )
        .expect("sign-up should set access token cookie"),
        refresh_token: TestUser::extract_cookie(
            sign_up_response.headers(),
            &auth_config.cookie_refresh_token_name,
        )
        .expect("sign-up should set refresh token cookie"),
        api_key: None,
    };

    let payload =
        organization_invite_accept(&base_url, &client, &mut invitee, auth_config, &invite.token)
            .await;
    auth_response_assert(&payload, &invitee_email, OrganizationRole::Member);
    assert_eq!(payload.organization.id, organization_id.to_string());

    let memberships = organizations_list(&base_url, &client, &invitee, auth_config).await;
    assert!(
        memberships.iter().any(|membership| {
            membership.organization.id == organization_id
                && membership.email == invitee_email
                && membership.role == OrganizationRole::Member
        }),
        "newly created user should gain membership from the pre-existing invite",
    );
}

/// Concurrent acceptance of the same invite should have one winner.
pub async fn organization_invite_accept_race_has_single_winner<C: TestContext>() {
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
    let invite_cookie = invitee.cookie_header(auth_config);

    let accept_one = client
        .post(format!("{base_url}{}", organization_invite_accept_path()))
        .header(header::COOKIE, invite_cookie.clone())
        .json(&json!({ "token": invite.token.clone() }))
        .send();
    let accept_two = client
        .post(format!("{base_url}{}", organization_invite_accept_path()))
        .header(header::COOKIE, invite_cookie)
        .json(&json!({ "token": invite.token }))
        .send();

    let (accept_one, accept_two) = tokio::join!(accept_one, accept_two);
    let statuses = [accept_one, accept_two]
        .into_iter()
        .map(|response| response.expect("invite accept response").status())
        .collect::<Vec<_>>();
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::NOT_FOUND)
            .count(),
        1
    );

    let members =
        organization_members_list(&base_url, &client, &owner, auth_config, organization_id).await;
    assert_eq!(
        members
            .iter()
            .filter(|member| member.email == invitee.email)
            .count(),
        1,
        "race should create one membership row",
    );
}

/// Concurrent accept and revoke should leave one terminal invite state.
pub async fn organization_invite_accept_and_revoke_race_has_single_winner<C: TestContext>() {
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

    let accept_request = client
        .post(format!("{base_url}{}", organization_invite_accept_path()))
        .header(header::COOKIE, invitee.cookie_header(auth_config))
        .json(&json!({ "token": invite.token.clone() }))
        .send();
    let revoke_request = client
        .delete(format!(
            "{base_url}{}",
            organization_invite_path(organization_id, invite.invite.id)
        ))
        .header(header::COOKIE, owner.cookie_header(auth_config))
        .send();

    let (accept_response, revoke_response) = tokio::join!(accept_request, revoke_request);
    let statuses = [
        accept_response.expect("accept race response").status(),
        revoke_response.expect("revoke race response").status(),
    ];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::NOT_FOUND)
            .count(),
        1
    );

    let invites =
        organization_invites_list(&base_url, &client, &owner, auth_config, organization_id).await;
    let invite = invites
        .into_iter()
        .find(|candidate| candidate.id == invite.invite.id)
        .expect("invite should remain visible in history");
    assert_ne!(
        invite.accepted_at.is_some(),
        invite.revoked_at.is_some(),
        "invite should end in exactly one terminal state",
    );
}

/// Concurrent invite creation for the same email should leave one active invite.
pub async fn organization_invite_create_race_keeps_single_active_invite<C: TestContext>() {
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
    let owner_cookie = owner.cookie_header(auth_config);
    let invite_email = format!("  {}  ", invitee.email.to_uppercase());

    let create_one = client
        .post(format!(
            "{base_url}{}",
            organization_invites_path(organization_id)
        ))
        .header(header::COOKIE, owner_cookie.clone())
        .json(&json!({ "email": invite_email, "role": OrganizationRole::Member }))
        .send();
    let create_two = client
        .post(format!(
            "{base_url}{}",
            organization_invites_path(organization_id)
        ))
        .header(header::COOKIE, owner_cookie)
        .json(&json!({ "email": invitee.email, "role": OrganizationRole::Admin }))
        .send();

    let (create_one, create_two) = tokio::join!(create_one, create_two);
    let create_one = create_one.expect("first invite create response");
    let create_two = create_two.expect("second invite create response");
    assert_eq!(create_one.status(), StatusCode::OK);
    assert_eq!(create_two.status(), StatusCode::OK);
    let create_one: OrganizationInviteWithSecret = response_json(create_one).await;
    let create_two: OrganizationInviteWithSecret = response_json(create_two).await;

    let invites =
        organization_invites_list(&base_url, &client, &owner, auth_config, organization_id).await;
    let active_invites = invites
        .iter()
        .filter(|invite| invite.revoked_at.is_none() && invite.accepted_at.is_none())
        .collect::<Vec<_>>();
    assert_eq!(
        active_invites.len(),
        1,
        "race should leave one active invite"
    );

    let active_invite = active_invites[0];
    let (active_token, stale_token, expected_role) = if active_invite.id == create_one.invite.id {
        (create_one.token, create_two.token, create_one.invite.role)
    } else {
        (create_two.token, create_one.token, create_two.invite.role)
    };

    let stale_accept = client
        .post(format!("{base_url}{}", organization_invite_accept_path()))
        .header(header::COOKIE, invitee.cookie_header(auth_config))
        .json(&json!({ "token": stale_token }))
        .send()
        .await
        .expect("stale invite accept request");
    assert_eq!(stale_accept.status(), StatusCode::NOT_FOUND);

    let active_accept = client
        .post(format!("{base_url}{}", organization_invite_accept_path()))
        .header(header::COOKIE, invitee.cookie_header(auth_config))
        .json(&json!({ "token": active_token }))
        .send()
        .await
        .expect("active invite accept request");
    assert_eq!(active_accept.status(), StatusCode::OK);
    let active_accept: AuthResponse = response_json(active_accept).await;
    assert_eq!(active_accept.user.email, invitee.email);
    assert_eq!(active_accept.organization.id, organization_id.to_string());
    assert_eq!(active_accept.organization.role, expected_role);
}

/// Re-inviting the same email should replace the older active invite.
pub async fn organization_invite_create_replaces_existing_active_invite<C: TestContext>() {
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

    let first = organization_invite_create(
        &base_url,
        &client,
        &owner,
        auth_config,
        organization_id,
        &invitee.email,
        OrganizationRole::Member,
    )
    .await;
    let second = organization_invite_create(
        &base_url,
        &client,
        &owner,
        auth_config,
        organization_id,
        &format!("  {}  ", invitee.email.to_uppercase()),
        OrganizationRole::Admin,
    )
    .await;

    let invites =
        organization_invites_list(&base_url, &client, &owner, auth_config, organization_id).await;
    let active_invites = invites
        .iter()
        .filter(|invite| invite.revoked_at.is_none() && invite.accepted_at.is_none())
        .collect::<Vec<_>>();
    assert_eq!(
        active_invites.len(),
        1,
        "only one invite should remain active"
    );
    assert_eq!(active_invites[0].id, second.invite.id);
    assert_eq!(active_invites[0].email, invitee.email);
    assert_eq!(active_invites[0].role, OrganizationRole::Admin);
    assert!(
        invites
            .iter()
            .any(|invite| invite.id == first.invite.id && invite.revoked_at.is_some()),
        "older invite should be revoked when replaced",
    );

    let stale_response = client
        .post(format!("{base_url}{}", organization_invite_accept_path()))
        .header(header::COOKIE, invitee.cookie_header(auth_config))
        .json(&json!({ "token": first.token }))
        .send()
        .await
        .expect("stale invite accept request");
    assert_eq!(stale_response.status(), StatusCode::NOT_FOUND);

    let payload =
        organization_invite_accept(&base_url, &client, &mut invitee, auth_config, &second.token)
            .await;
    auth_response_assert(&payload, &invitee.email, OrganizationRole::Admin);
    assert_eq!(payload.organization.id, organization_id.to_string());
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
