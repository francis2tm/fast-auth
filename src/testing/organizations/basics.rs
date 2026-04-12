use super::*;

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
