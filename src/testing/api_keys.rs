//! API key test functions.

use reqwest::{StatusCode, header};
use serde_json::json;

use crate::handlers::{API_KEYS_PATH, ME_PATH, ORGANIZATIONS_PATH};
use crate::{AuthResponse, OrganizationKind, OrganizationMember, OrganizationRole};

use super::{TestContext, TestUser, auth_response_assert, me_get};

/// API keys should be creatable, usable, listable, and deletable.
pub async fn api_key_create_list_use_delete_flow<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let mut user = TestUser::new(&base_url, &client, auth_config).await;
    let me = me_get(&base_url, &client, &user, auth_config).await;

    let api_key = user
        .api_key_create(&base_url, &client, auth_config, "integration")
        .await;

    let list_response = client
        .get(format!("{base_url}{API_KEYS_PATH}"))
        .header(header::COOKIE, user.cookie_header(auth_config))
        .send()
        .await
        .expect("list api keys");
    assert_eq!(list_response.status(), StatusCode::OK);

    let listed: serde_json::Value = list_response.json().await.expect("list json");
    let listed_items = listed["items"].as_array().expect("items array");
    assert_eq!(listed_items.len(), 1);
    assert!(
        listed_items[0].get("key").is_none(),
        "list must not leak plaintext key"
    );
    assert_eq!(
        listed_items[0]["organization_id"].as_str(),
        Some(me.organization.id.as_str())
    );
    assert_eq!(
        listed_items[0]["created_by_user_id"].as_str(),
        Some(me.user.id.as_str())
    );
    assert!(listed_items[0]["last_used_at"].is_null());

    let me_response = client
        .get(format!("{base_url}{ME_PATH}"))
        .header(header::AUTHORIZATION, format!("Bearer {api_key}"))
        .send()
        .await
        .expect("bearer me request");
    assert_eq!(me_response.status(), StatusCode::OK);
    let bearer_payload: AuthResponse = me_response.json().await.expect("bearer me json");
    auth_response_assert(
        &bearer_payload,
        &user.email,
        OrganizationRole::Owner,
        OrganizationKind::Personal,
    );
    assert_eq!(bearer_payload.organization.id, me.organization.id);

    let used_response = client
        .get(format!("{base_url}{API_KEYS_PATH}"))
        .header(header::COOKIE, user.cookie_header(auth_config))
        .send()
        .await
        .expect("list used api keys");

    let used: serde_json::Value = used_response.json().await.expect("used json");
    let used_items = used["items"].as_array().expect("items array");
    let api_key_id = used_items[0]["id"]
        .as_str()
        .expect("api key id")
        .to_string();
    assert!(
        used_items[0]["last_used_at"].as_str().is_some(),
        "successful bearer auth should update last_used_at"
    );

    let delete_response = client
        .delete(format!("{base_url}{API_KEYS_PATH}/{api_key_id}"))
        .header(header::COOKIE, user.cookie_header(auth_config))
        .send()
        .await
        .expect("delete api key");
    assert_eq!(delete_response.status(), StatusCode::OK);

    let deleted_response = client
        .get(format!("{base_url}{API_KEYS_PATH}"))
        .header(header::COOKIE, user.cookie_header(auth_config))
        .send()
        .await
        .expect("list deleted api keys");

    let deleted: serde_json::Value = deleted_response.json().await.expect("deleted json");
    assert_eq!(deleted["items"].as_array().expect("items array").len(), 0);

    let deleted_me = client
        .get(format!("{base_url}{ME_PATH}"))
        .header(header::AUTHORIZATION, user.api_key_auth_header())
        .send()
        .await
        .expect("deleted bearer me request");
    assert_eq!(deleted_me.status(), StatusCode::UNAUTHORIZED);
}

/// API keys should stay scoped to the active organization.
pub async fn api_keys_are_scoped_to_active_organization<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let mut user = TestUser::new(&base_url, &client, auth_config).await;
    let default_me = me_get(&base_url, &client, &user, auth_config).await;
    let default_api_key = user
        .api_key_create(&base_url, &client, auth_config, "primary")
        .await;

    let create_org_response = client
        .post(format!("{base_url}{ORGANIZATIONS_PATH}"))
        .header(header::COOKIE, user.cookie_header(auth_config))
        .json(&json!({ "name": "Secondary" }))
        .send()
        .await
        .expect("organization create request");
    assert_eq!(create_org_response.status(), StatusCode::OK);
    let organization: OrganizationMember = create_org_response
        .json()
        .await
        .expect("organization create json");

    let switch_response = client
        .post(format!("{base_url}/auth/organizations/current"))
        .header(header::COOKIE, user.cookie_header(auth_config))
        .json(&json!({ "organization_id": organization.organization.id }))
        .send()
        .await
        .expect("organization switch request");
    assert_eq!(switch_response.status(), StatusCode::OK);
    let headers = switch_response.headers().clone();
    let switch_payload: AuthResponse = switch_response
        .json()
        .await
        .expect("organization switch json");
    user.auth_cookies_replace(&headers, auth_config);

    auth_response_assert(
        &switch_payload,
        &user.email,
        OrganizationRole::Owner,
        OrganizationKind::Shared,
    );
    assert_eq!(
        switch_payload.organization.id,
        organization.organization.id.to_string()
    );

    let empty_list_response = client
        .get(format!("{base_url}{API_KEYS_PATH}"))
        .header(header::COOKIE, user.cookie_header(auth_config))
        .send()
        .await
        .expect("api keys list request");
    assert_eq!(empty_list_response.status(), StatusCode::OK);
    let empty_list: serde_json::Value = empty_list_response.json().await.expect("list json");
    assert_eq!(
        empty_list["items"].as_array().expect("items array").len(),
        0
    );

    user.api_key_create(&base_url, &client, auth_config, "secondary")
        .await;

    let scoped_list_response = client
        .get(format!("{base_url}{API_KEYS_PATH}"))
        .header(header::COOKIE, user.cookie_header(auth_config))
        .send()
        .await
        .expect("scoped api keys list request");
    assert_eq!(scoped_list_response.status(), StatusCode::OK);
    let scoped_list: serde_json::Value = scoped_list_response.json().await.expect("list json");
    let scoped_items = scoped_list["items"].as_array().expect("items array");
    assert_eq!(scoped_items.len(), 1);
    assert_eq!(
        scoped_items[0]["organization_id"].as_str(),
        Some(organization.organization.id.to_string().as_str()),
    );

    let bearer_response = client
        .get(format!("{base_url}{ME_PATH}"))
        .header(header::AUTHORIZATION, format!("Bearer {default_api_key}"))
        .header(header::COOKIE, user.cookie_header(auth_config))
        .send()
        .await
        .expect("mixed auth request");
    assert_eq!(bearer_response.status(), StatusCode::OK);
    let bearer_payload: AuthResponse = bearer_response.json().await.expect("bearer me json");
    auth_response_assert(
        &bearer_payload,
        &user.email,
        OrganizationRole::Owner,
        OrganizationKind::Personal,
    );
    assert_eq!(bearer_payload.organization.id, default_me.organization.id);

    let restored_me = me_get(&base_url, &client, &user, auth_config).await;
    assert_eq!(restored_me.organization.id, switch_payload.organization.id);
    assert_ne!(restored_me.organization.id, default_me.organization.id);
}

/// Bearer API keys must take precedence over ambient cookie auth.
pub async fn bearer_api_key_takes_precedence_over_cookie<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let mut user_one = TestUser::new(&base_url, &client, auth_config).await;
    let user_two = TestUser::new(&base_url, &client, auth_config).await;

    user_one
        .api_key_create(&base_url, &client, auth_config, "primary")
        .await;

    let response = client
        .get(format!("{base_url}{ME_PATH}"))
        .header(header::AUTHORIZATION, user_one.api_key_auth_header())
        .header(header::COOKIE, user_two.cookie_header(auth_config))
        .send()
        .await
        .expect("mixed auth request");
    assert_eq!(response.status(), StatusCode::OK);

    let body: AuthResponse = response.json().await.expect("me json");
    auth_response_assert(
        &body,
        &user_one.email,
        OrganizationRole::Owner,
        OrganizationKind::Personal,
    );
}

/// Malformed or unknown API keys must be rejected.
pub async fn invalid_api_key_returns_unauthorized<C: TestContext>() {
    let (base_url, client, _ctx) = C::spawn().await;

    let response = client
        .get(format!("{base_url}{ME_PATH}"))
        .header(
            header::AUTHORIZATION,
            "Bearer sk-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .send()
        .await
        .expect("invalid bearer request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
