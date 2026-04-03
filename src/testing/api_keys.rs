//! API key test functions.

use reqwest::{StatusCode, header};

use crate::handlers::{API_KEYS_PATH, ME_PATH};

use super::{TestContext, TestUser};

/// API keys should be creatable, usable, listable, and deletable.
pub async fn api_key_create_list_use_delete_flow<C: TestContext>() {
    let (base_url, client, ctx) = C::spawn().await;
    let auth_config = ctx.auth_config();
    let mut user = TestUser::new(&base_url, &client, auth_config).await;

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
    assert!(listed_items[0]["last_used_at"].is_null());

    let me_response = client
        .get(format!("{base_url}{ME_PATH}"))
        .header(header::AUTHORIZATION, format!("Bearer {api_key}"))
        .send()
        .await
        .expect("bearer me request");
    assert_eq!(me_response.status(), StatusCode::OK);

    let used_response = client
        .get(format!("{base_url}{API_KEYS_PATH}"))
        .header(header::COOKIE, user.cookie_header(auth_config))
        .send()
        .await
        .expect("list used api keys");

    let used: serde_json::Value = used_response.json().await.expect("used json");
    let used_items = used["items"].as_array().expect("items array");
    let api_key_id = used_items[0]["id"].as_str().expect("api key id").to_string();
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

    let body: serde_json::Value = response.json().await.expect("me json");
    assert_eq!(body["email"].as_str(), Some(user_one.email.as_str()));
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
