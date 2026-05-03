use fast_auth::handlers::API_KEYS_PATH;
use test_utils::app::{TestHttpContext, test_app_spawn};

async fn context_spawn() -> TestHttpContext {
    test_app_spawn(Default::default()).await.context().await
}

common::list_endpoint_test_suite!(
    api_keys_list,
    context_spawn,
    |context| format!("{}{}", context.base_url, API_KEYS_PATH),
    "created_at"
);
