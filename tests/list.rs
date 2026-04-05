use fast_auth::handlers::API_KEYS_PATH;
use test_utils::http::test_http_context_spawn;

common::list_endpoint_test_suite!(
    api_keys_list,
    test_http_context_spawn,
    |context| format!("{}{}", context.base_url, API_KEYS_PATH),
    "created_at"
);
