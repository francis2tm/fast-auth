use crate::config::{AuthConfig, CookieSameSite};
use axum_extra::extract::cookie::{Cookie, SameSite};
use time::Duration;

/// Create a cookie for the access token
pub fn access_token_cookie_create(token: String, config: &AuthConfig) -> Cookie<'static> {
    let max_age = Duration::seconds(config.access_token_expiry.as_secs() as i64);

    cookie_create(
        config.cookie_access_token_name.clone(),
        token,
        max_age,
        config,
    )
}

/// Create a cookie for the refresh token
pub fn refresh_token_cookie_create(token: String, config: &AuthConfig) -> Cookie<'static> {
    let max_age = Duration::seconds(config.refresh_token_expiry.as_secs() as i64);

    cookie_create(
        config.cookie_refresh_token_name.clone(),
        token,
        max_age,
        config,
    )
}

/// Create a cookie with standard security settings
fn cookie_create(
    name: String,
    value: String,
    max_age: Duration,
    config: &AuthConfig,
) -> Cookie<'static> {
    let same_site = match config.cookie_same_site {
        CookieSameSite::None => SameSite::None,
        CookieSameSite::Lax => SameSite::Lax,
        CookieSameSite::Strict => SameSite::Strict,
    };

    let mut cookie = Cookie::build((name, value))
        .path(config.cookie_path.clone())
        .http_only(true) // Prevent JavaScript access (XSS protection)
        .same_site(same_site) // CSRF protection
        .secure(config.cookie_secure) // Only send over HTTPS
        .max_age(max_age);

    // Add domain if configured
    if let Some(domain) = &config.cookie_domain {
        cookie = cookie.domain(domain.clone());
    }

    cookie.build()
}

/// Create a cookie that clears the access token
pub fn access_token_cookie_clear(config: &AuthConfig) -> Cookie<'static> {
    cookie_clear(config.cookie_access_token_name.clone(), config)
}

/// Create a cookie that clears the refresh token
pub fn refresh_token_cookie_clear(config: &AuthConfig) -> Cookie<'static> {
    cookie_clear(config.cookie_refresh_token_name.clone(), config)
}

/// Create a cookie with max_age=0 to clear it
fn cookie_clear(name: String, config: &AuthConfig) -> Cookie<'static> {
    let same_site = match config.cookie_same_site {
        CookieSameSite::None => SameSite::None,
        CookieSameSite::Lax => SameSite::Lax,
        CookieSameSite::Strict => SameSite::Strict,
    };

    let mut cookie = Cookie::build((name, ""))
        .path(config.cookie_path.clone())
        .http_only(true)
        .same_site(same_site)
        .secure(config.cookie_secure)
        .max_age(Duration::ZERO); // Clear the cookie

    // Add domain if configured
    if let Some(domain) = &config.cookie_domain {
        cookie = cookie.domain(domain.clone());
    }

    cookie.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> AuthConfig {
        AuthConfig {
            jwt_secret: "a-very-long-secret-string-at-least-32-chars".to_string(),
            cookie_domain: Some("example.com".to_string()),
            cookie_secure: true,
            cookie_same_site: CookieSameSite::Strict,
            ..Default::default()
        }
    }

    #[test]
    fn access_cookie_respects_security_config() {
        let config = base_config();
        let cookie = access_token_cookie_create("abc123".to_string(), &config);

        assert_eq!(cookie.name(), config.cookie_access_token_name);
        assert_eq!(cookie.value(), "abc123");
        assert_eq!(cookie.domain(), Some("example.com"));
        assert_eq!(cookie.path(), Some(config.cookie_path.as_str()));
        assert!(cookie.http_only().unwrap());
        assert!(cookie.secure().unwrap());
        assert_eq!(cookie.same_site(), Some(SameSite::Strict));

        // Max age should mirror access token expiry (default 15 min)
        assert_eq!(
            cookie.max_age(),
            Some(Duration::seconds(
                config.access_token_expiry.as_secs() as i64
            ))
        );
    }

    #[test]
    fn access_token_cookie_clear_sets_zero_age_and_same_name() {
        let config = base_config();
        let cleared = access_token_cookie_clear(&config);

        assert_eq!(cleared.name(), config.cookie_access_token_name);
        assert_eq!(cleared.value(), "");
        assert_eq!(cleared.max_age(), Some(Duration::ZERO));
        // Clearing should keep the same security metadata so browsers accept it
        assert_eq!(cleared.domain(), Some("example.com"));
        assert_eq!(cleared.path(), Some(config.cookie_path.as_str()));
        assert_eq!(cleared.same_site(), Some(SameSite::Strict));
    }
}
