//! Sessions and CSRF. The cookie holds a random id; the database holds only its SHA-256.

use crate::{
    error::{ApiError, ApiResult},
    state::AppState,
};
use axum::http::HeaderMap;
use chrono::{DateTime, Duration, Utc};
use escrow_core::{
    oauth::{SESSION_COOKIE, cookie_value},
    security::{csrf_valid, hash_session_id, is_session_id, random_hex, sha256_hex},
};
use escrow_db::{Db, User, sessions};

pub const SESSION_DAYS: i64 = 30;

pub async fn create(db: &Db, user_id: &str, now: DateTime<Utc>) -> Result<(String, i64), sqlx::Error> {
    let id = random_hex::<32>();
    sessions::create(&db.pool, &hash_session_id(&id), user_id, now + Duration::days(SESSION_DAYS)).await?;
    Ok((id, SESSION_DAYS * 86_400))
}

pub fn cookie_id(h: &HeaderMap) -> Option<String> {
    let raw = h.get(axum::http::header::COOKIE)?.to_str().ok()?;
    cookie_value(raw, SESSION_COOKIE).filter(|v| is_session_id(v)).map(str::to_string)
}

pub struct Authed {
    pub user: User,
    pub session_id: String,
}

/// Rate-limit key: the authenticated user, otherwise the client address.
///
/// Only ever pass an identity that `require_user` has already verified: a forged or unknown cookie
/// must not be able to borrow a signed-in user's budget.
pub fn limit_key(user: Option<&Authed>, ip: &str) -> String {
    user.map_or_else(|| format!("ip:{ip}"), |a| format!("u:{}", &sha256_hex(&a.user.id)[..16]))
}

/// The signed-in user, or 401. Mutating requests must also carry the CSRF token bound to the session.
pub async fn require_user(s: &AppState, h: &HeaderMap, mutating: bool) -> ApiResult<Authed> {
    let sid = cookie_id(h).ok_or_else(ApiError::unauthenticated)?;
    let user = sessions::user_for(&s.db.pool, &hash_session_id(&sid), (s.now)()).await?.ok_or_else(ApiError::unauthenticated)?;
    if mutating {
        let given = h.get("x-csrf-token").and_then(|v| v.to_str().ok());
        if !csrf_valid(&s.cfg.csrf_secret, &sid, given) {
            return Err(ApiError::forbidden("csrf", "missing or invalid CSRF token"));
        }
    }
    Ok(Authed { user, session_id: sid })
}

pub async fn destroy(db: &Db, session_id: &str) -> Result<(), sqlx::Error> {
    sessions::delete(&db.pool, &hash_session_id(session_id)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(cookie: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("cookie", HeaderValue::from_str(cookie).unwrap());
        h
    }

    #[test]
    fn only_well_formed_session_cookies_are_read() {
        let id = random_hex::<32>();
        assert_eq!(cookie_id(&headers(&format!("a=1; se_session={id}; b=2"))), Some(id));
        for bad in ["se_session=short", "se_session=", "other=abc", &format!("se_session={}", "Z".repeat(64))] {
            assert_eq!(cookie_id(&headers(bad)), None, "{bad}");
        }
        assert_eq!(cookie_id(&HeaderMap::new()), None);
    }

    fn authed(user_id: &str, session_id: &str) -> Authed {
        Authed {
            user: User {
                id: user_id.into(),
                github_id: 1,
                github_login: "u".into(),
                avatar_url: None,
                wallet: None,
                wallet_linked_at: None,
                is_admin: false,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            session_id: session_id.into(),
        }
    }

    #[test]
    fn the_limit_key_prefers_the_user_and_never_exposes_it() {
        let k = limit_key(Some(&authed("user-123", "sess-abc")), "1.2.3.4");
        assert!(k.starts_with("u:") && !k.contains("user-123") && k.len() == 18);
        // two sessions of the same user share one key; other users do not
        assert_eq!(limit_key(Some(&authed("user-123", "sess-xyz")), "1.2.3.4"), k);
        assert_ne!(limit_key(Some(&authed("user-999", "sess-abc")), "5.6.7.8"), k);
        // no verified identity: the client address is all we have
        assert_eq!(limit_key(None, "1.2.3.4"), "ip:1.2.3.4");
    }
}
