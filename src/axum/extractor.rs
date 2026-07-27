use std::sync::Arc;

use ::axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};

use crate::models::{Session, User};
use crate::FutureAuth;

/// Axum extractor that validates the session cookie and provides the authenticated user.
///
/// Usage:
/// ```rust,ignore
/// async fn my_handler(auth: AuthSession) -> impl IntoResponse {
///     Json(json!({ "user_id": auth.user.id }))
/// }
///
/// // Optional auth:
/// async fn public_handler(auth: Option<AuthSession>) -> impl IntoResponse {
///     if let Some(auth) = auth { /* logged in */ }
/// }
/// ```
pub struct AuthSession {
    pub user: User,
    pub session: Session,
}

impl<S> FromRequestParts<S> for AuthSession
where
    S: Send + Sync + AsRef<Arc<FutureAuth>>,
{
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let futureauth: &Arc<FutureAuth> = state.as_ref();

        let cookie_header = parts
            .headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let cookie_name = &futureauth.config.cookie_name;
        let token = cookie_header
            .split(';')
            .filter_map(|c| {
                let c = c.trim();
                c.strip_prefix(&format!("{cookie_name}="))
            })
            .next()
            .ok_or(StatusCode::UNAUTHORIZED)?;

        let (user, session) = futureauth
            .get_session(token)
            .await
            .map_err(|e| {
                tracing::error!("Session lookup failed: {e}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .ok_or(StatusCode::UNAUTHORIZED)?;

        Ok(AuthSession { user, session })
    }
}
