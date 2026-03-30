use std::sync::Arc;

use ::axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::models::OtpChannel;
use crate::FutureAuth;

#[derive(Deserialize)]
struct SendOtpRequest {
    email: Option<String>,
    phone: Option<String>,
}

#[derive(Deserialize)]
struct VerifyOtpRequest {
    email: Option<String>,
    phone: Option<String>,
    code: String,
}

#[derive(Serialize)]
struct SessionResponse {
    user: crate::models::User,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

/// Create an Axum router with auth routes. Mount this in your app:
///
/// ```rust,ignore
/// let app = Router::new()
///     .merge(futureauth::axum::auth_router(futureauth.clone()))
///     .with_state(app_state);
/// ```
///
/// Provides:
/// - `POST /api/auth/send-otp`
/// - `POST /api/auth/verify-otp`
/// - `GET  /api/auth/session`
/// - `POST /api/auth/sign-out`
pub fn auth_router<S>(futureauth: Arc<FutureAuth>) -> Router<S>
where
    S: Clone + Send + Sync + 'static + AsRef<Arc<FutureAuth>>,
{
    Router::new()
        .route("/api/auth/send-otp", post(send_otp))
        .route("/api/auth/verify-otp", post(verify_otp))
        .route("/api/auth/session", get(get_session))
        .route("/api/auth/sign-out", post(sign_out))
        .with_state(futureauth)
}

async fn send_otp(
    State(futureauth): State<Arc<FutureAuth>>,
    Json(body): Json<SendOtpRequest>,
) -> impl IntoResponse {
    let (channel, destination) = match (&body.email, &body.phone) {
        (Some(email), _) => (OtpChannel::Email, email.clone()),
        (_, Some(phone)) => (OtpChannel::Sms, phone.clone()),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "email or phone is required".into(),
                }),
            )
                .into_response()
        }
    };

    match futureauth.send_otp(channel, &destination).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response(),
        Err(e) => {
            tracing::error!("Failed to send OTP: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to send code".into(),
                }),
            )
                .into_response()
        }
    }
}

async fn verify_otp(
    State(futureauth): State<Arc<FutureAuth>>,
    headers: HeaderMap,
    Json(body): Json<VerifyOtpRequest>,
) -> impl IntoResponse {
    let identifier = match (&body.email, &body.phone) {
        (Some(email), _) => email.clone(),
        (_, Some(phone)) => phone.clone(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "email or phone is required".into(),
                }),
            )
                .into_response()
        }
    };

    let ip = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string());

    let ua = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match futureauth
        .verify_otp(&identifier, &body.code, ip.as_deref(), ua.as_deref())
        .await
    {
        Ok((user, session)) => {
            let cookie_name = &futureauth.config.cookie_name;
            let cookie = format!(
                "{cookie_name}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
                session.token,
                futureauth.config.session_ttl.as_secs()
            );

            (
                StatusCode::OK,
                [("set-cookie", cookie)],
                Json(SessionResponse { user }),
            )
                .into_response()
        }
        Err(crate::FutureAuthError::OtpMaxAttempts) => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "Too many failed attempts, please request a new code".into(),
            }),
        )
            .into_response(),
        Err(crate::FutureAuthError::InvalidOtp | crate::FutureAuthError::OtpExpired) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid or expired code".into(),
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("OTP verification failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Verification failed".into(),
                }),
            )
                .into_response()
        }
    }
}

async fn get_session(
    State(futureauth): State<Arc<FutureAuth>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let cookie_header = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let cookie_name = &futureauth.config.cookie_name;
    let token = cookie_header
        .split(';')
        .filter_map(|c| c.trim().strip_prefix(&format!("{cookie_name}=")))
        .next();

    let token = match token {
        Some(t) => t,
        None => {
            return (StatusCode::UNAUTHORIZED, Json(ErrorResponse {
                error: "Not authenticated".into(),
            })).into_response()
        }
    };

    match futureauth.get_session(token).await {
        Ok(Some((user, session))) => (StatusCode::OK, Json(serde_json::json!({
            "user": user,
            "session": { "expires_at": session.expires_at }
        }))).into_response(),
        _ => (StatusCode::UNAUTHORIZED, Json(ErrorResponse {
            error: "Not authenticated".into(),
        })).into_response(),
    }
}

async fn sign_out(
    State(futureauth): State<Arc<FutureAuth>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let cookie_header = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let cookie_name = &futureauth.config.cookie_name;
    if let Some(token) = cookie_header
        .split(';')
        .filter_map(|c| c.trim().strip_prefix(&format!("{cookie_name}=")))
        .next()
    {
        let _ = futureauth.revoke_session(token).await;
    }

    let clear = format!("{cookie_name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    (StatusCode::OK, [("set-cookie", clear)], Json(serde_json::json!({ "ok": true })))
}
