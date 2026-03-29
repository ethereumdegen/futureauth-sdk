use thiserror::Error;

#[derive(Debug, Error)]
pub enum FutureAuthError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("invalid OTP code")]
    InvalidOtp,

    #[error("OTP expired")]
    OtpExpired,

    #[error("OTP delivery failed: {0}")]
    OtpDeliveryFailed(String),

    #[error("session not found or expired")]
    SessionNotFound,

    #[error("user not found")]
    UserNotFound,

    #[error("invalid configuration: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, FutureAuthError>;
