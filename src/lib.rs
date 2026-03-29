pub mod config;
pub mod error;
pub mod models;
pub mod client;
pub mod db;

#[cfg(feature = "axum-integration")]
pub mod axum;

use std::sync::Arc;

use rand::Rng;
use sqlx::PgPool;

pub use config::FutureAuthConfig;
pub use error::{Result, FutureAuthError};
pub use models::{OtpChannel, Session, User};

pub struct FutureAuth {
    pub pool: PgPool,
    pub config: FutureAuthConfig,
    http: reqwest::Client,
}

impl FutureAuth {
    pub fn new(pool: PgPool, config: FutureAuthConfig) -> Arc<Self> {
        Arc::new(Self {
            pool,
            config,
            http: reqwest::Client::new(),
        })
    }

    /// Create auth tables if they don't exist. Safe to call on every startup.
    pub async fn ensure_tables(&self) -> Result<()> {
        db::migrations::ensure_tables(&self.pool).await
    }

    /// Generate a random OTP code, store it locally, and send it via FutureAuth.
    pub async fn send_otp(&self, channel: OtpChannel, destination: &str) -> Result<()> {
        let code = generate_otp(self.config.otp_length);

        // Store verification locally
        db::verification::create(&self.pool, destination, &code, self.config.otp_ttl).await?;

        // Send via FutureAuth API
        client::send_otp(&self.http, &self.config, channel, destination, &code).await?;

        tracing::info!("OTP sent to {destination} via {channel:?}");
        Ok(())
    }

    /// Verify an OTP code. On success, creates/finds the user and creates a session.
    pub async fn verify_otp(
        &self,
        identifier: &str,
        code: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(User, Session)> {
        // Verify the code locally
        db::verification::verify(&self.pool, identifier, code).await?;

        // Create or find user
        let user = if identifier.contains('@') {
            db::user::find_or_create_by_email(&self.pool, identifier).await?
        } else {
            db::user::find_or_create_by_phone(&self.pool, identifier).await?
        };

        // Create session
        let session = db::session::create(
            &self.pool,
            &user.id,
            self.config.session_ttl,
            ip_address,
            user_agent,
        )
        .await?;

        Ok((user, session))
    }

    /// Validate a session token. Returns the user and session if valid.
    pub async fn get_session(&self, token: &str) -> Result<Option<(User, Session)>> {
        db::session::find_by_token(&self.pool, token).await
    }

    /// Revoke a single session.
    pub async fn revoke_session(&self, token: &str) -> Result<()> {
        db::session::revoke(&self.pool, token).await
    }

    /// Revoke all sessions for a user.
    pub async fn revoke_all_sessions(&self, user_id: &str) -> Result<()> {
        db::session::revoke_all_for_user(&self.pool, user_id).await
    }

    /// Clean up expired sessions and verification codes.
    pub async fn cleanup_expired(&self) -> Result<(u64, u64)> {
        let sessions = db::session::cleanup_expired(&self.pool).await?;
        let verifications = db::verification::cleanup_expired(&self.pool).await?;
        Ok((sessions, verifications))
    }

    /// Look up a user by ID.
    pub async fn get_user(&self, id: &str) -> Result<Option<User>> {
        db::user::find_by_id(&self.pool, id).await
    }

    /// Look up a user by email.
    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>> {
        db::user::find_by_email(&self.pool, email).await
    }

    /// Look up a user by phone number.
    pub async fn get_user_by_phone(&self, phone: &str) -> Result<Option<User>> {
        db::user::find_by_phone(&self.pool, phone).await
    }
}

fn generate_otp(length: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| rng.gen_range(0..10).to_string())
        .collect()
}
