use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: Option<String>,
    pub phone_number: Option<String>,
    pub name: String,
    pub email_verified: bool,
    pub phone_number_verified: bool,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    /// SHA-256 hex of the session token. Stored on disk so a DB leak does not
    /// expose live sessions.
    #[serde(skip)]
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    /// Raw session token. Only populated on `db::session::create`, so the
    /// caller can hand it to the client (cookie, etc.). Never read back from
    /// the database — queries return an empty string here.
    #[sqlx(default)]
    #[serde(skip)]
    pub token: String,
}

#[derive(Debug, Clone, FromRow)]
pub struct Verification {
    pub id: String,
    pub identifier: String,
    /// SHA-256 hex of the OTP or magic-link token. The plaintext value is
    /// never persisted.
    pub code_hash: String,
    pub expires_at: DateTime<Utc>,
    pub attempts: i32,
    pub created_at: DateTime<Utc>,
    pub kind: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum OtpChannel {
    Email,
    Sms,
}
