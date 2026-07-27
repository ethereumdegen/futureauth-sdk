use chrono::Utc;
use sqlx::PgPool;
use std::time::Duration;

use crate::error::Result;
use crate::hashing;
use crate::models::{Session, User};

pub async fn create(
    pool: &PgPool,
    user_id: &str,
    ttl: Duration,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
) -> Result<Session> {
    let id = nanoid::nanoid!();
    let token = format!("{}.{}", nanoid::nanoid!(32), nanoid::nanoid!(16));
    let token_hash = hashing::hash_secret(&token);
    let expires_at = Utc::now() + chrono::Duration::seconds(ttl.as_secs() as i64);

    let mut session = sqlx::query_as::<_, Session>(
        "INSERT INTO session (id, user_id, token_hash, expires_at, ip_address, user_agent)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING *",
    )
    .bind(&id)
    .bind(user_id)
    .bind(&token_hash)
    .bind(expires_at)
    .bind(ip_address)
    .bind(user_agent)
    .fetch_one(pool)
    .await?;

    // Return the plaintext token to the caller so they can set it as a cookie.
    // It is never persisted in cleartext.
    session.token = token;
    Ok(session)
}

pub async fn find_by_token(pool: &PgPool, token: &str) -> Result<Option<(User, Session)>> {
    let token_hash = hashing::hash_secret(token);

    let row = sqlx::query_as::<_, Session>(
        "SELECT * FROM session WHERE token_hash = $1 AND expires_at > NOW()",
    )
    .bind(&token_hash)
    .fetch_optional(pool)
    .await?;

    let session = match row {
        Some(s) => s,
        None => return Ok(None),
    };

    let user = sqlx::query_as::<_, User>(r#"SELECT * FROM "user" WHERE id = $1"#)
        .bind(&session.user_id)
        .fetch_optional(pool)
        .await?;

    match user {
        Some(u) => Ok(Some((u, session))),
        None => Ok(None),
    }
}

pub async fn revoke(pool: &PgPool, token: &str) -> Result<()> {
    let token_hash = hashing::hash_secret(token);
    sqlx::query("DELETE FROM session WHERE token_hash = $1")
        .bind(&token_hash)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn revoke_all_for_user(pool: &PgPool, user_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM session WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn cleanup_expired(pool: &PgPool) -> Result<u64> {
    let result = sqlx::query("DELETE FROM session WHERE expires_at <= NOW()")
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}
