use chrono::Utc;
use sqlx::PgPool;
use std::time::Duration;

use crate::error::Result;
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
    let expires_at = Utc::now() + chrono::Duration::seconds(ttl.as_secs() as i64);

    let session = sqlx::query_as::<_, Session>(
        "INSERT INTO session (id, user_id, token, expires_at, ip_address, user_agent)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING *",
    )
    .bind(&id)
    .bind(user_id)
    .bind(&token)
    .bind(expires_at)
    .bind(ip_address)
    .bind(user_agent)
    .fetch_one(pool)
    .await?;

    Ok(session)
}

pub async fn find_by_token(pool: &PgPool, token: &str) -> Result<Option<(User, Session)>> {
    let row = sqlx::query_as::<_, Session>(
        "SELECT * FROM session WHERE token = $1 AND expires_at > NOW()",
    )
    .bind(token)
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
    sqlx::query("DELETE FROM session WHERE token = $1")
        .bind(token)
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
