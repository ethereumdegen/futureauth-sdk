use chrono::Utc;
use sqlx::PgPool;
use std::time::Duration;

use crate::error::{Result, FutureAuthError};
use crate::models::Verification;

pub async fn create(
    pool: &PgPool,
    identifier: &str,
    code: &str,
    ttl: Duration,
) -> Result<Verification> {
    // Delete any existing codes for this identifier
    sqlx::query("DELETE FROM verification WHERE identifier = $1")
        .bind(identifier)
        .execute(pool)
        .await?;

    let id = nanoid::nanoid!();
    let expires_at = Utc::now() + chrono::Duration::seconds(ttl.as_secs() as i64);

    let v = sqlx::query_as::<_, Verification>(
        "INSERT INTO verification (id, identifier, code, expires_at)
         VALUES ($1, $2, $3, $4)
         RETURNING *",
    )
    .bind(&id)
    .bind(identifier)
    .bind(code)
    .bind(expires_at)
    .fetch_one(pool)
    .await?;

    Ok(v)
}

pub async fn verify(pool: &PgPool, identifier: &str, code: &str) -> Result<()> {
    let row = sqlx::query_as::<_, Verification>(
        "SELECT * FROM verification WHERE identifier = $1 AND code = $2",
    )
    .bind(identifier)
    .bind(code)
    .fetch_optional(pool)
    .await?;

    let v = row.ok_or(FutureAuthError::InvalidOtp)?;

    if v.expires_at < Utc::now() {
        // Clean up expired code
        sqlx::query("DELETE FROM verification WHERE id = $1")
            .bind(&v.id)
            .execute(pool)
            .await?;
        return Err(FutureAuthError::OtpExpired);
    }

    // Delete the used code
    sqlx::query("DELETE FROM verification WHERE id = $1")
        .bind(&v.id)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn cleanup_expired(pool: &PgPool) -> Result<u64> {
    let result = sqlx::query("DELETE FROM verification WHERE expires_at <= NOW()")
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}
