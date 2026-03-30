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

/// Maximum number of failed verification attempts before the code is invalidated.
const MAX_ATTEMPTS: i32 = 4;

pub async fn verify(pool: &PgPool, identifier: &str, code: &str) -> Result<()> {
    // Look up the verification record by identifier (not code) so we can track attempts
    let row = sqlx::query_as::<_, Verification>(
        "SELECT * FROM verification WHERE identifier = $1",
    )
    .bind(identifier)
    .fetch_optional(pool)
    .await?;

    let v = row.ok_or(FutureAuthError::InvalidOtp)?;

    if v.expires_at < Utc::now() {
        sqlx::query("DELETE FROM verification WHERE id = $1")
            .bind(&v.id)
            .execute(pool)
            .await?;
        return Err(FutureAuthError::OtpExpired);
    }

    if v.code != code {
        let new_attempts = v.attempts + 1;
        if new_attempts >= MAX_ATTEMPTS {
            // Too many failed attempts — invalidate the code entirely
            sqlx::query("DELETE FROM verification WHERE id = $1")
                .bind(&v.id)
                .execute(pool)
                .await?;
            return Err(FutureAuthError::OtpMaxAttempts);
        }
        // Increment attempt counter
        sqlx::query("UPDATE verification SET attempts = $1 WHERE id = $2")
            .bind(new_attempts)
            .bind(&v.id)
            .execute(pool)
            .await?;
        return Err(FutureAuthError::InvalidOtp);
    }

    // Correct code — delete it (single-use)
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
