use chrono::Utc;
use sqlx::PgPool;
use std::time::Duration;

use crate::error::{FutureAuthError, Result};
use crate::hashing;
use crate::models::Verification;

pub async fn create(
    pool: &PgPool,
    identifier: &str,
    code: &str,
    ttl: Duration,
) -> Result<Verification> {
    // Delete any existing OTP codes for this identifier
    sqlx::query("DELETE FROM verification WHERE identifier = $1 AND kind = 'otp'")
        .bind(identifier)
        .execute(pool)
        .await?;

    let id = nanoid::nanoid!();
    let code_hash = hashing::hash_secret(code);
    let expires_at = Utc::now() + chrono::Duration::seconds(ttl.as_secs() as i64);

    let v = sqlx::query_as::<_, Verification>(
        "INSERT INTO verification (id, identifier, code_hash, expires_at, kind)
         VALUES ($1, $2, $3, $4, 'otp')
         RETURNING *",
    )
    .bind(&id)
    .bind(identifier)
    .bind(&code_hash)
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
        "SELECT * FROM verification WHERE identifier = $1 AND kind = 'otp'",
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

    let provided_hash = hashing::hash_secret(code);
    if !hashing::constant_time_eq(v.code_hash.as_bytes(), provided_hash.as_bytes()) {
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

pub async fn create_magic_link(
    pool: &PgPool,
    identifier: &str,
    token: &str,
    ttl: Duration,
) -> Result<Verification> {
    // Delete any existing magic links for this identifier
    sqlx::query("DELETE FROM verification WHERE identifier = $1 AND kind = 'magic_link'")
        .bind(identifier)
        .execute(pool)
        .await?;

    let id = nanoid::nanoid!();
    let code_hash = hashing::hash_secret(token);
    let expires_at = Utc::now() + chrono::Duration::seconds(ttl.as_secs() as i64);

    let v = sqlx::query_as::<_, Verification>(
        "INSERT INTO verification (id, identifier, code_hash, expires_at, kind)
         VALUES ($1, $2, $3, $4, 'magic_link')
         RETURNING *",
    )
    .bind(&id)
    .bind(identifier)
    .bind(&code_hash)
    .bind(expires_at)
    .fetch_one(pool)
    .await?;

    Ok(v)
}

/// Verify a magic link token. Returns the identifier (email) on success.
pub async fn verify_magic_link(pool: &PgPool, token: &str) -> Result<String> {
    let token_hash = hashing::hash_secret(token);

    let row = sqlx::query_as::<_, Verification>(
        "SELECT * FROM verification WHERE code_hash = $1 AND kind = 'magic_link'",
    )
    .bind(&token_hash)
    .fetch_optional(pool)
    .await?;

    let v = row.ok_or(FutureAuthError::InvalidMagicLink)?;

    if v.expires_at < Utc::now() {
        sqlx::query("DELETE FROM verification WHERE id = $1")
            .bind(&v.id)
            .execute(pool)
            .await?;
        return Err(FutureAuthError::MagicLinkExpired);
    }

    let identifier = v.identifier.clone();

    // Delete the token (single-use)
    sqlx::query("DELETE FROM verification WHERE id = $1")
        .bind(&v.id)
        .execute(pool)
        .await?;

    Ok(identifier)
}

pub async fn cleanup_expired(pool: &PgPool) -> Result<u64> {
    let result = sqlx::query("DELETE FROM verification WHERE expires_at <= NOW()")
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}
