use sqlx::PgPool;

use crate::error::Result;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS "user" (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE,
    phone_number TEXT UNIQUE,
    name TEXT NOT NULL DEFAULT '',
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    phone_number_verified BOOLEAN NOT NULL DEFAULT FALSE,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Backfill: add metadata column if table already exists (idempotent)
DO $$ BEGIN
    ALTER TABLE "user" ADD COLUMN metadata JSONB NOT NULL DEFAULT '{}';
EXCEPTION WHEN duplicate_column THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS session (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Backfill: add token_hash column on existing deployments and drop the legacy
-- plaintext `token` column. Existing rows cannot be hashed retroactively (we
-- don't have the plaintext), so we simply truncate the table — users will need
-- to sign in again on their next request. This is a one-time security upgrade.
DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'session' AND column_name = 'token'
    ) THEN
        TRUNCATE TABLE session;
        ALTER TABLE session ADD COLUMN IF NOT EXISTS token_hash TEXT NOT NULL UNIQUE;
        ALTER TABLE session DROP COLUMN token;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS verification (
    id TEXT PRIMARY KEY,
    identifier TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Backfill: add attempts column if table already exists (idempotent)
DO $$ BEGIN
    ALTER TABLE verification ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
EXCEPTION WHEN duplicate_column THEN NULL;
END $$;

-- Backfill: add code_hash column and drop the legacy plaintext `code` column.
-- Same reasoning as sessions — pending OTP/magic-link codes get wiped, users
-- just request a new one.
DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'verification' AND column_name = 'code'
    ) THEN
        TRUNCATE TABLE verification;
        ALTER TABLE verification ADD COLUMN IF NOT EXISTS code_hash TEXT NOT NULL;
        ALTER TABLE verification DROP COLUMN code;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_session_token_hash ON session(token_hash);
CREATE INDEX IF NOT EXISTS idx_session_user ON session(user_id);
CREATE INDEX IF NOT EXISTS idx_user_email ON "user"(email);
CREATE INDEX IF NOT EXISTS idx_user_phone ON "user"(phone_number);
CREATE INDEX IF NOT EXISTS idx_verification_identifier ON verification(identifier);

-- Drop legacy plaintext-token index if it still exists
DROP INDEX IF EXISTS idx_session_token;
DROP INDEX IF EXISTS idx_verification_code;

-- Backfill: add kind column for magic link support (idempotent)
DO $$ BEGIN
    ALTER TABLE verification ADD COLUMN kind TEXT NOT NULL DEFAULT 'otp';
EXCEPTION WHEN duplicate_column THEN NULL;
END $$;

CREATE INDEX IF NOT EXISTS idx_verification_code_hash ON verification(code_hash);
"#;

/// Returns the SQL needed to create all FutureAuth tables.
///
/// Useful if you manage migrations yourself (e.g. with sqlx-cli or refinery)
/// and want to include FutureAuth's schema in your own migration files.
pub fn migration_sql() -> &'static str {
    SCHEMA
}

pub async fn ensure_tables(pool: &PgPool) -> Result<()> {
    sqlx::raw_sql(SCHEMA).execute(pool).await?;
    tracing::info!("futureauth: auth tables ready");
    Ok(())
}
