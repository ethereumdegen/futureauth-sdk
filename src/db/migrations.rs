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
    token TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS verification (
    id TEXT PRIMARY KEY,
    identifier TEXT NOT NULL,
    code TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Backfill: add attempts column if table already exists (idempotent)
DO $$ BEGIN
    ALTER TABLE verification ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
EXCEPTION WHEN duplicate_column THEN NULL;
END $$;

CREATE INDEX IF NOT EXISTS idx_session_token ON session(token);
CREATE INDEX IF NOT EXISTS idx_session_user ON session(user_id);
CREATE INDEX IF NOT EXISTS idx_user_email ON "user"(email);
CREATE INDEX IF NOT EXISTS idx_user_phone ON "user"(phone_number);
CREATE INDEX IF NOT EXISTS idx_verification_identifier ON verification(identifier);
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
