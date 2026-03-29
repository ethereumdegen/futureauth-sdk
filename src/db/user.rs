use sqlx::PgPool;

use crate::error::Result;
use crate::models::User;

pub async fn find_by_id(pool: &PgPool, id: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(r#"SELECT * FROM "user" WHERE id = $1"#)
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(user)
}

pub async fn find_by_email(pool: &PgPool, email: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(r#"SELECT * FROM "user" WHERE email = $1"#)
        .bind(email)
        .fetch_optional(pool)
        .await?;
    Ok(user)
}

pub async fn find_by_phone(pool: &PgPool, phone: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(r#"SELECT * FROM "user" WHERE phone_number = $1"#)
        .bind(phone)
        .fetch_optional(pool)
        .await?;
    Ok(user)
}

pub async fn find_or_create_by_email(pool: &PgPool, email: &str) -> Result<User> {
    if let Some(user) = find_by_email(pool, email).await? {
        if !user.email_verified {
            sqlx::query(r#"UPDATE "user" SET email_verified = TRUE, updated_at = NOW() WHERE id = $1"#)
                .bind(&user.id)
                .execute(pool)
                .await?;
        }
        return find_by_id(pool, &user.id).await.map(|u| u.unwrap());
    }

    let id = nanoid::nanoid!();
    let user = sqlx::query_as::<_, User>(
        r#"INSERT INTO "user" (id, email, name, email_verified)
           VALUES ($1, $2, '', TRUE)
           RETURNING *"#,
    )
    .bind(&id)
    .bind(email)
    .fetch_one(pool)
    .await?;
    Ok(user)
}

pub async fn find_or_create_by_phone(pool: &PgPool, phone: &str) -> Result<User> {
    if let Some(user) = find_by_phone(pool, phone).await? {
        if !user.phone_number_verified {
            sqlx::query(r#"UPDATE "user" SET phone_number_verified = TRUE, updated_at = NOW() WHERE id = $1"#)
                .bind(&user.id)
                .execute(pool)
                .await?;
        }
        return find_by_id(pool, &user.id).await.map(|u| u.unwrap());
    }

    let id = nanoid::nanoid!();
    let user = sqlx::query_as::<_, User>(
        r#"INSERT INTO "user" (id, phone_number, name, phone_number_verified)
           VALUES ($1, $2, '', TRUE)
           RETURNING *"#,
    )
    .bind(&id)
    .bind(phone)
    .fetch_one(pool)
    .await?;
    Ok(user)
}
