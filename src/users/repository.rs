use crate::core::error::AppResult;
use crate::users::model::UserRow;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// A pending email confirmation / reset code.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CodeRow {
    pub id: Uuid,
    pub email: String,
    pub code: String,
    pub purpose: String,
    pub attempts: i32,
    pub expires_at: DateTime<Utc>,
}

/// Payload for creating a user.
pub struct NewUser {
    pub email: String,
    pub password_hash: Option<String>,
    pub permissions: Vec<String>,
    pub language: Option<String>,
    pub email_confirmed: bool,
}

#[derive(Clone)]
pub struct UserRepository {
    pool: PgPool,
}

impl UserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn get_by_email(&self, email: &str) -> AppResult<Option<UserRow>> {
        let row = sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE email = $1")
            .bind(email.to_lowercase())
            .fetch_optional(&self.pool)
            .await?;
        Ok(row)
    }

    pub async fn get_by_id(&self, id: Uuid) -> AppResult<Option<UserRow>> {
        let row = sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row)
    }

    pub async fn insert(&self, user: NewUser) -> AppResult<UserRow> {
        let row = sqlx::query_as::<_, UserRow>(
            r#"INSERT INTO users
               (email, password_hash, permissions, language, email_confirmed)
               VALUES ($1, $2, $3, $4, $5)
               RETURNING *"#,
        )
        .bind(user.email.to_lowercase())
        .bind(user.password_hash)
        .bind(&user.permissions)
        .bind(user.language)
        .bind(user.email_confirmed)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn set_email_confirmed(&self, id: Uuid) -> AppResult<()> {
        sqlx::query("UPDATE users SET email_confirmed = true, updated_at = now() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_password(&self, id: Uuid, password_hash: &str) -> AppResult<()> {
        sqlx::query("UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2")
            .bind(password_hash)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn set_notifications_email(&self, id: Uuid, enabled: bool) -> AppResult<()> {
        sqlx::query("UPDATE users SET notifications_email = $1, updated_at = now() WHERE id = $2")
            .bind(enabled)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list(&self, limit: i64, offset: i64) -> AppResult<Vec<UserRow>> {
        let rows = sqlx::query_as::<_, UserRow>(
            "SELECT * FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn count(&self) -> AppResult<i64> {
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
            .fetch_one(&self.pool)
            .await?;
        Ok(count)
    }

    // --- confirmation codes ---

    /// Replace any existing code for (email, purpose) with a fresh one.
    pub async fn upsert_code(
        &self,
        email: &str,
        code: &str,
        purpose: &str,
        expires_at: DateTime<Utc>,
    ) -> AppResult<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM email_codes WHERE email = $1 AND purpose = $2")
            .bind(email.to_lowercase())
            .bind(purpose)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO email_codes (email, code, purpose, expires_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(email.to_lowercase())
        .bind(code)
        .bind(purpose)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn get_code(&self, email: &str, purpose: &str) -> AppResult<Option<CodeRow>> {
        let row = sqlx::query_as::<_, CodeRow>(
            "SELECT * FROM email_codes WHERE email = $1 AND purpose = $2",
        )
        .bind(email.to_lowercase())
        .bind(purpose)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn increment_code_attempts(&self, id: Uuid) -> AppResult<()> {
        sqlx::query("UPDATE email_codes SET attempts = attempts + 1 WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_code(&self, id: Uuid) -> AppResult<()> {
        sqlx::query("DELETE FROM email_codes WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
