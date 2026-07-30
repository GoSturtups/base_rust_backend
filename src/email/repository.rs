use crate::core::error::AppResult;
use crate::email::model::{EmailMessageRow, EmailStatus, NewEmail};
use sqlx::PgPool;
use uuid::Uuid;

/// Data access for the email queue.
#[derive(Clone)]
pub struct EmailRepository {
    pool: PgPool,
}

impl EmailRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn enqueue(&self, email: &NewEmail) -> AppResult<Uuid> {
        let id: Uuid = sqlx::query_scalar(
            r#"INSERT INTO email_queue (to_address, subject, body_html, body_text, status)
               VALUES ($1, $2, $3, $4, $5)
               RETURNING id"#,
        )
        .bind(&email.to)
        .bind(&email.subject)
        .bind(&email.body_html)
        .bind(&email.body_text)
        .bind(EmailStatus::Planned.as_str())
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    /// Atomically claim a batch of sendable emails, flipping them to `sending`
    /// so concurrent workers never pick the same row.
    pub async fn claim_batch(&self, limit: i64, max_attempts: i32) -> AppResult<Vec<EmailMessageRow>> {
        let rows = sqlx::query_as::<_, EmailMessageRow>(
            r#"UPDATE email_queue SET status = $1, updated_at = now()
               WHERE id IN (
                   SELECT id FROM email_queue
                   WHERE status IN ('planned', 'failed') AND attempts < $2
                   ORDER BY created_at
                   FOR UPDATE SKIP LOCKED
                   LIMIT $3
               )
               RETURNING *"#,
        )
        .bind(EmailStatus::Sending.as_str())
        .bind(max_attempts)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn mark_sent(&self, id: Uuid) -> AppResult<()> {
        sqlx::query(
            r#"UPDATE email_queue SET status = $1, updated_at = now() WHERE id = $2"#,
        )
        .bind(EmailStatus::Sent.as_str())
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn mark_failed(&self, id: Uuid, error: &str) -> AppResult<()> {
        sqlx::query(
            r#"UPDATE email_queue
               SET status = $1, attempts = attempts + 1, last_error = $2, updated_at = now()
               WHERE id = $3"#,
        )
        .bind(EmailStatus::Failed.as_str())
        .bind(error)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
