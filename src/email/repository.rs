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
    ///
    /// Only `planned` messages are ever claimed: a failed send is terminal
    /// (`error`), so a broken relay cannot build a backlog that later floods out.
    pub async fn claim_batch(&self, limit: i64) -> AppResult<Vec<EmailMessageRow>> {
        let rows = sqlx::query_as::<_, EmailMessageRow>(
            r#"UPDATE email_queue SET status = $1, updated_at = now()
               WHERE id IN (
                   SELECT id FROM email_queue
                   WHERE status = 'planned'
                   ORDER BY created_at
                   FOR UPDATE SKIP LOCKED
                   LIMIT $2
               )
               RETURNING *"#,
        )
        .bind(EmailStatus::Sending.as_str())
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

    /// Mark a message as permanently failed: terminal `error` status with the
    /// failure reason recorded. Never re-queued, so there is nothing to count —
    /// sending is single-shot.
    pub async fn mark_error(&self, id: Uuid, error: &str) -> AppResult<()> {
        sqlx::query(
            r#"UPDATE email_queue
               SET status = $1, last_error = $2, updated_at = now()
               WHERE id = $3"#,
        )
        .bind(EmailStatus::Error.as_str())
        .bind(error)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
