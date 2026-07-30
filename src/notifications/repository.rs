use crate::core::error::AppResult;
use crate::notifications::model::{DeviceRow, NewNotification, NotificationRow, NotificationStatus};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub struct NotificationRepository {
    pool: PgPool,
}

impl NotificationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ---- devices ----

    /// Register or update a device for the user (unique per user + device_id).
    pub async fn upsert_device(
        &self,
        user_id: Uuid,
        device_id: &str,
        push_token: Option<&str>,
        platform: Option<&str>,
    ) -> AppResult<DeviceRow> {
        let row = sqlx::query_as::<_, DeviceRow>(
            r#"INSERT INTO devices (user_id, device_id, push_token, platform)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (user_id, device_id)
               DO UPDATE SET push_token = COALESCE(EXCLUDED.push_token, devices.push_token),
                             platform = COALESCE(EXCLUDED.platform, devices.platform),
                             updated_at = now()
               RETURNING *"#,
        )
        .bind(user_id)
        .bind(device_id)
        .bind(push_token)
        .bind(platform)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn set_push_enabled(
        &self,
        user_id: Uuid,
        device_id: &str,
        enabled: bool,
    ) -> AppResult<()> {
        sqlx::query(
            "UPDATE devices SET push_enabled = $1, updated_at = now() WHERE user_id = $2 AND device_id = $3",
        )
        .bind(enabled)
        .bind(user_id)
        .bind(device_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_token(
        &self,
        user_id: Uuid,
        device_id: &str,
        token: &str,
    ) -> AppResult<()> {
        sqlx::query(
            "UPDATE devices SET push_token = $1, updated_at = now() WHERE user_id = $2 AND device_id = $3",
        )
        .bind(token)
        .bind(user_id)
        .bind(device_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_devices(&self, user_id: Uuid) -> AppResult<Vec<DeviceRow>> {
        let rows = sqlx::query_as::<_, DeviceRow>(
            "SELECT * FROM devices WHERE user_id = $1 ORDER BY created_at",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Push-enabled devices that have a token, for delivery.
    pub async fn deliverable_devices(&self, user_id: Uuid) -> AppResult<Vec<DeviceRow>> {
        let rows = sqlx::query_as::<_, DeviceRow>(
            "SELECT * FROM devices WHERE user_id = $1 AND push_enabled = true AND push_token IS NOT NULL",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Remove a token that FCM rejected as invalid.
    pub async fn clear_token(&self, token: &str) -> AppResult<()> {
        sqlx::query("UPDATE devices SET push_token = NULL, updated_at = now() WHERE push_token = $1")
            .bind(token)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ---- notification queue ----

    pub async fn enqueue(&self, n: &NewNotification) -> AppResult<Uuid> {
        let id: Uuid = sqlx::query_scalar(
            r#"INSERT INTO notifications (user_id, title, body, link, status)
               VALUES ($1, $2, $3, $4, $5) RETURNING id"#,
        )
        .bind(n.user_id)
        .bind(&n.title)
        .bind(&n.body)
        .bind(&n.link)
        .bind(NotificationStatus::Planned.as_str())
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn claim_batch(
        &self,
        limit: i64,
        max_attempts: i32,
    ) -> AppResult<Vec<NotificationRow>> {
        let rows = sqlx::query_as::<_, NotificationRow>(
            r#"UPDATE notifications SET status = $1, updated_at = now()
               WHERE id IN (
                   SELECT id FROM notifications
                   WHERE status IN ('planned', 'failed') AND attempts < $2
                   ORDER BY created_at
                   FOR UPDATE SKIP LOCKED
                   LIMIT $3
               )
               RETURNING *"#,
        )
        .bind(NotificationStatus::Sending.as_str())
        .bind(max_attempts)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn mark_sent(&self, id: Uuid) -> AppResult<()> {
        sqlx::query("UPDATE notifications SET status = $1, updated_at = now() WHERE id = $2")
            .bind(NotificationStatus::Sent.as_str())
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn mark_failed(&self, id: Uuid, error: &str) -> AppResult<()> {
        sqlx::query(
            "UPDATE notifications SET status = $1, attempts = attempts + 1, last_error = $2, updated_at = now() WHERE id = $3",
        )
        .bind(NotificationStatus::Failed.as_str())
        .bind(error)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
