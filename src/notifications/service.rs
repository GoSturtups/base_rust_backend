use crate::config::NotificationsConfig;
use crate::core::error::AppResult;
use crate::core::module::Module;
use crate::notifications::fcm::{FcmSender, SendOutcome};
use crate::notifications::model::{Device, NewNotification, NotificationEvent};
use crate::notifications::repository::NotificationRepository;
use async_trait::async_trait;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use uuid::Uuid;

/// Public API of the notifications module. Cheap to clone.
pub struct NotificationService {
    repo: NotificationRepository,
    fcm: Arc<dyn FcmSender>,
    events: broadcast::Sender<NotificationEvent>,
}

impl NotificationService {
    pub fn new(pool: PgPool, fcm: Arc<dyn FcmSender>, _config: &NotificationsConfig) -> Arc<Self> {
        let (events, _) = broadcast::channel(256);
        Arc::new(Self {
            repo: NotificationRepository::new(pool),
            fcm,
            events,
        })
    }

    /// Subscribe to the realtime notification stream (used by the GraphQL
    /// subscription).
    pub fn subscribe(&self) -> broadcast::Receiver<NotificationEvent> {
        self.events.subscribe()
    }

    // ---- device management ----

    pub async fn register_device(
        &self,
        user_id: Uuid,
        device_id: &str,
        push_token: Option<&str>,
        platform: Option<&str>,
    ) -> AppResult<Device> {
        let platform = platform.or_else(|| device_id.split(':').next());
        let row = self
            .repo
            .upsert_device(user_id, device_id, push_token, platform)
            .await?;
        Ok(row.into())
    }

    pub async fn set_push_enabled(
        &self,
        user_id: Uuid,
        device_id: &str,
        enabled: bool,
    ) -> AppResult<bool> {
        self.repo.set_push_enabled(user_id, device_id, enabled).await?;
        Ok(enabled)
    }

    pub async fn update_fcm_token(
        &self,
        user_id: Uuid,
        device_id: &str,
        token: &str,
    ) -> AppResult<bool> {
        self.repo.update_token(user_id, device_id, token).await?;
        Ok(true)
    }

    pub async fn list_devices(&self, user_id: Uuid) -> AppResult<Vec<Device>> {
        Ok(self
            .repo
            .list_devices(user_id)
            .await?
            .into_iter()
            .map(Device::from)
            .collect())
    }

    // ---- scheduling ----

    /// Schedule a notification for delivery and emit it to realtime subscribers.
    pub async fn notify(&self, n: NewNotification) -> AppResult<Uuid> {
        let id = self.repo.enqueue(&n).await?;
        // Fan out to any connected subscribers; ignore "no receivers".
        let _ = self.events.send(NotificationEvent {
            user_id: n.user_id.to_string(),
            title: n.title,
            body: n.body,
            link: n.link,
        });
        Ok(id)
    }

    /// Claim a batch of planned notifications and push them to each of the
    /// user's enabled devices, cleaning up tokens FCM rejects.
    async fn process_batch(&self, batch: i64) -> AppResult<usize> {
        let rows = self.repo.claim_batch(batch).await?;
        let count = rows.len();
        for row in rows {
            let devices = self.repo.deliverable_devices(row.user_id).await?;
            if devices.is_empty() {
                self.repo.mark_sent(row.id).await?; // nothing to deliver to
                continue;
            }
            let mut sent_any = false;
            let mut last_error: Option<String> = None;
            for device in devices {
                let Some(token) = device.push_token else { continue };
                match self.fcm.send(&token, &row).await {
                    SendOutcome::Sent => sent_any = true,
                    SendOutcome::InvalidToken => {
                        self.repo.clear_token(&token).await?;
                    }
                    SendOutcome::Error(e) => last_error = Some(e),
                }
            }
            if sent_any {
                self.repo.mark_sent(row.id).await?;
            } else {
                let reason = last_error.as_deref().unwrap_or("delivery failed");
                tracing::warn!(notification_id = %row.id, error = %reason, "notification delivery failed; marking as error");
                self.repo.mark_error(row.id, reason).await?;
            }
        }
        Ok(count)
    }
}

/// Background worker module for the notification queue.
pub struct NotificationsModule {
    service: Arc<NotificationService>,
    interval: Duration,
}

impl NotificationsModule {
    pub fn new(service: Arc<NotificationService>, config: &NotificationsConfig) -> Self {
        Self {
            service,
            interval: Duration::from_secs(config.worker_interval_secs),
        }
    }
}

#[async_trait]
impl Module for NotificationsModule {
    fn name(&self) -> &'static str {
        "notifications"
    }

    async fn start(&self) -> anyhow::Result<()> {
        let service = self.service.clone();
        let interval = self.interval;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                if let Err(e) = service.process_batch(20).await {
                    tracing::error!(error = %e, "notification worker batch failed");
                }
            }
        });
        Ok(())
    }
}
