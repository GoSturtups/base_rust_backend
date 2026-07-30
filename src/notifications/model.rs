use async_graphql::SimpleObject;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Lifecycle of a queued push notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationStatus {
    Planned,
    Sending,
    Sent,
    Failed,
}

impl NotificationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            NotificationStatus::Planned => "planned",
            NotificationStatus::Sending => "sending",
            NotificationStatus::Sent => "sent",
            NotificationStatus::Failed => "failed",
        }
    }
}

/// A registered client device. `device_id` is `<platform>:<id>` (see the
/// module docs); `push_token` is the current FCM registration token.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DeviceRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_id: String,
    pub push_token: Option<String>,
    pub push_enabled: bool,
    pub platform: Option<String>,
}

/// GraphQL projection of a device.
#[derive(SimpleObject)]
pub struct Device {
    pub device_id: String,
    pub push_enabled: bool,
    pub has_token: bool,
    pub platform: Option<String>,
}

impl From<DeviceRow> for Device {
    fn from(r: DeviceRow) -> Self {
        Device {
            device_id: r.device_id,
            push_enabled: r.push_enabled,
            has_token: r.push_token.is_some(),
            platform: r.platform,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct NotificationRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub title: String,
    pub body: String,
    pub link: Option<String>,
    pub status: String,
    pub attempts: i32,
    pub created_at: DateTime<Utc>,
}

/// Payload for scheduling a notification.
#[derive(Debug, Clone)]
pub struct NewNotification {
    pub user_id: Uuid,
    pub title: String,
    pub body: String,
    pub link: Option<String>,
}

/// Real-time event pushed to GraphQL subscribers.
#[derive(Debug, Clone, SimpleObject)]
pub struct NotificationEvent {
    pub user_id: String,
    pub title: String,
    pub body: String,
    pub link: Option<String>,
}
