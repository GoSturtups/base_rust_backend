use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Lifecycle of a queued email.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailStatus {
    Planned,
    Sending,
    Sent,
    Failed,
}

impl EmailStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            EmailStatus::Planned => "planned",
            EmailStatus::Sending => "sending",
            EmailStatus::Sent => "sent",
            EmailStatus::Failed => "failed",
        }
    }
}

/// A row of the `email_queue` table. Some columns are only read for
/// observability/admin tooling, hence `dead_code` is allowed.
#[allow(dead_code)]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EmailMessageRow {
    pub id: Uuid,
    pub to_address: String,
    pub subject: String,
    pub body_html: String,
    pub body_text: String,
    pub status: String,
    pub attempts: i32,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Payload for enqueuing a new email.
#[derive(Debug, Clone)]
pub struct NewEmail {
    pub to: String,
    pub subject: String,
    pub body_html: String,
    pub body_text: String,
}
