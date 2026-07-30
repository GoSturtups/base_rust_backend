//! Firebase Cloud Messaging delivery abstraction.
//!
//! Sending via FCM HTTP v1 requires an OAuth2 access token minted from the
//! service-account key. That credential exchange is intentionally left as the
//! one integration point to fill in per deployment; the queue, token lifecycle
//! and invalid-token cleanup around it are fully implemented and driven through
//! this trait.

use crate::notifications::model::NotificationRow;
use async_trait::async_trait;

/// Result of a single push attempt.
pub enum SendOutcome {
    Sent,
    /// The token is no longer valid and should be removed.
    InvalidToken,
    /// Transient failure; the notification will be retried.
    Error(String),
}

#[async_trait]
pub trait FcmSender: Send + Sync {
    /// Deliver `notification` to a single device `token`.
    async fn send(&self, token: &str, notification: &NotificationRow) -> SendOutcome;
}

/// Placeholder sender used until FCM credentials are configured: it logs the
/// notification and reports success so the pipeline can be exercised end to end.
pub struct LoggingFcmSender;

#[async_trait]
impl FcmSender for LoggingFcmSender {
    async fn send(&self, token: &str, notification: &NotificationRow) -> SendOutcome {
        tracing::info!(
            token = %token,
            title = %notification.title,
            body = %notification.body,
            link = ?notification.link,
            "FCM (logging sender) would deliver notification"
        );
        SendOutcome::Sent
    }
}
