//! Notifications module: device registry, per-device push toggle, FCM token
//! management, a queued + retried delivery worker with invalid-token cleanup,
//! and a realtime GraphQL subscription.

mod fcm;
mod graphql;
mod model;
mod repository;
mod service;

pub use fcm::{FcmSender, LoggingFcmSender, SendOutcome};
pub use graphql::{NotificationsMutation, NotificationsQuery, NotificationsSubscription};
pub use model::{NewNotification, NotificationEvent};
pub use service::{NotificationService, NotificationsModule};

use crate::config::Config;
use sqlx::PgPool;
use std::sync::Arc;

/// Build the notification service with the appropriate FCM sender.
pub fn build_notification_service(pool: PgPool, config: &Config) -> Arc<NotificationService> {
    // A real FCM v1 sender is wired here once service-account credentials are
    // provided; the logging sender lets the pipeline run in the meantime.
    let fcm: Arc<dyn FcmSender> = Arc::new(LoggingFcmSender);
    NotificationService::new(pool, fcm, &config.notifications)
}
