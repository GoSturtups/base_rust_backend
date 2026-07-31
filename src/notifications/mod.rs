//! Notifications module: device registry, per-device push toggle, FCM token
//! management, a queued + retried delivery worker with invalid-token cleanup,
//! and a realtime GraphQL subscription.

mod fcm;
mod graphql;
mod model;
mod repository;
mod service;

pub use fcm::{FcmSender, FcmV1Sender, LoggingFcmSender, SendOutcome};
pub use graphql::{NotificationsMutation, NotificationsQuery, NotificationsSubscription};
pub use model::{NewNotification, NotificationEvent};
pub use service::{NotificationService, NotificationsModule};

use crate::config::Config;
use sqlx::PgPool;
use std::sync::Arc;

/// Build the notification service with the appropriate FCM sender.
///
/// When a Firebase Admin SDK service account is configured
/// (`firebase.service_account_json`) real pushes are sent via FCM HTTP v1;
/// otherwise the logging sender lets the pipeline run without credentials.
pub fn build_notification_service(pool: PgPool, config: &Config) -> Arc<NotificationService> {
    let fcm: Arc<dyn FcmSender> =
        match FcmV1Sender::from_service_account_json(&config.firebase.service_account_json) {
            Some(sender) => {
                tracing::info!("FCM v1 sender enabled (service account configured)");
                Arc::new(sender)
            }
            None => {
                tracing::info!(
                    "FCM service account not configured; using logging sender (no real pushes)"
                );
                Arc::new(LoggingFcmSender)
            }
        };
    NotificationService::new(pool, fcm, &config.notifications)
}
