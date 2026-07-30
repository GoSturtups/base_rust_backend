//! Email module: an SMTP-backed, queued mailer.
//!
//! Callers never send synchronously — they [`EmailService::enqueue`] a message,
//! and a background worker (started via the [`Module`] hook) claims planned
//! rows, sends them over SMTP and records the outcome, retrying failures up to
//! `email.max_send_attempts`.
//!
//! Per-user email opt-out is enforced by the caller (the users module) so that
//! one-time confirmation codes always go out regardless of the user's setting,
//! while general notifications respect it.

mod model;
mod repository;
mod sender;

pub use model::{EmailStatus, NewEmail};

use crate::config::EmailConfig;
use crate::core::error::AppResult;
use crate::core::module::Module;
use async_trait::async_trait;
use repository::EmailRepository;
use sender::SmtpSender;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// Public API for enqueuing email. Cheap to clone (`Arc` inside).
#[derive(Clone)]
pub struct EmailService {
    repo: EmailRepository,
    sender: SmtpSender,
    max_attempts: i32,
}

impl EmailService {
    pub fn new(pool: PgPool, config: &EmailConfig) -> AppResult<Arc<Self>> {
        Ok(Arc::new(Self {
            repo: EmailRepository::new(pool),
            sender: SmtpSender::new(config)?,
            max_attempts: config.max_send_attempts,
        }))
    }

    /// Add a message to the queue; it will be delivered by the worker.
    pub async fn enqueue(&self, email: NewEmail) -> AppResult<Uuid> {
        self.repo.enqueue(&email).await
    }

    /// Claim and attempt to deliver up to `batch` queued messages.
    /// Returns the number of messages processed.
    async fn process_batch(&self, batch: i64) -> AppResult<usize> {
        let rows = self.repo.claim_batch(batch, self.max_attempts).await?;
        let count = rows.len();
        for row in rows {
            match self.sender.send(&row).await {
                Ok(()) => {
                    self.repo.mark_sent(row.id).await?;
                }
                Err(e) => {
                    tracing::warn!(email_id = %row.id, error = %e, "email send failed");
                    self.repo.mark_failed(row.id, &e.to_string()).await?;
                }
            }
        }
        Ok(count)
    }
}

/// Background worker module for the email queue.
pub struct EmailModule {
    service: Arc<EmailService>,
    interval: Duration,
}

impl EmailModule {
    pub fn new(service: Arc<EmailService>, config: &EmailConfig) -> Self {
        Self {
            service,
            interval: Duration::from_secs(config.worker_interval_secs),
        }
    }
}

#[async_trait]
impl Module for EmailModule {
    fn name(&self) -> &'static str {
        "email"
    }

    async fn start(&self) -> anyhow::Result<()> {
        let service = self.service.clone();
        let interval = self.interval;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                if let Err(e) = service.process_batch(20).await {
                    tracing::error!(error = %e, "email worker batch failed");
                }
            }
        });
        Ok(())
    }
}
