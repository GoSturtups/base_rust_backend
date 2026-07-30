use crate::config::EmailConfig;
use crate::core::error::{AppError, AppResult};
use crate::email::model::EmailMessageRow;
use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

/// SMTP transport wrapper. Uses [`lettre`] with a Tokio executor and rustls.
#[derive(Clone)]
pub struct SmtpSender {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl SmtpSender {
    pub fn new(config: &EmailConfig) -> AppResult<Self> {
        let mut builder = if config.smtp_tls {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)
                .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?
                .port(config.smtp_port)
        } else {
            // Plain connection for local dev relays (MailHog, Mailpit, …).
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.smtp_host)
                .port(config.smtp_port)
        };

        if !config.smtp_user.is_empty() {
            builder = builder.credentials(Credentials::new(
                config.smtp_user.clone(),
                config.smtp_password.clone(),
            ));
        }

        let from: Mailbox = format!("{} <{}>", config.from_name, config.from_address)
            .parse()
            .map_err(|e| AppError::Internal(anyhow::anyhow!("invalid from address: {e}")))?;

        Ok(Self {
            transport: builder.build(),
            from,
        })
    }

    pub async fn send(&self, row: &EmailMessageRow) -> AppResult<()> {
        let to: Mailbox = row
            .to_address
            .parse()
            .map_err(|e| AppError::Validation(format!("invalid recipient address: {e}")))?;

        let message = Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(&row.subject)
            .multipart(MultiPart::alternative_plain_html(
                row.body_text.clone(),
                row.body_html.clone(),
            ))
            .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;

        self.transport
            .send(message)
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;
        Ok(())
    }
}
