//! Firebase Cloud Messaging delivery abstraction.
//!
//! Sending via FCM HTTP v1 requires an OAuth2 access token minted from the
//! Firebase Admin SDK service-account key. [`FcmV1Sender`] performs that
//! credential exchange (RS256-signed JWT bearer grant) and posts to the
//! `messages:send` endpoint; the queue, token lifecycle and invalid-token
//! cleanup around it are fully implemented and driven through this trait.
//!
//! When no service account is configured we fall back to [`LoggingFcmSender`],
//! so the pipeline still runs end to end in development.

use crate::notifications::model::NotificationRow;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Result of a single push attempt.
pub enum SendOutcome {
    Sent,
    /// The token is no longer valid and should be removed.
    InvalidToken,
    /// The send failed. The notification is marked as a terminal `error` and is
    /// NOT retried (`claim_batch` only ever picks up `planned` rows).
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

/// Subset of the Firebase Admin SDK service-account JSON we need: the signing
/// identity (`client_email` + `private_key`), the OAuth token endpoint and the
/// `project_id` that scopes the FCM send URL.
#[derive(Debug, Clone, Deserialize)]
struct ServiceAccount {
    project_id: String,
    client_email: String,
    private_key: String,
    #[serde(default = "default_token_uri")]
    token_uri: String,
}

fn default_token_uri() -> String {
    "https://oauth2.googleapis.com/token".to_string()
}

impl ServiceAccount {
    /// Parse the service-account JSON. Returns `None` (with a warning) if the
    /// string is empty or missing the fields we require, so callers can fall
    /// back to the logging sender.
    fn from_json(json: &str) -> Option<Self> {
        let json = json.trim();
        if json.is_empty() {
            return None;
        }
        match serde_json::from_str::<ServiceAccount>(json) {
            Ok(sa)
                if !sa.project_id.is_empty()
                    && !sa.client_email.is_empty()
                    && !sa.private_key.is_empty() =>
            {
                Some(sa)
            }
            Ok(_) => {
                tracing::warn!("firebase service account JSON is missing required fields");
                None
            }
            Err(e) => {
                tracing::warn!("failed to parse firebase service account JSON: {e}");
                None
            }
        }
    }
}

/// Claims for the OAuth2 JWT bearer assertion (RFC 7523 / Google service
/// accounts).
#[derive(Serialize)]
struct OAuthClaims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: u64,
    exp: u64,
}

#[derive(Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: u64,
}

struct CachedToken {
    value: String,
    expires_at: Instant,
}

/// Real FCM HTTP v1 sender, authenticated with a service account.
pub struct FcmV1Sender {
    account: ServiceAccount,
    http: reqwest::Client,
    token: Mutex<Option<CachedToken>>,
}

impl FcmV1Sender {
    fn new(account: ServiceAccount) -> Self {
        Self {
            account,
            http: reqwest::Client::new(),
            token: Mutex::new(None),
        }
    }

    /// Build a sender from the raw service-account JSON, or `None` if it is not
    /// configured / invalid (caller falls back to [`LoggingFcmSender`]).
    pub fn from_service_account_json(json: &str) -> Option<Self> {
        ServiceAccount::from_json(json).map(Self::new)
    }

    /// Return a valid OAuth2 access token, minting (and caching) a fresh one
    /// when the cached token is missing or about to expire.
    async fn access_token(&self) -> Result<String, String> {
        let mut guard = self.token.lock().await;
        if let Some(cached) = guard.as_ref() {
            if cached.expires_at > Instant::now() + Duration::from_secs(60) {
                return Ok(cached.value.clone());
            }
        }
        let (value, ttl) = self.mint_token().await?;
        *guard = Some(CachedToken {
            value: value.clone(),
            expires_at: Instant::now() + ttl,
        });
        Ok(value)
    }

    async fn mint_token(&self) -> Result<(String, Duration), String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();
        let claims = OAuthClaims {
            iss: &self.account.client_email,
            scope: "https://www.googleapis.com/auth/firebase.messaging",
            aud: &self.account.token_uri,
            iat: now,
            exp: now + 3600,
        };
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(self.account.private_key.as_bytes())
            .map_err(|e| format!("invalid service-account private key: {e}"))?;
        let assertion = jsonwebtoken::encode(&header, &claims, &key)
            .map_err(|e| format!("failed to sign OAuth JWT: {e}"))?;

        let resp = self
            .http
            .post(&self.account.token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("oauth token request failed ({status}): {body}"));
        }

        let token: OAuthTokenResponse = resp.json().await.map_err(|e| e.to_string())?;
        // Refresh a little before the real expiry; clamp to a sane minimum.
        let ttl = Duration::from_secs(token.expires_in.clamp(60, 3600));
        Ok((token.access_token, ttl))
    }
}

#[async_trait]
impl FcmSender for FcmV1Sender {
    async fn send(&self, token: &str, notification: &NotificationRow) -> SendOutcome {
        let access = match self.access_token().await {
            Ok(t) => t,
            Err(e) => return SendOutcome::Error(format!("fcm auth failed: {e}")),
        };

        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            self.account.project_id
        );
        let mut message = serde_json::json!({
            "message": {
                "token": token,
                "notification": {
                    "title": notification.title,
                    "body": notification.body,
                }
            }
        });
        if let Some(link) = &notification.link {
            message["message"]["data"] = serde_json::json!({ "link": link });
        }

        let resp = match self.http.post(&url).bearer_auth(access).json(&message).send().await {
            Ok(r) => r,
            Err(e) => return SendOutcome::Error(e.to_string()),
        };

        let status = resp.status();
        if status.is_success() {
            return SendOutcome::Sent;
        }

        let body = resp.text().await.unwrap_or_default();
        // A stale/removed token surfaces as 404 UNREGISTERED. Everything else is
        // treated as transient so we don't purge tokens over payload/quota bugs.
        if status == reqwest::StatusCode::NOT_FOUND || body.contains("UNREGISTERED") {
            SendOutcome::InvalidToken
        } else {
            SendOutcome::Error(format!("fcm send failed ({status}): {body}"))
        }
    }
}
