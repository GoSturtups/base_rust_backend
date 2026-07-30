//! Firebase authentication support.
//!
//! Verifies a client-supplied Firebase ID token and returns the identity. The
//! REST implementation calls Google's Identity Toolkit `accounts:lookup`
//! endpoint (needs only the Web API key), which also tells us whether the email
//! is verified — the task requires sending our own confirmation code when it is
//! not.
//!
//! Firebase is used solely to (1) prove the token is valid and (2) obtain and
//! validate the email. We never surface or store the Firebase UID — users are
//! always matched against our own database by email.

use crate::core::error::{AppError, AppResult};
use async_trait::async_trait;
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct FirebaseUser {
    pub email: Option<String>,
    pub email_verified: bool,
}

#[async_trait]
pub trait FirebaseVerifier: Send + Sync {
    async fn verify(&self, id_token: &str) -> AppResult<FirebaseUser>;
}

/// Used when Firebase is not configured; every call fails clearly.
pub struct DisabledFirebaseVerifier;

#[async_trait]
impl FirebaseVerifier for DisabledFirebaseVerifier {
    async fn verify(&self, _id_token: &str) -> AppResult<FirebaseUser> {
        Err(AppError::Firebase("firebase is not configured".into()))
    }
}

/// Verifies tokens via the Identity Toolkit REST API.
pub struct RestFirebaseVerifier {
    api_key: String,
    client: reqwest::Client,
}

impl RestFirebaseVerifier {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            client: reqwest::Client::new(),
        }
    }
}

#[derive(Deserialize)]
struct LookupResponse {
    users: Option<Vec<LookupUser>>,
}

#[derive(Deserialize)]
struct LookupUser {
    email: Option<String>,
    #[serde(default, rename = "emailVerified")]
    email_verified: bool,
}

#[async_trait]
impl FirebaseVerifier for RestFirebaseVerifier {
    async fn verify(&self, id_token: &str) -> AppResult<FirebaseUser> {
        let url = format!(
            "https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={}",
            self.api_key
        );
        let resp = self
            .client
            .post(&url)
            .json(&serde_json::json!({ "idToken": id_token }))
            .send()
            .await
            .map_err(|e| AppError::Firebase(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(AppError::Firebase(format!(
                "lookup failed with status {}",
                resp.status()
            )));
        }

        let body: LookupResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Firebase(e.to_string()))?;

        let user = body
            .users
            .and_then(|mut u| u.pop())
            .ok_or_else(|| AppError::Firebase("token did not resolve to a user".into()))?;

        Ok(FirebaseUser {
            email: user.email,
            email_verified: user.email_verified,
        })
    }
}
