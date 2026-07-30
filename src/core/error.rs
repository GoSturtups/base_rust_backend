//! Error handling.
//!
//! Every user-facing error carries a stable, machine-readable `code`
//! (e.g. `wrong_credentials`) and a human-readable English `message`, surfaced
//! through the standard GraphQL `errors` array with the code in `extensions.code`.

use async_graphql::{ErrorExtensions, FieldError};
use thiserror::Error;

/// Stable error codes returned to clients in `extensions.code`.
pub mod codes {
    pub const UNKNOWN: &str = "unknown";
    pub const VALIDATION: &str = "validation_error";
    pub const WRONG_CREDENTIALS: &str = "wrong_credentials";
    pub const EMAIL_ALREADY_REGISTERED: &str = "email_already_registered";
    pub const EMAIL_NOT_CONFIRMED: &str = "email_not_confirmed";
    pub const EMAIL_NOT_REGISTERED: &str = "email_not_registered";
    pub const USER_NOT_FOUND: &str = "user_not_found";
    pub const WRONG_CODE: &str = "wrong_code";
    pub const CODE_EXPIRED: &str = "code_expired";
    pub const CODE_NOT_FOUND: &str = "code_not_found";
    pub const WRONG_TOKEN: &str = "wrong_token";
    pub const TOKEN_EXPIRED: &str = "token_expired";
    pub const AUTHORIZATION_REQUIRED: &str = "authorization_required";
    pub const ACCESS_DENIED: &str = "access_denied";
    pub const TOO_MANY_TRIES: &str = "too_many_tries";
    pub const NOT_FOUND: &str = "not_found";
    pub const FIREBASE_ERROR: &str = "firebase_error";
    pub const INTERNAL: &str = "internal_error";
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("{0}")]
    Validation(String),
    #[error("wrong email or password")]
    WrongCredentials,
    #[error("email is already registered")]
    EmailAlreadyRegistered,
    #[error("email is not confirmed")]
    EmailNotConfirmed,
    #[error("email is not registered")]
    EmailNotRegistered,
    #[error("user not found")]
    UserNotFound,
    #[error("confirmation code is wrong")]
    WrongCode,
    #[error("confirmation code has expired")]
    CodeExpired,
    #[error("no confirmation code was requested")]
    CodeNotFound,
    #[error("invalid token")]
    WrongToken,
    #[error("token has expired")]
    TokenExpired,
    #[error("authorization required")]
    AuthorizationRequired,
    #[error("access denied")]
    AccessDenied,
    #[error("too many attempts, try again later")]
    TooManyTries,
    #[error("{0} not found")]
    NotFound(String),
    #[error("firebase error: {0}")]
    Firebase(String),
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

impl AppError {
    pub fn code(&self) -> &'static str {
        use codes::*;
        match self {
            AppError::Validation(_) => VALIDATION,
            AppError::WrongCredentials => WRONG_CREDENTIALS,
            AppError::EmailAlreadyRegistered => EMAIL_ALREADY_REGISTERED,
            AppError::EmailNotConfirmed => EMAIL_NOT_CONFIRMED,
            AppError::EmailNotRegistered => EMAIL_NOT_REGISTERED,
            AppError::UserNotFound => USER_NOT_FOUND,
            AppError::WrongCode => WRONG_CODE,
            AppError::CodeExpired => CODE_EXPIRED,
            AppError::CodeNotFound => CODE_NOT_FOUND,
            AppError::WrongToken => WRONG_TOKEN,
            AppError::TokenExpired => TOKEN_EXPIRED,
            AppError::AuthorizationRequired => AUTHORIZATION_REQUIRED,
            AppError::AccessDenied => ACCESS_DENIED,
            AppError::TooManyTries => TOO_MANY_TRIES,
            AppError::NotFound(_) => NOT_FOUND,
            AppError::Firebase(_) => FIREBASE_ERROR,
            AppError::Internal(_) => INTERNAL,
        }
    }

    /// Full internal detail suitable for logs and DB records — unlike `Display`,
    /// which is the client-safe message (`Internal` collapses to "internal
    /// error"). Use this when persisting a failure reason (e.g. `last_error`).
    pub fn detail(&self) -> String {
        match self {
            // `{:#}` renders the whole anyhow cause chain.
            AppError::Internal(err) => format!("{err:#}"),
            other => other.to_string(),
        }
    }
}

/// Convert sqlx errors into an opaque internal error (details go to the logs,
/// never to the client).
impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        AppError::Internal(anyhow::anyhow!(e))
    }
}

/// Render into a GraphQL error with the stable code attached in extensions.
impl ErrorExtensions for AppError {
    fn extend(&self) -> FieldError {
        if let AppError::Internal(err) = self {
            tracing::error!(error = ?err, "internal error");
        }
        let code = self.code();
        FieldError::new(self.to_string()).extend_with(|_, e| e.set("code", code))
    }
}

pub type AppResult<T> = Result<T, AppError>;

/// Convert an [`AppResult`] into a GraphQL result, attaching the stable error
/// code in `extensions.code`.
///
/// `async_graphql` already provides a blanket `From<T: Display>` for its error
/// type, so we cannot add our own `From<AppError>` — this trait is the explicit,
/// code-preserving bridge used by resolvers (`some_service.call().await.gql()`).
pub trait IntoFieldResult<T> {
    fn gql(self) -> async_graphql::Result<T>;
}

impl<T> IntoFieldResult<T> for AppResult<T> {
    fn gql(self) -> async_graphql::Result<T> {
        self.map_err(|e| e.extend())
    }
}
