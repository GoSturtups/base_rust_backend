//! Per-request context injected into every GraphQL resolver.
//!
//! Built by the HTTP layer from request headers:
//!   * `Authorization: Bearer <access token>` -> authenticated [`CurrentUser`]
//!   * `X-Device-Id: <platform>:<id>`         -> device identity
//!   * `Accept-Language: <lang>`              -> language code

use crate::core::permission::PermissionLike;

/// The authenticated caller. Present only when a valid access token was sent
/// AND it still matches a live user with the same email (see the auth service).
///
/// Permissions are held as their raw string identities because a user may carry
/// a mix of core and project-defined permissions; typed checks go through
/// [`CurrentUser::has`], which accepts any [`PermissionLike`].
#[derive(Debug, Clone)]
pub struct CurrentUser {
    pub id: String,
    pub email: String,
    pub permissions: Vec<String>,
}

impl CurrentUser {
    /// Whether the user holds the given (typed) permission.
    pub fn has<P: PermissionLike + ?Sized>(&self, permission: &P) -> bool {
        self.has_str(permission.as_str())
    }

    /// Whether the user holds the permission with this raw string identity.
    pub fn has_str(&self, permission: &str) -> bool {
        self.permissions.iter().any(|p| p == permission)
    }

    /// Whether the user holds every permission in `required` (raw strings).
    pub fn has_all_str(&self, required: &[String]) -> bool {
        required.iter().all(|r| self.has_str(r))
    }
}

/// Everything derived from the incoming request that resolvers may need.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub current_user: Option<CurrentUser>,
    /// `<platform>:<device id>` — see the notifications module.
    pub device_id: Option<String>,
    /// Resolved language code (falls back to the configured default).
    pub language: String,
    /// The language exactly as the client sent it (`Accept-Language` header or
    /// the websocket `language` param), `None` when it sent nothing. Unlike
    /// [`RequestContext::language`] this tells "the client said nothing" apart
    /// from "the client asked for the default", which matters where a language
    /// is *persisted* (registration, Firebase sign-up) rather than merely used.
    pub requested_language: Option<String>,
}

impl RequestContext {
    pub fn anonymous(default_language: impl Into<String>) -> Self {
        Self {
            current_user: None,
            device_id: None,
            language: default_language.into(),
            requested_language: None,
        }
    }

    /// The current user or an [`crate::core::error::AppError::AuthorizationRequired`].
    pub fn require_user(&self) -> Result<&CurrentUser, crate::core::error::AppError> {
        self.current_user
            .as_ref()
            .ok_or(crate::core::error::AppError::AuthorizationRequired)
    }
}
