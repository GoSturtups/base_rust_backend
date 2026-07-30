//! Per-request context injected into every GraphQL resolver.
//!
//! Built by the HTTP layer from request headers:
//!   * `Authorization: Bearer <access token>` -> authenticated [`CurrentUser`]
//!   * `X-Device-Id: <platform>:<id>`         -> device identity
//!   * `Accept-Language: <lang>`              -> language code

use crate::core::permission::Permission;

/// The authenticated caller. Present only when a valid access token was sent
/// AND it still matches a live user with the same email (see the auth service).
#[derive(Debug, Clone)]
pub struct CurrentUser {
    pub id: String,
    pub email: String,
    pub permissions: Vec<Permission>,
}

impl CurrentUser {
    pub fn has_permission(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }

    pub fn has_all(&self, required: &[Permission]) -> bool {
        required.iter().all(|p| self.permissions.contains(p))
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
}

impl RequestContext {
    pub fn anonymous(default_language: impl Into<String>) -> Self {
        Self {
            current_user: None,
            device_id: None,
            language: default_language.into(),
        }
    }

    /// The current user or an [`crate::core::error::AppError::AuthorizationRequired`].
    pub fn require_user(&self) -> Result<&CurrentUser, crate::core::error::AppError> {
        self.current_user
            .as_ref()
            .ok_or(crate::core::error::AppError::AuthorizationRequired)
    }
}
