//! GraphQL guards for operation- and field-level access control.
//!
//! Attach to any query/mutation/subscription or individual field:
//! ```ignore
//! #[graphql(guard = "RequirePermission::new(Permission::ReadUsers)")]
//! async fn users(&self, ctx: &Context<'_>) -> Result<UserConnection> { ... }
//! ```

use crate::core::context::RequestContext;
use crate::core::error::AppError;
use crate::core::permission::Permission;
use async_graphql::{Context, ErrorExtensions, Guard, Result};

fn ctx_request<'a>(ctx: &'a Context<'_>) -> Result<&'a RequestContext> {
    ctx.data::<RequestContext>()
        .map_err(|_| AppError::Internal(anyhow::anyhow!("request context missing")).extend())
}

/// Requires any authenticated (logged-in) user.
pub struct RequireAuth;

impl Guard for RequireAuth {
    async fn check(&self, ctx: &Context<'_>) -> Result<()> {
        let request = ctx_request(ctx)?;
        request
            .current_user
            .as_ref()
            .map(|_| ())
            .ok_or_else(|| AppError::AuthorizationRequired.extend())
    }
}

/// Requires an authenticated user holding all of the listed permissions.
pub struct RequirePermission {
    permissions: Vec<Permission>,
}

impl RequirePermission {
    pub fn new(permission: Permission) -> Self {
        Self {
            permissions: vec![permission],
        }
    }

    pub fn all(permissions: Vec<Permission>) -> Self {
        Self { permissions }
    }
}

impl Guard for RequirePermission {
    async fn check(&self, ctx: &Context<'_>) -> Result<()> {
        let request = ctx_request(ctx)?;
        let user = request
            .current_user
            .as_ref()
            .ok_or_else(|| AppError::AuthorizationRequired.extend())?;
        if user.has_all(&self.permissions) {
            Ok(())
        } else {
            Err(AppError::AccessDenied.extend())
        }
    }
}
