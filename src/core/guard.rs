//! GraphQL guards for operation- and field-level access control.
//!
//! Attach to any query/mutation/subscription or individual field. The guards
//! are generic over [`PermissionLike`], so they work identically for the base
//! crate's [`CorePermission`](crate::core::permission::CorePermission) and for a
//! downstream project's own permission enum:
//!
//! ```ignore
//! // one core permission
//! #[graphql(guard = "RequirePermission::new(CorePermission::ReadUsers)")]
//! // one project permission
//! #[graphql(guard = "RequirePermission::new(AppPermission::ManageOrders)")]
//! // several at once, mixing core + project permissions
//! #[graphql(guard = "RequireAllPermissions::new(&[&CorePermission::Moderation, &AppPermission::ReadOrders])")]
//! ```

use crate::core::context::RequestContext;
use crate::core::error::AppError;
use crate::core::permission::PermissionLike;
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

/// Requires an authenticated user holding a single permission.
///
/// Generic over [`PermissionLike`]: the permission is referenced by its typed
/// value at the call site, so a typo is a compile error, while the check itself
/// compares the stable string identity.
pub struct RequirePermission<P: PermissionLike> {
    permission: P,
}

impl<P: PermissionLike> RequirePermission<P> {
    pub fn new(permission: P) -> Self {
        Self { permission }
    }
}

impl<P: PermissionLike + 'static> Guard for RequirePermission<P> {
    async fn check(&self, ctx: &Context<'_>) -> Result<()> {
        let request = ctx_request(ctx)?;
        let user = request
            .current_user
            .as_ref()
            .ok_or_else(|| AppError::AuthorizationRequired.extend())?;
        if user.has(&self.permission) {
            Ok(())
        } else {
            Err(AppError::AccessDenied.extend())
        }
    }
}

/// Requires an authenticated user holding **all** of the listed permissions,
/// which may freely mix core and project-defined permissions via
/// `&dyn PermissionLike`:
///
/// ```ignore
/// RequireAllPermissions::new(&[&CorePermission::Moderation, &AppPermission::ReadOrders])
/// ```
pub struct RequireAllPermissions {
    required: Vec<String>,
}

impl RequireAllPermissions {
    pub fn new(permissions: &[&dyn PermissionLike]) -> Self {
        Self {
            required: permissions.iter().map(|p| p.as_str().to_string()).collect(),
        }
    }
}

impl Guard for RequireAllPermissions {
    async fn check(&self, ctx: &Context<'_>) -> Result<()> {
        let request = ctx_request(ctx)?;
        let user = request
            .current_user
            .as_ref()
            .ok_or_else(|| AppError::AuthorizationRequired.extend())?;
        if user.has_all_str(&self.required) {
            Ok(())
        } else {
            Err(AppError::AccessDenied.extend())
        }
    }
}
