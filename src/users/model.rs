use crate::core::context::RequestContext;
use crate::core::error::AppError;
use crate::core::permission::{CorePermission, PermissionLike};
use async_graphql::{Context, ErrorExtensions, Object, SimpleObject, ID};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// A row of the `users` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRow {
    pub id: Uuid,
    pub email: String,
    pub password_hash: Option<String>,
    pub email_confirmed: bool,
    pub permissions: Vec<String>,
    pub language: Option<String>,
    pub notifications_email: bool,
    pub blocked: bool,
    pub created_at: DateTime<Utc>,
}

impl UserRow {
    /// The user's raw permission strings, as stored in the database.
    pub fn permissions(&self) -> Vec<String> {
        self.permissions.clone()
    }
}

/// GraphQL projection of a user, with field-level access control.
///
/// Demonstrates restricting individual fields: `email` and `blocked` are only
/// readable by the user themselves or by a privileged caller, whereas `id` and
/// `permissions` are always visible to any authorized viewer of the list.
pub struct User {
    row: UserRow,
}

impl User {
    pub fn new(row: UserRow) -> Self {
        Self { row }
    }

    fn is_self(&self, ctx: &Context<'_>) -> bool {
        ctx.data_opt::<RequestContext>()
            .and_then(|c| c.current_user.as_ref())
            .map(|u| u.id == self.row.id.to_string())
            .unwrap_or(false)
    }

    fn viewer_has(&self, ctx: &Context<'_>, permission: impl PermissionLike) -> bool {
        ctx.data_opt::<RequestContext>()
            .and_then(|c| c.current_user.as_ref())
            .map(|u| u.has(&permission))
            .unwrap_or(false)
    }
}

#[Object]
impl User {
    async fn id(&self) -> ID {
        ID(self.row.id.to_string())
    }

    /// Visible to the user themselves or to moderators.
    async fn email(&self, ctx: &Context<'_>) -> async_graphql::Result<String> {
        if self.is_self(ctx) || self.viewer_has(ctx, CorePermission::Moderation) {
            Ok(self.row.email.clone())
        } else {
            Err(AppError::AccessDenied.extend())
        }
    }

    /// Raw permission strings. Since permissions are an open set, they are
    /// exposed as strings rather than a fixed GraphQL enum.
    async fn permissions(&self) -> Vec<String> {
        self.row.permissions()
    }

    async fn email_confirmed(&self) -> bool {
        self.row.email_confirmed
    }

    /// Only moderators (or the user themselves) may see block status.
    async fn blocked(&self, ctx: &Context<'_>) -> async_graphql::Result<bool> {
        if self.is_self(ctx) || self.viewer_has(ctx, CorePermission::Moderation) {
            Ok(self.row.blocked)
        } else {
            Err(AppError::AccessDenied.extend())
        }
    }

    async fn language(&self) -> Option<String> {
        self.row.language.clone()
    }

    async fn created_at(&self) -> DateTime<Utc> {
        self.row.created_at
    }
}

/// A page of users with a total count for offset pagination.
#[derive(SimpleObject)]
pub struct UserConnection {
    pub nodes: Vec<User>,
    pub total_count: i64,
    pub has_next_page: bool,
}

/// Access + refresh token pair returned by auth mutations.
#[derive(SimpleObject, Clone)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    /// False when registration requires email confirmation before tokens are valid.
    pub authenticated: bool,
}
