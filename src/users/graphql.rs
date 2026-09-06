//! GraphQL surface of the users module.
//!
//! Operations are marked with guards to show the three access levels required
//! by the spec:
//!   * **public** — `register`, `login`, … (no guard);
//!   * **authenticated only** — `me`, `setEmailNotifications` (`RequireAuth`);
//!   * **permission gated** — `users` (`RequirePermission`).

use crate::core::context::RequestContext;
use crate::core::error::IntoFieldResult;
use crate::core::guard::{RequireAuth, RequirePermission};
use crate::core::permission::CorePermission;
use crate::users::model::{AuthTokens, UserConnection};
use crate::users::service::AuthService;
use async_graphql::{Context, Object, SimpleObject};
use std::sync::Arc;

/// The authenticated caller's own profile.
#[derive(SimpleObject)]
pub struct Viewer {
    pub id: String,
    pub email: String,
    pub permissions: Vec<String>,
}

fn service<'a>(ctx: &Context<'a>) -> async_graphql::Result<&'a Arc<AuthService>> {
    ctx.data::<Arc<AuthService>>()
}

/// The language the client asked for on this very request (`Accept-Language`),
/// untouched by the configured fallback — see
/// [`RequestContext::requested_language`].
///
/// Every mailing mutation passes it down: an account created (or a mailbox
/// contacted) by a client whose UI is Russian must not be written to in the
/// server's default language just because nothing is stored on the account yet.
fn requested_language(ctx: &Context<'_>) -> Option<String> {
    ctx.data_opt::<RequestContext>()
        .and_then(|c| c.requested_language.clone())
}

#[derive(Default)]
pub struct UsersQuery;

#[Object]
impl UsersQuery {
    /// The current user, or null when unauthenticated. Public.
    async fn me(&self, ctx: &Context<'_>) -> Option<Viewer> {
        ctx.data_opt::<RequestContext>()
            .and_then(|c| c.current_user.as_ref())
            .map(|u| Viewer {
                id: u.id.clone(),
                email: u.email.clone(),
                permissions: u.permissions.clone(),
            })
    }

    /// Paginated list of registered users. Requires `READ_USERS`.
    #[graphql(guard = "RequirePermission::new(CorePermission::ReadUsers)")]
    async fn users(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 20)] limit: i64,
        #[graphql(default = 0)] offset: i64,
    ) -> async_graphql::Result<UserConnection> {
        service(ctx)?.list_users(limit, offset).await.gql()
    }
}

#[derive(Default)]
pub struct UsersMutation;

#[Object]
impl UsersMutation {
    /// Register with email + password. Sends a 6-digit confirmation code.
    async fn register(
        &self,
        ctx: &Context<'_>,
        email: String,
        password: String,
        language: Option<String>,
    ) -> async_graphql::Result<AuthTokens> {
        // The explicit argument wins; otherwise the request's own language
        // (`Accept-Language`) stands in, so clients that never pass the
        // argument still get their account and e-mails in their language.
        let language = language.or_else(|| requested_language(ctx));
        service(ctx)?
            .register(&email, &password, language.as_deref())
            .await
            .gql()
    }

    /// Confirm the emailed code; on success the user is logged in.
    async fn confirm_email(
        &self,
        ctx: &Context<'_>,
        email: String,
        code: String,
    ) -> async_graphql::Result<AuthTokens> {
        let language = requested_language(ctx);
        service(ctx)?
            .confirm_email(&email, &code, language.as_deref())
            .await
            .gql()
    }

    async fn resend_confirmation_code(
        &self,
        ctx: &Context<'_>,
        email: String,
    ) -> async_graphql::Result<bool> {
        let language = requested_language(ctx);
        service(ctx)?
            .resend_confirmation(&email, language.as_deref())
            .await
            .gql()
    }

    async fn login(
        &self,
        ctx: &Context<'_>,
        email: String,
        password: String,
    ) -> async_graphql::Result<AuthTokens> {
        // An unconfirmed account gets its code re-sent from inside `login`.
        let language = requested_language(ctx);
        service(ctx)?
            .login(&email, &password, language.as_deref())
            .await
            .gql()
    }

    async fn refresh_token(
        &self,
        ctx: &Context<'_>,
        refresh_token: String,
    ) -> async_graphql::Result<AuthTokens> {
        service(ctx)?.refresh(&refresh_token).await.gql()
    }

    async fn request_password_reset(
        &self,
        ctx: &Context<'_>,
        email: String,
    ) -> async_graphql::Result<bool> {
        let language = requested_language(ctx);
        service(ctx)?
            .request_password_reset(&email, language.as_deref())
            .await
            .gql()
    }

    async fn confirm_password_reset(
        &self,
        ctx: &Context<'_>,
        email: String,
        code: String,
        new_password: String,
    ) -> async_graphql::Result<AuthTokens> {
        let language = requested_language(ctx);
        service(ctx)?
            .confirm_password_reset(&email, &code, &new_password, language.as_deref())
            .await
            .gql()
    }

    /// Log in or register via a Firebase ID token.
    async fn firebase_auth(
        &self,
        ctx: &Context<'_>,
        id_token: String,
    ) -> async_graphql::Result<AuthTokens> {
        let language = requested_language(ctx);
        service(ctx)?
            .firebase_auth(&id_token, language.as_deref())
            .await
            .gql()
    }

    /// Toggle the caller's email notifications (does not affect one-time codes).
    #[graphql(guard = "RequireAuth")]
    async fn set_email_notifications(
        &self,
        ctx: &Context<'_>,
        enabled: bool,
    ) -> async_graphql::Result<bool> {
        let request = ctx.data::<RequestContext>()?;
        let user = request.require_user()?;
        service(ctx)?
            .set_email_notifications(&user.id, enabled)
            .await
            .gql()
    }
}
