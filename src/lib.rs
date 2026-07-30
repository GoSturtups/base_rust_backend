//! # base_backend
//!
//! A reusable GraphQL backend boilerplate: users (email/password + Firebase),
//! a queued SMTP mailer, push notifications with a delivery worker, and simple
//! i18n — built on Axum + async-graphql + Postgres, and designed to be dropped
//! into other projects.
//!
//! Call [`run`] from a binary, or use [`build_backend`] to get the ready-made
//! services (auth + notifications + workers started) and serve your own
//! extended GraphQL schema through the generic [`http::router`]. See the
//! `saobracaj_backend` project and `examples/consumer.rs`.

pub mod config;
pub mod core;
pub mod email;
pub mod http;
pub mod i18n;
pub mod notifications;
pub mod schema;
pub mod users;

use crate::config::Config;
use crate::core::jwt::JwtService;
use crate::core::module::Module;
use crate::email::{EmailModule, EmailService};
use crate::http::AppState;
use crate::i18n::Localizer;
use crate::notifications::{NotificationService, NotificationsModule};
use crate::schema::{AppSchema, Mutation, Query, Subscription};
use crate::users::AuthService;
use async_graphql::Schema;
use sqlx::PgPool;
use std::sync::Arc;

/// Load configuration from `env.yaml` (+ env overrides) and run the server.
pub async fn run() -> anyhow::Result<()> {
    let config = Config::load()?;
    run_with_config(config).await
}

/// Run the server with an explicit configuration.
pub async fn run_with_config(config: Config) -> anyhow::Result<()> {
    let backend = build_backend(config).await?;

    let schema = build_schema(backend.auth.clone(), backend.notifications.clone());
    let state = AppState {
        schema,
        auth: backend.auth.clone(),
        localizer: backend.localizer.clone(),
    };

    backend.serve(http::router(state)).await
}

/// The base backend's shared services, with background workers already started.
///
/// Obtain one with [`build_backend`], then either serve the built-in schema or
/// register `auth`/`notifications` as data on your own extended schema and serve
/// it via [`http::router`]. [`Backend::serve`] binds the configured address.
pub struct Backend {
    pub auth: Arc<AuthService>,
    pub notifications: Arc<NotificationService>,
    pub localizer: Localizer,
    pub config: Config,
}

impl Backend {
    /// Bind `config.server.{host,port}` and serve the given router.
    pub async fn serve(&self, router: axum::Router) -> anyhow::Result<()> {
        let addr = format!("{}:{}", self.config.server.host, self.config.server.port);
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        tracing::info!(%addr, "graphql server listening");
        axum::serve(listener, router).await?;
        Ok(())
    }
}

/// Connect to Postgres, build every base service and start the background
/// workers (email + notifications). The returned [`Backend`] is ready to plug
/// into a GraphQL schema.
pub async fn build_backend(config: Config) -> anyhow::Result<Backend> {
    let pool = core::db::connect(&config.database).await?;

    let auth = build_services(pool.clone(), &config)?;
    let notifications = notifications::build_notification_service(pool.clone(), &config);
    let email_service = EmailService::new(pool.clone(), &config.email)?;

    // Start background workers.
    let modules: Vec<Box<dyn Module>> = vec![
        Box::new(EmailModule::new(email_service.clone(), &config.email)),
        Box::new(NotificationsModule::new(
            notifications.clone(),
            &config.notifications,
        )),
    ];
    for module in &modules {
        module.start().await?;
        tracing::info!(module = module.name(), "module started");
    }

    let localizer = Localizer::new(&config.i18n);
    Ok(Backend {
        auth,
        notifications,
        localizer,
        config,
    })
}

/// Wire up the auth service (shared email service is created once and reused).
fn build_services(pool: PgPool, config: &Config) -> anyhow::Result<Arc<AuthService>> {
    let localizer = Localizer::new(&config.i18n);
    let jwt = JwtService::new(config.jwt.clone());
    let email_service = EmailService::new(pool.clone(), &config.email)?;
    Ok(users::build_auth_service(
        pool,
        config,
        jwt,
        email_service,
        localizer,
    ))
}

/// Build the merged GraphQL schema with all module services registered as data.
pub fn build_schema(
    auth_service: Arc<AuthService>,
    notification_service: Arc<NotificationService>,
) -> AppSchema {
    Schema::build(Query::default(), Mutation::default(), Subscription::default())
        .data(auth_service)
        .data(notification_service)
        .finish()
}
