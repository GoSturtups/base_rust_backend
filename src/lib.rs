//! # base_backend
//!
//! A reusable GraphQL backend boilerplate: users (email/password + Firebase),
//! a queued SMTP mailer, push notifications with a delivery worker, and simple
//! i18n — built on Axum + async-graphql + Postgres, and designed to be dropped
//! into other projects.
//!
//! Call [`run`] from a binary, or [`build_schema`]/[`http::router`] to embed the
//! server in an existing application.

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
    let pool = core::db::connect(&config.database).await?;

    let auth_service = build_services(pool.clone(), &config)?;
    let notification_service = notifications::build_notification_service(pool.clone(), &config);
    let email_service = EmailService::new(pool.clone(), &config.email)?;

    // Start background workers.
    let modules: Vec<Box<dyn Module>> = vec![
        Box::new(EmailModule::new(email_service.clone(), &config.email)),
        Box::new(NotificationsModule::new(
            notification_service.clone(),
            &config.notifications,
        )),
    ];
    for module in &modules {
        module.start().await?;
        tracing::info!(module = module.name(), "module started");
    }

    let schema = build_schema(auth_service.clone(), notification_service);
    let state = AppState {
        schema,
        auth: auth_service,
        localizer: Localizer::new(&config.i18n),
    };

    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "graphql server listening");
    axum::serve(listener, http::router(state)).await?;
    Ok(())
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
