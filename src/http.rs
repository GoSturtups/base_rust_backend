//! HTTP layer: Axum router, per-request GraphQL context construction and the
//! websocket subscription endpoint.
//!
//! [`AppState`] and [`router`] are generic over the GraphQL schema's roots, so a
//! project embedding this crate can serve its **own** extended schema (base
//! queries + its own) through the same auth/context/websocket wiring — see
//! `examples/consumer.rs` and the `saobracaj_backend` project.

use crate::core::context::{CurrentUser, RequestContext};
use crate::i18n::Localizer;
use crate::users::AuthService;
use async_graphql::http::{GraphiQLSource, ALL_WEBSOCKET_PROTOCOLS};
use async_graphql::{Data, ObjectType, Schema, SubscriptionType};
use async_graphql_axum::{GraphQLProtocol, GraphQLRequest, GraphQLResponse, GraphQLWebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::http::{header, HeaderMap};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

/// Everything the HTTP layer needs to serve a GraphQL schema with this crate's
/// authentication and request context. Generic over the schema roots so it fits
/// both the base schema and any downstream-extended schema.
pub struct AppState<Q, M, S>
where
    Q: ObjectType + 'static,
    M: ObjectType + 'static,
    S: SubscriptionType + 'static,
{
    pub schema: Schema<Q, M, S>,
    pub auth: Arc<AuthService>,
    pub localizer: Localizer,
}

// Derived `Clone` would demand `Q/M/S: Clone`, which schema roots need not be;
// `Schema` is itself cheaply cloneable, so implement `Clone` by hand.
impl<Q, M, S> Clone for AppState<Q, M, S>
where
    Q: ObjectType + 'static,
    M: ObjectType + 'static,
    S: SubscriptionType + 'static,
{
    fn clone(&self) -> Self {
        Self {
            schema: self.schema.clone(),
            auth: self.auth.clone(),
            localizer: self.localizer.clone(),
        }
    }
}

pub fn router<Q, M, S>(state: AppState<Q, M, S>) -> Router
where
    Q: ObjectType + 'static,
    M: ObjectType + 'static,
    S: SubscriptionType + 'static,
{
    Router::new()
        .route("/graphql", get(graphiql).post(graphql_handler::<Q, M, S>))
        .route("/ws", get(ws_handler::<Q, M, S>))
        .route("/health", get(|| async { "ok" }))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")))
        .map(|s| s.trim().to_string())
}

/// Authenticate a bearer token, returning `None` (anonymous) on any failure so
/// that public operations still work; guards then reject protected ones.
///
/// `requested_language` is the raw client language (e.g. from `Accept-Language`)
/// so the auth service can keep the stored user language in sync.
async fn resolve_user(
    auth: &AuthService,
    token: Option<&str>,
    requested_language: Option<&str>,
) -> Option<CurrentUser> {
    let token = token?;
    match auth.authenticate(token, requested_language).await {
        Ok(user) => Some(user),
        Err(err) => {
            tracing::debug!(error = %err, "rejected access token");
            None
        }
    }
}

/// Build the per-request GraphQL context from HTTP headers. Public so consumers
/// wiring their own transport can reuse the exact same context construction.
pub async fn build_context(
    auth: &AuthService,
    localizer: &Localizer,
    headers: &HeaderMap,
) -> RequestContext {
    let requested_language = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok());
    let token = bearer_token(headers);
    let current_user = resolve_user(auth, token.as_deref(), requested_language).await;
    let device_id = headers
        .get("x-device-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let language = localizer.resolve(requested_language);
    RequestContext {
        current_user,
        device_id,
        language,
    }
}

async fn graphiql() -> impl IntoResponse {
    Html(
        GraphiQLSource::build()
            .endpoint("/graphql")
            .subscription_endpoint("/ws")
            .finish(),
    )
}

async fn graphql_handler<Q, M, S>(
    State(state): State<AppState<Q, M, S>>,
    headers: HeaderMap,
    req: GraphQLRequest,
) -> GraphQLResponse
where
    Q: ObjectType + 'static,
    M: ObjectType + 'static,
    S: SubscriptionType + 'static,
{
    let ctx = build_context(&state.auth, &state.localizer, &headers).await;
    state.schema.execute(req.into_inner().data(ctx)).await.into()
}

/// Websocket subscription endpoint. The client authenticates in the
/// `connection_init` payload (`{"Authorization": "Bearer …", "deviceId": "…",
/// "language": "…"}`).
async fn ws_handler<Q, M, S>(
    State(state): State<AppState<Q, M, S>>,
    protocol: GraphQLProtocol,
    upgrade: WebSocketUpgrade,
) -> Response
where
    Q: ObjectType + 'static,
    M: ObjectType + 'static,
    S: SubscriptionType + 'static,
{
    let schema = state.schema.clone();
    let auth = state.auth.clone();
    let localizer = state.localizer.clone();

    upgrade
        .protocols(ALL_WEBSOCKET_PROTOCOLS)
        .on_upgrade(move |stream| {
            GraphQLWebSocket::new(stream, schema, protocol)
                .on_connection_init(move |params| async move {
                    let token = params
                        .get("Authorization")
                        .or_else(|| params.get("authorization"))
                        .and_then(|v| v.as_str())
                        .map(|v| v.strip_prefix("Bearer ").unwrap_or(v).trim().to_string());
                    let requested_language =
                        params.get("language").and_then(|v| v.as_str());
                    let current_user =
                        resolve_user(&auth, token.as_deref(), requested_language).await;
                    let device_id = params
                        .get("deviceId")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let language = localizer.resolve(requested_language);

                    let mut data = Data::default();
                    data.insert(RequestContext {
                        current_user,
                        device_id,
                        language,
                    });
                    Ok(data)
                })
                .serve()
        })
}
