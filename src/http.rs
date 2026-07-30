//! HTTP layer: Axum router, per-request GraphQL context construction and the
//! websocket subscription endpoint.

use crate::core::context::{CurrentUser, RequestContext};
use crate::i18n::Localizer;
use crate::schema::AppSchema;
use crate::users::AuthService;
use async_graphql::http::{GraphiQLSource, ALL_WEBSOCKET_PROTOCOLS};
use async_graphql::Data;
use async_graphql_axum::{GraphQLProtocol, GraphQLRequest, GraphQLResponse, GraphQLWebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::http::{header, HeaderMap};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

#[derive(Clone)]
pub struct AppState {
    pub schema: AppSchema,
    pub auth: Arc<AuthService>,
    pub localizer: Localizer,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/graphql", get(graphiql).post(graphql_handler))
        .route("/ws", get(ws_handler))
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
async fn resolve_user(auth: &AuthService, token: Option<&str>) -> Option<CurrentUser> {
    let token = token?;
    match auth.authenticate(token).await {
        Ok(user) => Some(user),
        Err(err) => {
            tracing::debug!(error = %err, "rejected access token");
            None
        }
    }
}

async fn build_context(state: &AppState, headers: &HeaderMap) -> RequestContext {
    let token = bearer_token(headers);
    let current_user = resolve_user(&state.auth, token.as_deref()).await;
    let device_id = headers
        .get("x-device-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let language = state.localizer.resolve(
        headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok()),
    );
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

async fn graphql_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    req: GraphQLRequest,
) -> GraphQLResponse {
    let ctx = build_context(&state, &headers).await;
    state.schema.execute(req.into_inner().data(ctx)).await.into()
}

/// Websocket subscription endpoint. The client authenticates in the
/// `connection_init` payload (`{"Authorization": "Bearer …", "deviceId": "…",
/// "language": "…"}`).
async fn ws_handler(
    State(state): State<AppState>,
    protocol: GraphQLProtocol,
    upgrade: WebSocketUpgrade,
) -> Response {
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
                    let current_user = resolve_user(&auth, token.as_deref()).await;
                    let device_id = params
                        .get("deviceId")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let language = localizer.resolve(
                        params.get("language").and_then(|v| v.as_str()),
                    );

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
