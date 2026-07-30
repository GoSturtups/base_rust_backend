//! GraphQL surface of the notifications module, including a subscription that
//! streams notifications to the authenticated user in real time.

use crate::core::context::RequestContext;
use crate::core::error::{AppError, IntoFieldResult};
use crate::notifications::model::{Device, NotificationEvent};
use crate::notifications::service::NotificationService;
use async_graphql::{Context, Object, Subscription};
use futures_util::Stream;
use std::sync::Arc;
use tokio::sync::broadcast::error::RecvError;
use uuid::Uuid;

fn service<'a>(ctx: &Context<'a>) -> async_graphql::Result<&'a Arc<NotificationService>> {
    ctx.data::<Arc<NotificationService>>()
}

/// The authenticated user id and the request's device id (from `X-Device-Id`).
fn user_and_device(ctx: &Context<'_>) -> async_graphql::Result<(Uuid, String)> {
    let request = ctx.data::<RequestContext>()?;
    let user = request.require_user()?;
    let id = Uuid::parse_str(&user.id).map_err(|_| AppError::UserNotFound)?;
    let device_id = request
        .device_id
        .clone()
        .ok_or_else(|| AppError::Validation("missing X-Device-Id header".into()))?;
    Ok((id, device_id))
}

#[derive(Default)]
pub struct NotificationsQuery;

#[Object]
impl NotificationsQuery {
    /// Devices registered by the current user.
    async fn my_devices(&self, ctx: &Context<'_>) -> async_graphql::Result<Vec<Device>> {
        let request = ctx.data::<RequestContext>()?;
        let user = request.require_user()?;
        let id = Uuid::parse_str(&user.id).map_err(|_| AppError::UserNotFound)?;
        service(ctx)?.list_devices(id).await.gql()
    }
}

#[derive(Default)]
pub struct NotificationsMutation;

#[Object]
impl NotificationsMutation {
    /// Register (or refresh) the current device, optionally with its FCM token.
    async fn register_device(
        &self,
        ctx: &Context<'_>,
        push_token: Option<String>,
        platform: Option<String>,
    ) -> async_graphql::Result<Device> {
        let (user_id, device_id) = user_and_device(ctx)?;
        service(ctx)?
            .register_device(user_id, &device_id, push_token.as_deref(), platform.as_deref())
            .await
            .gql()
    }

    /// Enable/disable push for the current device.
    async fn set_device_push_enabled(
        &self,
        ctx: &Context<'_>,
        enabled: bool,
    ) -> async_graphql::Result<bool> {
        let (user_id, device_id) = user_and_device(ctx)?;
        service(ctx)?
            .set_push_enabled(user_id, &device_id, enabled)
            .await
            .gql()
    }

    /// Update the FCM registration token for the current device.
    async fn update_fcm_token(
        &self,
        ctx: &Context<'_>,
        token: String,
    ) -> async_graphql::Result<bool> {
        let (user_id, device_id) = user_and_device(ctx)?;
        service(ctx)?
            .update_fcm_token(user_id, &device_id, &token)
            .await
            .gql()
    }
}

#[derive(Default)]
pub struct NotificationsSubscription;

#[Subscription]
impl NotificationsSubscription {
    /// Stream notifications addressed to the authenticated user.
    async fn notifications(
        &self,
        ctx: &Context<'_>,
    ) -> async_graphql::Result<impl Stream<Item = NotificationEvent>> {
        let request = ctx.data::<RequestContext>()?;
        let user = request.require_user()?;
        let uid = user.id.clone();
        let rx = service(ctx)?.subscribe();

        Ok(futures_util::stream::unfold(
            (rx, uid),
            |(mut rx, uid)| async move {
                loop {
                    match rx.recv().await {
                        Ok(event) if event.user_id == uid => {
                            return Some((event, (rx, uid)));
                        }
                        Ok(_) => continue,
                        Err(RecvError::Lagged(_)) => continue,
                        Err(RecvError::Closed) => return None,
                    }
                }
            },
        ))
    }
}
