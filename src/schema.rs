//! The merged GraphQL schema. Each feature module contributes its own
//! Query/Mutation/Subscription roots which are combined here — adding a module
//! is a one-line change to these tuples.

use crate::notifications::{NotificationsMutation, NotificationsQuery, NotificationsSubscription};
use crate::users::{UsersMutation, UsersQuery};
use async_graphql::{MergedObject, MergedSubscription};

#[derive(MergedObject, Default)]
pub struct Query(UsersQuery, NotificationsQuery);

#[derive(MergedObject, Default)]
pub struct Mutation(UsersMutation, NotificationsMutation);

#[derive(MergedSubscription, Default)]
pub struct Subscription(NotificationsSubscription);

pub type AppSchema = async_graphql::Schema<Query, Mutation, Subscription>;
