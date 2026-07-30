//! The merged GraphQL schema. Each feature module contributes its own
//! Query/Mutation/Subscription roots which are combined here — adding a module
//! is a one-line change to these tuples.
//!
//! The roots carry explicit GraphQL names (`BaseQuery`/`BaseMutation`/
//! `BaseSubscription`) so a downstream project can nest them inside its own
//! `Query`/`Mutation`/`Subscription` `MergedObject` without a name clash — the
//! base fields flatten into the project's root. See `examples/consumer.rs`.

use crate::notifications::{NotificationsMutation, NotificationsQuery, NotificationsSubscription};
use crate::users::{UsersMutation, UsersQuery};
use async_graphql::{MergedObject, MergedSubscription};

#[derive(MergedObject, Default)]
#[graphql(name = "BaseQuery")]
pub struct Query(UsersQuery, NotificationsQuery);

#[derive(MergedObject, Default)]
#[graphql(name = "BaseMutation")]
pub struct Mutation(UsersMutation, NotificationsMutation);

#[derive(MergedSubscription, Default)]
#[graphql(name = "BaseSubscription")]
pub struct Subscription(NotificationsSubscription);

pub type AppSchema = async_graphql::Schema<Query, Mutation, Subscription>;
