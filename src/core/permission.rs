//! Access-control permissions.
//!
//! Permissions are stored per-user (a text array in Postgres) and embedded in
//! the access token so most authorization checks need no extra DB round-trip.

use async_graphql::Enum;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// A single capability. New projects extend this enum with their own values;
/// the two `REGISTERED`/`READ_USERS` defaults are what every fresh user gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Enum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// The user has completed registration (base permission).
    Registered,
    /// May list registered users.
    ReadUsers,
    /// May send push notifications to arbitrary users.
    SendPushNotifications,
    /// Full moderation rights.
    Moderation,
}

impl Permission {
    pub fn as_str(&self) -> &'static str {
        match self {
            Permission::Registered => "registered",
            Permission::ReadUsers => "read_users",
            Permission::SendPushNotifications => "send_push_notifications",
            Permission::Moderation => "moderation",
        }
    }

    /// Permissions granted to a user on successful registration.
    pub fn defaults() -> Vec<Permission> {
        vec![Permission::Registered, Permission::ReadUsers]
    }
}

impl FromStr for Permission {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "registered" => Ok(Permission::Registered),
            "read_users" => Ok(Permission::ReadUsers),
            "send_push_notifications" => Ok(Permission::SendPushNotifications),
            "moderation" => Ok(Permission::Moderation),
            _ => Err(()),
        }
    }
}

/// Parse a DB/JWT string list into permissions, silently dropping unknown ones
/// (forward compatible with values a newer deployment may have written).
pub fn parse_permissions(values: &[String]) -> Vec<Permission> {
    values.iter().filter_map(|v| v.parse().ok()).collect()
}

pub fn permissions_to_strings(perms: &[Permission]) -> Vec<String> {
    perms.iter().map(|p| p.as_str().to_string()).collect()
}
