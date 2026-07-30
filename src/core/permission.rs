//! Access-control permissions.
//!
//! Permissions are an **open set**: the base crate ships its own
//! [`CorePermission`] values, and any downstream project extends the system by
//! defining its own enum and implementing [`PermissionLike`] for it — no change
//! to this crate is required. Guards ([`crate::core::guard`]) work uniformly
//! across all permission types because they compare the stable string returned
//! by [`PermissionLike::as_str`].
//!
//! On the wire and at rest a permission is just a string: it is stored per-user
//! (a `TEXT[]` column in Postgres) and embedded in the access token so most
//! authorization checks need no extra DB round-trip. Typed enums exist only at
//! the *definition* and *guard* sites, where the compiler can catch typos; the
//! string form appears solely inside `as_str` and at the storage boundary.

/// A capability that can gate a GraphQL operation or field.
///
/// Implement this for your project's own permission enum to plug it into the
/// existing guards:
///
/// ```
/// use base_backend::core::permission::PermissionLike;
///
/// #[derive(Clone, Copy)]
/// enum AppPermission { ReadOrders, ManageOrders }
///
/// impl PermissionLike for AppPermission {
///     fn as_str(&self) -> &str {
///         match self {
///             AppPermission::ReadOrders => "read_orders",
///             AppPermission::ManageOrders => "manage_orders",
///         }
///     }
/// }
/// ```
///
/// The trait is object-safe, so heterogeneous requirements (mixing core and
/// project permissions) can be expressed with `&dyn PermissionLike` — see
/// [`crate::core::guard::RequireAllPermissions`].
pub trait PermissionLike: Send + Sync {
    /// The stable string identity of this permission, as stored in the database
    /// and the access token. Must be unique across every permission the
    /// deployment uses (see [`CorePermission::ALL`] and the uniqueness test).
    fn as_str(&self) -> &str;
}

/// Permissions owned by the base crate. Downstream projects define their own
/// enum rather than adding variants here, so this stays stable as a library.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CorePermission {
    /// The user has completed registration (base permission).
    Registered,
    /// May list registered users.
    ReadUsers,
    /// May send push notifications to arbitrary users.
    SendPushNotifications,
    /// Full moderation rights.
    Moderation,
}

impl CorePermission {
    /// Every core permission, for iteration (e.g. uniqueness checks).
    pub const ALL: [CorePermission; 4] = [
        CorePermission::Registered,
        CorePermission::ReadUsers,
        CorePermission::SendPushNotifications,
        CorePermission::Moderation,
    ];

    /// Permissions **stored** for a user on successful registration.
    ///
    /// Empty: a freshly registered user is granted no permissions and must have
    /// any capability assigned explicitly. Note that [`CorePermission::Registered`]
    /// is *not* stored here — it is implicit for every persisted user (see
    /// [`crate::users::model::UserRow::permissions`]), so it holds even when this
    /// list, and the stored `permissions` column, are empty.
    pub fn defaults() -> Vec<CorePermission> {
        vec![]
    }
}

impl PermissionLike for CorePermission {
    fn as_str(&self) -> &str {
        match self {
            CorePermission::Registered => "registered",
            CorePermission::ReadUsers => "read_users",
            CorePermission::SendPushNotifications => "send_push_notifications",
            CorePermission::Moderation => "moderation",
        }
    }
}

// A reference to a permission is itself a permission, so `&CorePermission` (and
// any `&P`) can be passed wherever `impl PermissionLike` is expected.
impl<T: PermissionLike + ?Sized> PermissionLike for &T {
    fn as_str(&self) -> &str {
        (**self).as_str()
    }
}

/// Serialize a list of typed permissions to the string form stored in the DB /
/// access token. Granting code should always go through this rather than
/// hand-writing strings, so the only place a permission string is spelled out
/// is each type's `as_str`.
pub fn permissions_to_strings<P: PermissionLike>(perms: &[P]) -> Vec<String> {
    perms.iter().map(|p| p.as_str().to_string()).collect()
}
