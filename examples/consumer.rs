//! Example: a downstream project that uses `base_backend` as a **library**,
//! extends its GraphQL schema, and defines its own permissions — without any
//! change to the base crate.
//!
//! Run with:
//! ```bash
//! cargo run --example consumer
//! ```
//! It builds the merged schema and prints the SDL, showing the project's own
//! `myOrders` / `allOrders` / `auditOrders` queries sitting alongside the base
//! crate's `me` / `users` queries.
//!
//! Because this example is compiled as a separate crate that depends on
//! `base_backend`, implementing the (foreign) `PermissionLike` trait for the
//! (local) `AppPermission` enum is allowed by Rust's orphan rules — exactly as
//! it would be in a real consuming project.

use async_graphql::{Context, MergedObject, Object, Result, Schema, SimpleObject};
use base_backend::core::context::RequestContext;
use base_backend::core::guard::{RequireAllPermissions, RequireAuth, RequirePermission};
use base_backend::core::permission::{CorePermission, PermissionLike};

// ---------------------------------------------------------------------------
// 1. The project's own permissions — a brand new set, defined entirely here.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppPermission {
    ReadOrders,
    ManageOrders,
}

impl PermissionLike for AppPermission {
    fn as_str(&self) -> &str {
        match self {
            AppPermission::ReadOrders => "read_orders",
            AppPermission::ManageOrders => "manage_orders",
        }
    }
}

// ---------------------------------------------------------------------------
// 2. A new GraphQL type + query root contributed by the project.
// ---------------------------------------------------------------------------

#[derive(SimpleObject)]
struct Order {
    id: String,
    total_cents: i64,
}

#[derive(Default)]
struct OrdersQuery;

#[Object]
impl OrdersQuery {
    /// Any logged-in user can see their own orders.
    #[graphql(guard = "RequireAuth")]
    async fn my_orders(&self, ctx: &Context<'_>) -> Result<Vec<Order>> {
        let request = ctx.data::<RequestContext>()?;
        let user = request.require_user()?;
        Ok(vec![Order {
            id: format!("order-for-{}", user.id),
            total_cents: 1000,
        }])
    }

    /// Listing *all* orders needs the project's own `read_orders` permission.
    #[graphql(guard = "RequirePermission::new(AppPermission::ReadOrders)")]
    async fn all_orders(&self, _ctx: &Context<'_>) -> Result<Vec<Order>> {
        Ok(Vec::new())
    }

    /// A privileged audit view guarded by BOTH a core permission and a project
    /// permission at once — the two systems compose in a single guard.
    #[graphql(
        guard = "RequireAllPermissions::new(&[&CorePermission::Moderation, &AppPermission::ReadOrders])"
    )]
    async fn audit_orders(&self, _ctx: &Context<'_>) -> Result<Vec<Order>> {
        Ok(Vec::new())
    }

    // A typo here would NOT compile, because `ManageOrder` is not a variant:
    //   #[graphql(guard = "RequirePermission::new(AppPermission::ManageOrder)")]
    //                                                            ^^^^^^^^^^^ error
}

// ---------------------------------------------------------------------------
// 3. Extend the base schema: merge the base Query with the project's OrdersQuery.
//    The base Mutation/Subscription roots are reused unchanged.
// ---------------------------------------------------------------------------

#[derive(MergedObject, Default)]
struct Query(base_backend::schema::Query, OrdersQuery);

type AppSchema =
    Schema<Query, base_backend::schema::Mutation, base_backend::schema::Subscription>;

fn build_schema() -> AppSchema {
    Schema::build(
        Query::default(),
        base_backend::schema::Mutation::default(),
        base_backend::schema::Subscription::default(),
    )
    .finish()
}

fn main() {
    let schema = build_schema();
    let sdl = schema.sdl();

    // The project's queries and the base crate's queries live in one schema.
    for field in ["myOrders", "allOrders", "auditOrders", "me", "users"] {
        assert!(sdl.contains(field), "expected `{field}` in the merged schema");
    }

    // The two permission systems really are distinct strings.
    assert_eq!(AppPermission::ReadOrders.as_str(), "read_orders");
    assert_eq!(CorePermission::Moderation.as_str(), "moderation");

    println!("Merged schema built successfully. Project + base queries:");
    println!("  myOrders / allOrders / auditOrders  (project — AppPermission)");
    println!("  me / users                          (base — CorePermission)");
}
