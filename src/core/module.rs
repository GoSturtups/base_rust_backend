//! The feature-module abstraction.
//!
//! Each feature (users, email, notifications, …) is a self-contained module.
//! A module contributes GraphQL types to the merged root schema (wired
//! statically in [`crate::schema`]) and may start background workers via
//! [`Module::start`]. This mirrors the "HugePlugin" pattern from the reference
//! Kotlin backend while staying idiomatic Rust.

use async_trait::async_trait;

/// A background feature module. Implementors are registered in
/// [`crate::app::App`] and their [`start`](Module::start) hook is called once
/// the database and services are ready.
#[async_trait]
pub trait Module: Send + Sync {
    /// Stable identifier, used in logs.
    fn name(&self) -> &'static str;

    /// Start any background work (queue workers, schedulers, …).
    /// Long-running loops must be spawned with `tokio::spawn` and not block.
    async fn start(&self) -> anyhow::Result<()> {
        Ok(())
    }
}
