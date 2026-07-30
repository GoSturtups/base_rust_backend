//! Reusable infrastructure shared by all feature modules: configuration-driven
//! database access, JWT auth, permissions, GraphQL guards, error handling and
//! the [`module::Module`] abstraction.

pub mod context;
pub mod db;
pub mod error;
pub mod guard;
pub mod jwt;
pub mod module;
pub mod permission;

pub use context::{CurrentUser, RequestContext};
pub use error::{codes, AppError, AppResult, IntoFieldResult};
pub use guard::{RequireAllPermissions, RequireAuth, RequirePermission};
pub use jwt::{Claims, JwtService, TokenType, Tokens};
pub use module::Module;
pub use permission::{CorePermission, PermissionLike};
