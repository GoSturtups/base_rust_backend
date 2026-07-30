//! Users module: registration, email confirmation, login, refresh, password
//! reset, Firebase auth, permissions and a paginated user listing.

mod firebase;
mod graphql;
mod model;
mod password;
mod repository;
mod service;

pub use firebase::{
    DisabledFirebaseVerifier, FirebaseUser, FirebaseVerifier, RestFirebaseVerifier,
};
pub use graphql::{UsersMutation, UsersQuery};
pub use repository::UserRepository;
pub use service::AuthService;

use crate::config::Config;
use crate::core::jwt::JwtService;
use crate::email::EmailService;
use crate::i18n::Localizer;
use sqlx::PgPool;
use std::sync::Arc;

/// Assemble the users [`AuthService`] from its dependencies, picking a live or
/// disabled Firebase verifier based on config.
pub fn build_auth_service(
    pool: PgPool,
    config: &Config,
    jwt: JwtService,
    email: Arc<EmailService>,
    localizer: Localizer,
) -> Arc<AuthService> {
    let firebase: Arc<dyn FirebaseVerifier> = if config.firebase.is_enabled() {
        Arc::new(RestFirebaseVerifier::new(config.firebase.api_key.clone()))
    } else {
        Arc::new(DisabledFirebaseVerifier)
    };

    AuthService::new(
        UserRepository::new(pool),
        jwt,
        email,
        localizer,
        firebase,
        config.email.confirm_email_before_auth,
    )
}
