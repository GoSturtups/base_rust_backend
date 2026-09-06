//! Shared test harness for the end-to-end API tests.
//!
//! Boots the *real* Axum + GraphQL server in-process (on an ephemeral port) and
//! talks to it over HTTP with `reqwest`, exactly like a client would — so the
//! whole auth path is exercised: the bearer-token extraction in the HTTP layer,
//! the DB-backed token verification in `AuthService::authenticate`, and the
//! GraphQL guards.
//!
//! Background workers (SMTP mailer, push worker) are deliberately NOT started,
//! so no external SMTP/FCM is needed. One-time email codes are read straight
//! from the `email_codes` table (they are also logged at debug level in dev).
//!
//! ## Requirements
//! A reachable PostgreSQL. Point `TEST_DATABASE_URL` at it, e.g.
//! ```bash
//! TEST_DATABASE_URL=postgres://localhost:5432/base_backend_test \
//!   cargo test --test api
//! ```
//! When unset it falls back to the `env.yaml` default. Migrations run on boot
//! (idempotent), and every test uses freshly-randomised emails so the suite is
//! safe to run repeatedly against the same database and in parallel.

#![allow(dead_code)]

use base_backend::build_schema;
use base_backend::config::Config;
use base_backend::core::jwt::JwtService;
use base_backend::email::EmailService;
use base_backend::http::{router, AppState};
use base_backend::i18n::Localizer;
use base_backend::{notifications, users};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

/// A running server plus the handles a test needs to poke at it.
pub struct TestApp {
    pub base_url: String,
    /// Direct DB access, to read one-time codes and flip flags the API cannot.
    pub pool: PgPool,
    /// The server's config — notably the JWT secret, so tests can forge tokens.
    pub config: Config,
    client: reqwest::Client,
}

impl TestApp {
    /// Boot a fresh server instance bound to a random localhost port.
    pub async fn spawn() -> TestApp {
        // Reuse the shipped defaults, then override just the DB URL.
        let mut config = Config::load_from("env.yaml").expect("load env.yaml (run from crate root)");
        config.database.url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| config.database.url.clone());
        config.database.run_migrations = true;
        // Keep the confirm-before-auth flow on: it is the more security-relevant path.
        config.email.confirm_email_before_auth = true;

        let pool = base_backend::core::db::connect(&config.database)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "could not connect/migrate Postgres at `{}`: {e}.\n\
                     Set TEST_DATABASE_URL to a reachable database.",
                    config.database.url
                )
            });

        let jwt = JwtService::new(config.jwt.clone());
        let email = EmailService::new(pool.clone(), &config.email).expect("email service");
        let localizer = Localizer::new(&config.i18n);
        let auth = users::build_auth_service(pool.clone(), &config, jwt, email, localizer.clone());
        // Install a welcome-email composer the way a consuming application
        // would, so the first-confirmation trigger is part of the tested path.
        auth.set_welcome_email(Box::new(|lang| base_backend::i18n::EmailContent {
            subject: format!("welcome:{lang}"),
            title: "Welcome".into(),
            body_html: "<p>welcome</p>".into(),
            body_text: "welcome".into(),
        }));
        let notification_service = notifications::build_notification_service(pool.clone(), &config);
        let schema = build_schema(auth.clone(), notification_service);
        let state = AppState {
            schema,
            auth,
            localizer,
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router(state)).await.unwrap();
        });

        TestApp {
            base_url: format!("http://{addr}"),
            pool,
            config,
            client: reqwest::Client::new(),
        }
    }

    // ---- GraphQL transport ----

    /// POST a GraphQL operation and return the parsed JSON response.
    pub async fn gql(&self, query: &str, token: Option<&str>) -> Value {
        self.gql_vars(query, json!({}), token).await
    }

    pub async fn gql_vars(&self, query: &str, variables: Value, token: Option<&str>) -> Value {
        self.gql_full(query, variables, token, None).await
    }

    /// As [`TestApp::gql_vars`], but with the client's `Accept-Language` — the
    /// header every real client sends and the server uses to pick the language
    /// of the emails it queues.
    pub async fn gql_lang(&self, query: &str, variables: Value, language: &str) -> Value {
        self.gql_full(query, variables, None, Some(language)).await
    }

    async fn gql_full(
        &self,
        query: &str,
        variables: Value,
        token: Option<&str>,
        language: Option<&str>,
    ) -> Value {
        let mut req = self
            .client
            .post(format!("{}/graphql", self.base_url))
            .json(&json!({ "query": query, "variables": variables }));
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        if let Some(l) = language {
            req = req.header("Accept-Language", l);
        }
        let resp = req.send().await.expect("graphql request");
        assert_eq!(
            resp.status(),
            200,
            "GraphQL endpoint always answers 200 (errors go in the body)"
        );
        resp.json().await.expect("graphql json body")
    }

    // ---- auth flow helpers ----

    /// Register + confirm a brand-new user and return its `(access, refresh)` pair.
    pub async fn register_and_confirm(&self, email: &str, password: &str) -> Tokens {
        let reg = self
            .gql_vars(REGISTER, json!({ "email": email, "password": password }), None)
            .await;
        assert!(
            reg["errors"].is_null(),
            "register should succeed, got {reg}"
        );
        // With confirm-before-auth, register issues no usable tokens.
        assert_eq!(reg["data"]["register"]["authenticated"], json!(false));

        let code = self.confirmation_code(email).await;
        let confirmed = self
            .gql_vars(CONFIRM_EMAIL, json!({ "email": email, "code": code }), None)
            .await;
        assert!(
            confirmed["errors"].is_null(),
            "confirmEmail should succeed, got {confirmed}"
        );
        let node = &confirmed["data"]["confirmEmail"];
        assert_eq!(node["authenticated"], json!(true));
        Tokens {
            access: node["accessToken"].as_str().unwrap().to_string(),
            refresh: node["refreshToken"].as_str().unwrap().to_string(),
        }
    }

    // ---- direct DB access ----

    /// The current one-time code for an email + purpose (`confirm_email` / `reset_password`).
    pub async fn code_for(&self, email: &str, purpose: &str) -> String {
        sqlx::query_scalar::<_, String>(
            "SELECT code FROM email_codes WHERE email = $1 AND purpose = $2",
        )
        .bind(email.to_lowercase())
        .bind(purpose)
        .fetch_one(&self.pool)
        .await
        .expect("a one-time code should have been issued")
    }

    pub async fn confirmation_code(&self, email: &str) -> String {
        self.code_for(email, "confirm_email").await
    }

    /// How many welcome emails (as composed by the harness above) have been
    /// queued for this address.
    pub async fn welcome_email_count(&self, email: &str) -> i64 {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM email_queue WHERE to_address = $1 AND subject LIKE 'welcome:%'",
        )
        .bind(email.to_lowercase())
        .fetch_one(&self.pool)
        .await
        .expect("count welcome emails")
    }

    /// Subjects of the emails queued for this address, oldest first. The
    /// welcome ones are `welcome:<lang>` (see the composer in `spawn`), the
    /// one-time codes carry the localizer's own localized subject.
    pub async fn email_subjects(&self, email: &str) -> Vec<String> {
        sqlx::query_scalar::<_, String>(
            "SELECT subject FROM email_queue WHERE to_address = $1 ORDER BY created_at",
        )
        .bind(email.to_lowercase())
        .fetch_all(&self.pool)
        .await
        .expect("read queued emails")
    }

    /// The language stored on the account (`users.language`), or `None` when
    /// the account carries no language yet.
    pub async fn stored_language(&self, email: &str) -> Option<String> {
        sqlx::query_scalar::<_, Option<String>>("SELECT language FROM users WHERE email = $1")
            .bind(email.to_lowercase())
            .fetch_one(&self.pool)
            .await
            .expect("user should exist")
    }

    pub async fn user_id(&self, email: &str) -> Uuid {
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE email = $1")
            .bind(email.to_lowercase())
            .fetch_one(&self.pool)
            .await
            .expect("user should exist")
    }

    pub async fn set_blocked(&self, email: &str, blocked: bool) {
        sqlx::query("UPDATE users SET blocked = $1 WHERE email = $2")
            .bind(blocked)
            .bind(email.to_lowercase())
            .execute(&self.pool)
            .await
            .unwrap();
    }

    pub async fn set_permissions(&self, email: &str, perms: &[&str]) {
        let perms: Vec<String> = perms.iter().map(|s| s.to_string()).collect();
        sqlx::query("UPDATE users SET permissions = $1 WHERE email = $2")
            .bind(&perms)
            .bind(email.to_lowercase())
            .execute(&self.pool)
            .await
            .unwrap();
    }

    // ---- token forgery (for security tests) ----

    /// A `JwtService` using the server's real secret/issuer but a custom TTL,
    /// so tests can mint already-expired tokens or tokens with forged claims.
    pub fn jwt_with_access_ttl(&self, minutes: i64) -> JwtService {
        let mut cfg = self.config.jwt.clone();
        cfg.access_ttl_minutes = minutes;
        JwtService::new(cfg)
    }

    /// A `JwtService` signing with a *different* secret (an attacker's).
    pub fn jwt_with_secret(&self, secret: &str) -> JwtService {
        let mut cfg = self.config.jwt.clone();
        cfg.secret = secret.to_string();
        JwtService::new(cfg)
    }

    /// Forge an access token for `(user_id, email)` with arbitrary permission
    /// strings, signed with the server's real secret. Used to prove the server
    /// trusts the database over the token's own claims — so an attacker may
    /// claim any raw permission string here.
    pub fn forge_access_token(&self, user_id: &str, email: &str, perms: &[&str]) -> String {
        let perms: Vec<String> = perms.iter().map(|s| s.to_string()).collect();
        JwtService::new(self.config.jwt.clone())
            .issue_pair(user_id, email, &perms)
            .unwrap()
            .access_token
    }
}

pub struct Tokens {
    pub access: String,
    pub refresh: String,
}

/// A unique email so tests never collide and are re-runnable.
pub fn unique_email() -> String {
    format!("user-{}@test.local", Uuid::new_v4())
}

// ---- JSON assertion helpers ----

/// Read `errors[0].extensions.code`, if any.
pub fn first_error_code(v: &Value) -> Option<String> {
    v["errors"][0]["extensions"]["code"]
        .as_str()
        .map(String::from)
}

/// True if any error in the response carries `extensions.code == code`.
pub fn has_error_code(v: &Value, code: &str) -> bool {
    v["errors"]
        .as_array()
        .map(|errs| {
            errs.iter()
                .any(|e| e["extensions"]["code"].as_str() == Some(code))
        })
        .unwrap_or(false)
}

// ---- GraphQL operation strings ----

pub const REGISTER: &str = r#"
    mutation($email: String!, $password: String!) {
        register(email: $email, password: $password) { accessToken refreshToken authenticated }
    }"#;

pub const REGISTER_WITH_LANGUAGE: &str = r#"
    mutation($email: String!, $password: String!, $language: String) {
        register(email: $email, password: $password, language: $language) {
            accessToken refreshToken authenticated
        }
    }"#;

pub const CONFIRM_EMAIL: &str = r#"
    mutation($email: String!, $code: String!) {
        confirmEmail(email: $email, code: $code) { accessToken refreshToken authenticated }
    }"#;

pub const LOGIN: &str = r#"
    mutation($email: String!, $password: String!) {
        login(email: $email, password: $password) { accessToken refreshToken authenticated }
    }"#;

pub const REFRESH: &str = r#"
    mutation($t: String!) {
        refreshToken(refreshToken: $t) { accessToken refreshToken authenticated }
    }"#;

pub const ME: &str = r#"query { me { id email permissions } }"#;

pub const USERS: &str = r#"query { users(limit: 100, offset: 0) { totalCount nodes { id } } }"#;

pub const USERS_WITH_EMAIL: &str =
    r#"query { users(limit: 100, offset: 0) { nodes { id email } } }"#;

pub const SET_EMAIL_NOTIFICATIONS: &str = r#"
    mutation($enabled: Boolean!) { setEmailNotifications(enabled: $enabled) }"#;

pub const FIREBASE_AUTH: &str =
    r#"mutation($t: String!) { firebaseAuth(idToken: $t) { accessToken authenticated } }"#;

pub const REQUEST_PASSWORD_RESET: &str =
    r#"mutation($email: String!) { requestPasswordReset(email: $email) }"#;

pub const CONFIRM_PASSWORD_RESET: &str = r#"
    mutation($email: String!, $code: String!, $pw: String!) {
        confirmPasswordReset(email: $email, code: $code, newPassword: $pw) {
            accessToken authenticated
        }
    }"#;
