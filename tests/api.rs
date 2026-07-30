//! End-to-end API & security tests.
//!
//! These boot the real GraphQL server and drive it over HTTP. See
//! `tests/common/mod.rs` for the harness and DB requirements.
//!
//! Coverage map:
//!   * registration / email confirmation / login happy paths + input validation
//!   * refresh-token rotation and misuse
//!   * rejection of invalid / tampered / expired / wrong-type / mismatched tokens
//!   * guards: unauthenticated access, permission-gated queries, field-level ACL
//!   * the server trusting the DB over JWT claims (perms, blocked, email binding)
//!   * anti-enumeration (login + password-reset) and brute-force throttling

mod common;

use base_backend::core::permission::Permission;
use common::*;
use serde_json::json;

// ---------------------------------------------------------------------------
// Registration / login happy paths + validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_confirm_login_and_me_round_trip() {
    let app = TestApp::spawn().await;
    let email = unique_email();

    let tokens = app.register_and_confirm(&email, "password1").await;

    // The access token identifies the caller through `me`.
    let me = app.gql(ME, Some(&tokens.access)).await;
    assert!(me["errors"].is_null(), "{me}");
    assert_eq!(me["data"]["me"]["email"], json!(email));
    let perms = me["data"]["me"]["permissions"].as_array().unwrap();
    assert!(perms.iter().any(|p| p == "REGISTERED"));
    assert!(perms.iter().any(|p| p == "READ_USERS"));

    // A confirmed user can log in and get a fresh pair.
    let login = app
        .gql_vars(LOGIN, json!({ "email": email, "password": "password1" }), None)
        .await;
    assert!(login["errors"].is_null(), "{login}");
    assert_eq!(login["data"]["login"]["authenticated"], json!(true));
    assert!(!login["data"]["login"]["accessToken"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn duplicate_registration_is_rejected() {
    let app = TestApp::spawn().await;
    let email = unique_email();
    app.gql_vars(REGISTER, json!({ "email": email, "password": "password1" }), None)
        .await;

    let again = app
        .gql_vars(REGISTER, json!({ "email": email, "password": "password1" }), None)
        .await;
    assert!(has_error_code(&again, "email_already_registered"), "{again}");
}

#[tokio::test]
async fn weak_password_and_bad_email_are_validated() {
    let app = TestApp::spawn().await;

    let weak = app
        .gql_vars(REGISTER, json!({ "email": unique_email(), "password": "short" }), None)
        .await;
    assert!(has_error_code(&weak, "validation_error"), "{weak}");

    let bad_email = app
        .gql_vars(REGISTER, json!({ "email": "not-an-email", "password": "password1" }), None)
        .await;
    assert!(has_error_code(&bad_email, "validation_error"), "{bad_email}");
}

#[tokio::test]
async fn login_before_confirmation_is_refused() {
    let app = TestApp::spawn().await;
    let email = unique_email();
    app.gql_vars(REGISTER, json!({ "email": email, "password": "password1" }), None)
        .await;

    let login = app
        .gql_vars(LOGIN, json!({ "email": email, "password": "password1" }), None)
        .await;
    assert!(has_error_code(&login, "email_not_confirmed"), "{login}");
}

/// Wrong password and unknown email must be indistinguishable (no user enumeration).
#[tokio::test]
async fn login_failures_do_not_reveal_whether_the_account_exists() {
    let app = TestApp::spawn().await;
    let email = unique_email();
    app.register_and_confirm(&email, "password1").await;

    let wrong_password = app
        .gql_vars(LOGIN, json!({ "email": email, "password": "wrong-password" }), None)
        .await;
    let unknown_user = app
        .gql_vars(LOGIN, json!({ "email": unique_email(), "password": "password1" }), None)
        .await;

    assert_eq!(first_error_code(&wrong_password).as_deref(), Some("wrong_credentials"));
    assert_eq!(first_error_code(&unknown_user).as_deref(), Some("wrong_credentials"));
}

// ---------------------------------------------------------------------------
// Refresh tokens
// ---------------------------------------------------------------------------

#[tokio::test]
async fn refresh_token_issues_a_working_access_token() {
    let app = TestApp::spawn().await;
    let email = unique_email();
    let tokens = app.register_and_confirm(&email, "password1").await;

    let refreshed = app.gql_vars(REFRESH, json!({ "t": tokens.refresh }), None).await;
    assert!(refreshed["errors"].is_null(), "{refreshed}");
    let new_access = refreshed["data"]["refreshToken"]["accessToken"].as_str().unwrap();
    assert!(!new_access.is_empty());

    let me = app.gql(ME, Some(new_access)).await;
    assert_eq!(me["data"]["me"]["email"], json!(email));
}

#[tokio::test]
async fn refresh_rejects_an_access_token_or_garbage() {
    let app = TestApp::spawn().await;
    let email = unique_email();
    let tokens = app.register_and_confirm(&email, "password1").await;

    // An access token is not a refresh token.
    let with_access = app.gql_vars(REFRESH, json!({ "t": tokens.access }), None).await;
    assert!(has_error_code(&with_access, "wrong_token"), "{with_access}");

    let garbage = app.gql_vars(REFRESH, json!({ "t": "not.a.jwt" }), None).await;
    assert!(has_error_code(&garbage, "wrong_token"), "{garbage}");
}

// ---------------------------------------------------------------------------
// Token validity / tampering / expiry
// ---------------------------------------------------------------------------

#[tokio::test]
async fn protected_operation_requires_authentication() {
    let app = TestApp::spawn().await;

    // No token at all.
    let anon = app.gql_vars(SET_EMAIL_NOTIFICATIONS, json!({ "enabled": false }), None).await;
    assert!(has_error_code(&anon, "authorization_required"), "{anon}");

    // Public `me` stays null (not an error) when unauthenticated.
    let me = app.gql(ME, None).await;
    assert!(me["errors"].is_null(), "{me}");
    assert!(me["data"]["me"].is_null());
}

#[tokio::test]
async fn garbage_and_tampered_tokens_are_treated_as_anonymous() {
    let app = TestApp::spawn().await;
    let email = unique_email();
    let tokens = app.register_and_confirm(&email, "password1").await;

    // Pure garbage.
    assert!(app.gql(ME, Some("garbage")).await["data"]["me"].is_null());

    // Flip the last character of the signature — signature no longer verifies.
    let mut tampered = tokens.access.clone();
    let last = tampered.pop().unwrap();
    tampered.push(if last == 'a' { 'b' } else { 'a' });
    let me = app.gql(ME, Some(&tampered)).await;
    assert!(me["data"]["me"].is_null(), "tampered token must not authenticate: {me}");

    // And it certainly must not pass a guard.
    let guarded = app
        .gql_vars(SET_EMAIL_NOTIFICATIONS, json!({ "enabled": false }), Some(&tampered))
        .await;
    assert!(has_error_code(&guarded, "authorization_required"), "{guarded}");
}

#[tokio::test]
async fn token_signed_with_a_foreign_secret_is_rejected() {
    let app = TestApp::spawn().await;
    let email = unique_email();
    app.register_and_confirm(&email, "password1").await;
    let uid = app.user_id(&email).await.to_string();

    // Attacker mints a token for the real user, signed with their own secret.
    let forged = app
        .jwt_with_secret("attacker-secret")
        .issue_pair(&uid, &email, &[])
        .unwrap()
        .access_token;

    let me = app.gql(ME, Some(&forged)).await;
    assert!(me["data"]["me"].is_null(), "foreign-signed token must be rejected: {me}");
}

#[tokio::test]
async fn expired_access_token_is_rejected() {
    let app = TestApp::spawn().await;
    let email = unique_email();
    app.register_and_confirm(&email, "password1").await;
    let uid = app.user_id(&email).await.to_string();

    // Same secret, but expired well beyond jsonwebtoken's 60s leeway.
    let expired = app
        .jwt_with_access_ttl(-10)
        .issue_pair(&uid, &email, &[])
        .unwrap()
        .access_token;

    let me = app.gql(ME, Some(&expired)).await;
    assert!(me["data"]["me"].is_null(), "expired token must be rejected: {me}");
}

/// A refresh token must not be usable as an access token on protected operations.
#[tokio::test]
async fn refresh_token_cannot_be_used_as_access_token() {
    let app = TestApp::spawn().await;
    let email = unique_email();
    let tokens = app.register_and_confirm(&email, "password1").await;

    let me = app.gql(ME, Some(&tokens.refresh)).await;
    assert!(me["data"]["me"].is_null(), "refresh token must not authenticate `me`: {me}");

    let guarded = app
        .gql_vars(SET_EMAIL_NOTIFICATIONS, json!({ "enabled": true }), Some(&tokens.refresh))
        .await;
    assert!(has_error_code(&guarded, "authorization_required"), "{guarded}");
}

/// The auth layer binds a token to the user's *current* email; a token whose
/// email no longer matches the DB is rejected even if correctly signed.
#[tokio::test]
async fn token_with_mismatched_email_is_rejected() {
    let app = TestApp::spawn().await;
    let email = unique_email();
    app.register_and_confirm(&email, "password1").await;
    let uid = app.user_id(&email).await.to_string();

    let forged = app.forge_access_token(&uid, "someone-else@test.local", &[]);
    let me = app.gql(ME, Some(&forged)).await;
    assert!(me["data"]["me"].is_null(), "email-mismatched token must be rejected: {me}");
}

// ---------------------------------------------------------------------------
// Authorization: permission guards & field-level access control
// ---------------------------------------------------------------------------

#[tokio::test]
async fn users_query_needs_authentication() {
    let app = TestApp::spawn().await;
    let anon = app.gql(USERS, None).await;
    assert!(has_error_code(&anon, "authorization_required"), "{anon}");
}

#[tokio::test]
async fn confirmed_user_can_list_users() {
    let app = TestApp::spawn().await;
    let email = unique_email();
    let tokens = app.register_and_confirm(&email, "password1").await;

    let list = app.gql(USERS, Some(&tokens.access)).await;
    assert!(list["errors"].is_null(), "{list}");
    assert!(list["data"]["users"]["nodes"].as_array().unwrap().len() >= 1);
}

/// Permissions are authoritative from the DB, not the token: revoking
/// `read_users` in the database blocks the query even with an unchanged token.
#[tokio::test]
async fn revoking_permission_in_db_denies_the_query() {
    let app = TestApp::spawn().await;
    let email = unique_email();
    let tokens = app.register_and_confirm(&email, "password1").await;

    assert!(app.gql(USERS, Some(&tokens.access)).await["errors"].is_null());

    app.set_permissions(&email, &["registered"]).await; // drop read_users

    let denied = app.gql(USERS, Some(&tokens.access)).await;
    assert!(has_error_code(&denied, "access_denied"), "{denied}");
}

/// A token that *claims* elevated permissions gains nothing: the server reads
/// permissions from the database, so forged `Moderation` does not unlock the
/// moderator-only `email`/`blocked` fields.
#[tokio::test]
async fn forged_permissions_in_token_are_ignored() {
    let app = TestApp::spawn().await;

    // Two users; `viewer` will try to read `target`'s email.
    let target_email = unique_email();
    app.register_and_confirm(&target_email, "password1").await;
    let target_id = app.user_id(&target_email).await.to_string();

    let viewer_email = unique_email();
    app.register_and_confirm(&viewer_email, "password1").await;
    let viewer_id = app.user_id(&viewer_email).await.to_string();

    // Forge a token claiming Moderation (which the DB user does NOT have).
    let forged = app.forge_access_token(
        &viewer_id,
        &viewer_email,
        &[Permission::Registered, Permission::ReadUsers, Permission::Moderation],
    );

    let list = app.gql(USERS_WITH_EMAIL, Some(&forged)).await;
    // The query itself is allowed (read_users), but the target's `email` field is denied.
    assert!(has_error_code(&list, "access_denied"), "{list}");

    let nodes = list["data"]["users"]["nodes"].as_array().unwrap();
    let target_node = nodes
        .iter()
        .find(|n| n["id"] == json!(target_id))
        .expect("target must be on the first page");
    assert!(
        target_node["email"].is_null(),
        "another user's email must not leak: {target_node}"
    );

    // The viewer can still read their OWN email in the same list.
    let self_node = nodes
        .iter()
        .find(|n| n["id"] == json!(viewer_id))
        .expect("viewer must be on the first page");
    assert_eq!(self_node["email"], json!(viewer_email));
}

// ---------------------------------------------------------------------------
// Blocked users
// ---------------------------------------------------------------------------

#[tokio::test]
async fn blocked_user_is_locked_out_despite_a_valid_token() {
    let app = TestApp::spawn().await;
    let email = unique_email();
    let tokens = app.register_and_confirm(&email, "password1").await;

    // Works before the block.
    assert_eq!(app.gql(ME, Some(&tokens.access)).await["data"]["me"]["email"], json!(email));

    app.set_blocked(&email, true).await;

    let me = app.gql(ME, Some(&tokens.access)).await;
    assert!(me["data"]["me"].is_null(), "blocked user must not resolve: {me}");

    let guarded = app
        .gql_vars(SET_EMAIL_NOTIFICATIONS, json!({ "enabled": false }), Some(&tokens.access))
        .await;
    assert!(has_error_code(&guarded, "authorization_required"), "{guarded}");
}

// ---------------------------------------------------------------------------
// Email-code brute force & password reset
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wrong_confirmation_code_throttles_after_max_attempts() {
    let app = TestApp::spawn().await;
    let email = unique_email();
    app.gql_vars(REGISTER, json!({ "email": email, "password": "password1" }), None)
        .await;

    // A code guaranteed to differ from the real one.
    let real = app.confirmation_code(&email).await;
    let wrong = format!("{}0", &real[..real.len() - 1]);
    let wrong = if wrong == real { format!("{}1", &real[..real.len() - 1]) } else { wrong };

    // First MAX_CODE_ATTEMPTS (5) wrong tries report `wrong_code`.
    for i in 0..5 {
        let resp = app
            .gql_vars(CONFIRM_EMAIL, json!({ "email": email, "code": wrong }), None)
            .await;
        assert!(has_error_code(&resp, "wrong_code"), "attempt {i}: {resp}");
    }
    // The next try is throttled.
    let throttled = app
        .gql_vars(CONFIRM_EMAIL, json!({ "email": email, "code": wrong }), None)
        .await;
    assert!(has_error_code(&throttled, "too_many_tries"), "{throttled}");
}

#[tokio::test]
async fn password_reset_rotates_credentials() {
    let app = TestApp::spawn().await;
    let email = unique_email();
    app.register_and_confirm(&email, "password1").await;

    let requested = app
        .gql_vars(REQUEST_PASSWORD_RESET, json!({ "email": email }), None)
        .await;
    assert_eq!(requested["data"]["requestPasswordReset"], json!(true));

    let code = app.code_for(&email, "reset_password").await;
    let confirmed = app
        .gql_vars(
            CONFIRM_PASSWORD_RESET,
            json!({ "email": email, "code": code, "pw": "password2" }),
            None,
        )
        .await;
    assert!(confirmed["errors"].is_null(), "{confirmed}");
    assert_eq!(confirmed["data"]["confirmPasswordReset"]["authenticated"], json!(true));

    // Old password no longer works; the new one does.
    let old = app
        .gql_vars(LOGIN, json!({ "email": email, "password": "password1" }), None)
        .await;
    assert!(has_error_code(&old, "wrong_credentials"), "{old}");

    let new = app
        .gql_vars(LOGIN, json!({ "email": email, "password": "password2" }), None)
        .await;
    assert!(new["errors"].is_null(), "{new}");
    assert_eq!(new["data"]["login"]["authenticated"], json!(true));
}

/// Requesting a reset for a non-existent address must still return `true`
/// (no account-enumeration side channel).
#[tokio::test]
async fn password_reset_does_not_leak_account_existence() {
    let app = TestApp::spawn().await;
    let resp = app
        .gql_vars(REQUEST_PASSWORD_RESET, json!({ "email": unique_email() }), None)
        .await;
    assert!(resp["errors"].is_null(), "{resp}");
    assert_eq!(resp["data"]["requestPasswordReset"], json!(true));
}

// ---------------------------------------------------------------------------
// Firebase (disabled in this configuration)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn firebase_auth_is_disabled_and_cannot_be_used_to_bypass() {
    let app = TestApp::spawn().await;
    let resp = app
        .gql_vars(FIREBASE_AUTH, json!({ "t": "any-id-token" }), None)
        .await;
    assert!(has_error_code(&resp, "firebase_error"), "{resp}");
}
