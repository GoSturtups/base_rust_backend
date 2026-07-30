//! Unit tests that need no database or network.

use base_backend::config::{Config, I18nConfig, JwtConfig};
use base_backend::core::context::CurrentUser;
use base_backend::core::jwt::JwtService;
use base_backend::core::permission::{permissions_to_strings, CorePermission, PermissionLike};
use base_backend::core::TokenType;
use base_backend::i18n::Localizer;

fn jwt_config() -> JwtConfig {
    JwtConfig {
        secret: "test-secret".into(),
        issuer: "test-issuer".into(),
        access_ttl_minutes: 30,
        refresh_ttl_days: 30,
    }
}

#[test]
fn jwt_roundtrip_carries_identity_and_permissions() {
    let jwt = JwtService::new(jwt_config());
    let tokens = jwt
        .issue_pair(
            "user-1",
            "user@example.com",
            &permissions_to_strings(&[CorePermission::ReadUsers]),
        )
        .unwrap();

    let claims = jwt.decode(&tokens.access_token, TokenType::Access).unwrap();
    assert_eq!(claims.sub, "user-1");
    assert_eq!(claims.email, "user@example.com");
    assert!(claims.perms.iter().any(|p| p == "read_users"));

    // An access token must not validate as a refresh token.
    assert!(jwt.decode(&tokens.access_token, TokenType::Refresh).is_err());
    // Refresh token validates as refresh.
    assert!(jwt.decode(&tokens.refresh_token, TokenType::Refresh).is_ok());
}

#[test]
fn jwt_rejects_wrong_secret() {
    let jwt = JwtService::new(jwt_config());
    let tokens = jwt.issue_pair("u", "e@x.com", &[]).unwrap();

    let mut other = jwt_config();
    other.secret = "different".into();
    let other_jwt = JwtService::new(other);
    assert!(other_jwt.decode(&tokens.access_token, TokenType::Access).is_err());
}

#[test]
fn registration_grants_no_stored_permissions() {
    // A freshly registered user is granted nothing; `registered` is implicit for
    // any persisted user rather than stored (see `UserRow::permissions`).
    assert_eq!(CorePermission::defaults(), vec![]);
}

/// Guard against accidental fail-open collisions: no two core permissions may
/// share a string identity. Downstream projects should extend this assertion to
/// their own permission set.
#[test]
fn core_permission_strings_are_unique() {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    for p in CorePermission::ALL {
        let s = p.as_str().to_string();
        assert!(seen.insert(s.clone()), "duplicate permission string: {s}");
    }
}

/// A downstream project's own permission type plugs into the same machinery:
/// `CurrentUser::has` works across core and project-defined permissions, all
/// held as raw strings.
#[test]
fn custom_permissions_extend_the_core_set() {
    #[derive(Clone, Copy)]
    enum AppPermission {
        ReadOrders,
    }
    impl PermissionLike for AppPermission {
        fn as_str(&self) -> &str {
            "read_orders"
        }
    }

    let user = CurrentUser {
        id: "u1".into(),
        email: "u@example.com".into(),
        permissions: vec!["read_users".into(), "read_orders".into()],
    };

    assert!(user.has(&CorePermission::ReadUsers)); // core permission
    assert!(user.has(&AppPermission::ReadOrders)); // project permission
    assert!(!user.has(&CorePermission::Moderation)); // not granted
    assert!(user.has_all_str(&permissions_to_strings(&[CorePermission::ReadUsers])));
}

#[test]
fn localizer_resolves_and_falls_back() {
    let localizer = Localizer::new(&I18nConfig {
        default_language: "en".into(),
        supported: vec!["en".into(), "ru".into(), "sr".into()],
    });
    assert_eq!(localizer.resolve(Some("ru-RU")), "ru");
    assert_eq!(localizer.resolve(Some("sr")), "sr");
    assert_eq!(localizer.resolve(Some("de")), "en");
    assert_eq!(localizer.resolve(None), "en");

    let content = localizer.confirm_email("ru", "123456");
    assert!(content.body_text.contains("123456"));
    assert!(!content.subject.is_empty());
}

#[test]
fn config_loads_defaults_from_yaml() {
    let config = Config::load_from("env.yaml").unwrap();
    assert_eq!(config.server.port, 8080);
    assert_eq!(config.i18n.default_language, "en");
    assert!(config.email.confirm_email_before_auth);
}
