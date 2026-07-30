//! Unit tests that need no database or network.

use base_backend::config::{Config, I18nConfig, JwtConfig};
use base_backend::core::jwt::JwtService;
use base_backend::core::permission::{parse_permissions, Permission};
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
        .issue_pair("user-1", "user@example.com", &[Permission::ReadUsers])
        .unwrap();

    let claims = jwt.decode(&tokens.access_token, TokenType::Access).unwrap();
    assert_eq!(claims.sub, "user-1");
    assert_eq!(claims.email, "user@example.com");
    assert!(claims.perms.contains(&Permission::ReadUsers));

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
fn permissions_parse_ignores_unknown_values() {
    let parsed = parse_permissions(&[
        "read_users".into(),
        "totally_unknown".into(),
        "moderation".into(),
    ]);
    assert_eq!(parsed, vec![Permission::ReadUsers, Permission::Moderation]);
}

#[test]
fn default_permissions_match_spec() {
    assert_eq!(
        Permission::defaults(),
        vec![Permission::Registered, Permission::ReadUsers]
    );
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
