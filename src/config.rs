//! Application configuration.
//!
//! Loaded from `env.yaml` (path overridable with `CONFIG_PATH`) and then
//! overlaid with environment variables so the same build runs unchanged across
//! environments. Env var names mirror the nested keys, upper-cased and joined
//! with `__`, e.g. `DATABASE__URL`, `JWT__SECRET`, `EMAIL__SMTP_PASSWORD`.

use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub jwt: JwtConfig,
    pub email: EmailConfig,
    #[serde(default)]
    pub firebase: FirebaseConfig,
    pub i18n: I18nConfig,
    pub notifications: NotificationsConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_true")]
    pub run_migrations: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    pub secret: String,
    pub issuer: String,
    pub access_ttl_minutes: i64,
    pub refresh_ttl_days: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    #[serde(default)]
    pub smtp_user: String,
    #[serde(default)]
    pub smtp_password: String,
    #[serde(default)]
    pub smtp_tls: bool,
    pub from_address: String,
    pub from_name: String,
    #[serde(default = "default_true")]
    pub confirm_email_before_auth: bool,
    #[serde(default = "default_worker_interval")]
    pub worker_interval_secs: u64,
    #[serde(default = "default_max_attempts")]
    pub max_send_attempts: i32,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FirebaseConfig {
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub project_id: String,
    #[serde(default)]
    pub service_account_path: String,
}

impl FirebaseConfig {
    pub fn is_enabled(&self) -> bool {
        !self.api_key.is_empty()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct I18nConfig {
    pub default_language: String,
    pub supported: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NotificationsConfig {
    #[serde(default = "default_worker_interval")]
    pub worker_interval_secs: u64,
    #[serde(default = "default_max_attempts")]
    pub max_send_attempts: i32,
}

fn default_max_connections() -> u32 {
    10
}
fn default_true() -> bool {
    true
}
fn default_worker_interval() -> u64 {
    10
}
fn default_max_attempts() -> i32 {
    5
}

impl Config {
    /// Load configuration from the yaml file and apply environment overrides.
    pub fn load() -> anyhow::Result<Self> {
        let path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| "env.yaml".to_string());
        Self::load_from(path)
    }

    pub fn load_from(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            anyhow::anyhow!("failed to read config {}: {e}", path.as_ref().display())
        })?;
        let mut config: Config = serde_yaml::from_str(&raw)?;
        config.apply_env_overrides();
        Ok(config)
    }

    /// Overlay a handful of well-known secrets/settings from the environment.
    fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("SERVER__HOST") {
            self.server.host = v;
        }
        if let Ok(v) = std::env::var("SERVER__PORT") {
            if let Ok(p) = v.parse() {
                self.server.port = p;
            }
        }
        if let Ok(v) = std::env::var("DATABASE__URL") {
            self.database.url = v;
        }
        if let Ok(v) = std::env::var("JWT__SECRET") {
            self.jwt.secret = v;
        }
        if let Ok(v) = std::env::var("EMAIL__SMTP_HOST") {
            self.email.smtp_host = v;
        }
        if let Ok(v) = std::env::var("EMAIL__SMTP_USER") {
            self.email.smtp_user = v;
        }
        if let Ok(v) = std::env::var("EMAIL__SMTP_PASSWORD") {
            self.email.smtp_password = v;
        }
        if let Ok(v) = std::env::var("FIREBASE__API_KEY") {
            self.firebase.api_key = v;
        }
        if let Ok(v) = std::env::var("FIREBASE__PROJECT_ID") {
            self.firebase.project_id = v;
        }
    }
}
