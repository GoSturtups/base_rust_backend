//! JWT encoding/decoding for access and refresh tokens.
//!
//! The access token embeds the user id, email and permissions so that guards
//! can authorize most requests without a DB call; a full DB check
//! (see [`crate::core::context`]) still runs to confirm the token matches a
//! live user with the same email.

use crate::config::JwtConfig;
use crate::core::error::{AppError, AppResult};
use crate::core::permission::Permission;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenType {
    Access,
    Refresh,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// user id
    pub sub: String,
    pub email: String,
    #[serde(default)]
    pub perms: Vec<Permission>,
    pub typ: TokenType,
    pub iss: String,
    pub exp: i64,
    pub iat: i64,
}

#[derive(Debug, Clone)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Clone)]
pub struct JwtService {
    config: JwtConfig,
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl JwtService {
    pub fn new(config: JwtConfig) -> Self {
        let encoding = EncodingKey::from_secret(config.secret.as_bytes());
        let decoding = DecodingKey::from_secret(config.secret.as_bytes());
        Self {
            config,
            encoding,
            decoding,
        }
    }

    pub fn issue_pair(
        &self,
        user_id: &str,
        email: &str,
        perms: &[Permission],
    ) -> AppResult<Tokens> {
        let access = self.issue(user_id, email, perms, TokenType::Access)?;
        let refresh = self.issue(user_id, email, perms, TokenType::Refresh)?;
        Ok(Tokens {
            access_token: access,
            refresh_token: refresh,
        })
    }

    fn issue(
        &self,
        user_id: &str,
        email: &str,
        perms: &[Permission],
        typ: TokenType,
    ) -> AppResult<String> {
        let now = Utc::now();
        let exp = match typ {
            TokenType::Access => now + Duration::minutes(self.config.access_ttl_minutes),
            TokenType::Refresh => now + Duration::days(self.config.refresh_ttl_days),
        };
        let claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            perms: perms.to_vec(),
            typ,
            iss: self.config.issuer.clone(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
        };
        encode(&Header::default(), &claims, &self.encoding)
            .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))
    }

    pub fn decode(&self, token: &str, expected: TokenType) -> AppResult<Claims> {
        let mut validation = Validation::default();
        validation.set_issuer(&[&self.config.issuer]);
        let data = decode::<Claims>(token, &self.decoding, &validation).map_err(|e| {
            use jsonwebtoken::errors::ErrorKind;
            match e.kind() {
                ErrorKind::ExpiredSignature => AppError::TokenExpired,
                _ => AppError::WrongToken,
            }
        })?;
        if data.claims.typ != expected {
            return Err(AppError::WrongToken);
        }
        Ok(data.claims)
    }
}
