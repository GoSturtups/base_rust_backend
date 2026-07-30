//! Authentication & user-management use cases.

use crate::core::context::CurrentUser;
use crate::core::error::{AppError, AppResult};
use crate::core::jwt::{JwtService, TokenType};
use crate::core::permission::{permissions_to_strings, Permission};
use crate::email::{EmailService, NewEmail};
use crate::i18n::Localizer;
use crate::users::firebase::FirebaseVerifier;
use crate::users::model::{AuthTokens, User, UserConnection, UserRow};
use crate::users::password::{generate_code, hash_password, verify_password};
use crate::users::repository::{NewUser, UserRepository};
use chrono::{Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

const CONFIRM_EMAIL: &str = "confirm_email";
const RESET_PASSWORD: &str = "reset_password";
const CODE_TTL_MINUTES: i64 = 15;
const MAX_CODE_ATTEMPTS: i32 = 5;
const MAX_PAGE_SIZE: i64 = 100;

pub struct AuthService {
    repo: UserRepository,
    jwt: JwtService,
    email: Arc<EmailService>,
    localizer: Localizer,
    firebase: Arc<dyn FirebaseVerifier>,
    confirm_email_before_auth: bool,
}

impl AuthService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repo: UserRepository,
        jwt: JwtService,
        email: Arc<EmailService>,
        localizer: Localizer,
        firebase: Arc<dyn FirebaseVerifier>,
        confirm_email_before_auth: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            repo,
            jwt,
            email,
            localizer,
            firebase,
            confirm_email_before_auth,
        })
    }

    // ---- request-time token verification (used by the HTTP auth layer) ----

    /// Validate an access token: verify the JWT signature/expiry AND confirm it
    /// still matches a live, non-blocked user with the same email.
    pub async fn authenticate(&self, access_token: &str) -> AppResult<CurrentUser> {
        let claims = self.jwt.decode(access_token, TokenType::Access)?;
        let id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::WrongToken)?;
        let user = self.repo.get_by_id(id).await?.ok_or(AppError::WrongToken)?;
        if user.email != claims.email {
            return Err(AppError::WrongToken);
        }
        if user.blocked {
            return Err(AppError::AccessDenied);
        }
        let permissions = user.permissions();
        Ok(CurrentUser {
            id: user.id.to_string(),
            email: user.email,
            permissions,
        })
    }

    // ---- registration / login ----

    pub async fn register(
        &self,
        email: &str,
        password: &str,
        language: Option<String>,
    ) -> AppResult<AuthTokens> {
        let email = normalize_email(email)?;
        validate_password(password)?;
        if self.repo.get_by_email(&email).await?.is_some() {
            return Err(AppError::EmailAlreadyRegistered);
        }

        let user = self
            .repo
            .insert(NewUser {
                email: email.clone(),
                password_hash: Some(hash_password(password)?),
                permissions: permissions_to_strings(&Permission::defaults()),
                language: language.clone(),
                email_confirmed: false,
            })
            .await?;

        self.send_code(&email, CONFIRM_EMAIL, language.as_deref())
            .await?;

        if self.confirm_email_before_auth {
            Ok(AuthTokens {
                access_token: String::new(),
                refresh_token: String::new(),
                authenticated: false,
            })
        } else {
            self.tokens_for(&user)
        }
    }

    /// Confirm the registration/verification code and log the user in.
    pub async fn confirm_email(&self, email: &str, code: &str) -> AppResult<AuthTokens> {
        let email = normalize_email(email)?;
        let user = self
            .repo
            .get_by_email(&email)
            .await?
            .ok_or(AppError::EmailNotRegistered)?;
        self.consume_code(&email, code, CONFIRM_EMAIL).await?;
        self.repo.set_email_confirmed(user.id).await?;
        // reload to reflect confirmed status
        let user = self.repo.get_by_id(user.id).await?.unwrap_or(user);
        self.tokens_for(&user)
    }

    pub async fn resend_confirmation(&self, email: &str) -> AppResult<bool> {
        let email = normalize_email(email)?;
        if let Some(user) = self.repo.get_by_email(&email).await? {
            self.send_code(&email, CONFIRM_EMAIL, user.language.as_deref())
                .await?;
        }
        Ok(true)
    }

    pub async fn login(&self, email: &str, password: &str) -> AppResult<AuthTokens> {
        let email = normalize_email(email)?;
        let user = self
            .repo
            .get_by_email(&email)
            .await?
            .ok_or(AppError::WrongCredentials)?;

        let hash = user.password_hash.as_deref().ok_or(AppError::WrongCredentials)?;
        if !verify_password(password, hash) {
            return Err(AppError::WrongCredentials);
        }
        if !user.email_confirmed {
            // resend so the user can complete verification
            self.send_code(&email, CONFIRM_EMAIL, user.language.as_deref())
                .await?;
            return Err(AppError::EmailNotConfirmed);
        }
        self.tokens_for(&user)
    }

    pub async fn refresh(&self, refresh_token: &str) -> AppResult<AuthTokens> {
        let claims = self.jwt.decode(refresh_token, TokenType::Refresh)?;
        let id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::WrongToken)?;
        let user = self.repo.get_by_id(id).await?.ok_or(AppError::WrongToken)?;
        if user.email != claims.email {
            return Err(AppError::WrongToken);
        }
        self.tokens_for(&user)
    }

    // ---- password reset ----

    /// Always returns true (does not leak whether the email exists).
    pub async fn request_password_reset(&self, email: &str) -> AppResult<bool> {
        let email = normalize_email(email)?;
        if let Some(user) = self.repo.get_by_email(&email).await? {
            self.send_code(&email, RESET_PASSWORD, user.language.as_deref())
                .await?;
        }
        Ok(true)
    }

    pub async fn confirm_password_reset(
        &self,
        email: &str,
        code: &str,
        new_password: &str,
    ) -> AppResult<AuthTokens> {
        let email = normalize_email(email)?;
        validate_password(new_password)?;
        let user = self
            .repo
            .get_by_email(&email)
            .await?
            .ok_or(AppError::EmailNotRegistered)?;
        self.consume_code(&email, code, RESET_PASSWORD).await?;
        self.repo
            .update_password(user.id, &hash_password(new_password)?)
            .await?;
        // Proving control of the mailbox also confirms the email.
        if !user.email_confirmed {
            self.repo.set_email_confirmed(user.id).await?;
        }
        let user = self.repo.get_by_id(user.id).await?.unwrap_or(user);
        self.tokens_for(&user)
    }

    // ---- firebase ----

    /// Log in or register through Firebase. Firebase is used only to validate
    /// the token and obtain a (verified) email; the user is then looked up in
    /// our own database by that email. Firebase UIDs are never used or stored.
    /// If Firebase reports the email as unverified we send our own confirmation
    /// code and withhold tokens.
    pub async fn firebase_auth(&self, id_token: &str) -> AppResult<AuthTokens> {
        let fb = self.firebase.verify(id_token).await?;

        let email = fb
            .email
            .as_deref()
            .ok_or_else(|| AppError::Firebase("firebase account has no email".into()))?;
        let email = normalize_email(email)?;

        let user = match self.repo.get_by_email(&email).await? {
            Some(user) => {
                if fb.email_verified && !user.email_confirmed {
                    self.repo.set_email_confirmed(user.id).await?;
                    self.repo.get_by_id(user.id).await?.unwrap_or(user)
                } else {
                    user
                }
            }
            None => {
                self.repo
                    .insert(NewUser {
                        email: email.clone(),
                        password_hash: None,
                        permissions: permissions_to_strings(&Permission::defaults()),
                        language: None,
                        email_confirmed: fb.email_verified,
                    })
                    .await?
            }
        };

        if !user.email_confirmed {
            self.send_code(&user.email, CONFIRM_EMAIL, user.language.as_deref())
                .await?;
            return Err(AppError::EmailNotConfirmed);
        }

        self.tokens_for(&user)
    }

    // ---- user listing / settings ----

    pub async fn list_users(&self, limit: i64, offset: i64) -> AppResult<UserConnection> {
        let limit = limit.clamp(1, MAX_PAGE_SIZE);
        let offset = offset.max(0);
        let rows = self.repo.list(limit, offset).await?;
        let total = self.repo.count().await?;
        let has_next = offset + (rows.len() as i64) < total;
        Ok(UserConnection {
            nodes: rows.into_iter().map(User::new).collect(),
            total_count: total,
            has_next_page: has_next,
        })
    }

    pub async fn set_email_notifications(&self, user_id: &str, enabled: bool) -> AppResult<bool> {
        let id = Uuid::parse_str(user_id).map_err(|_| AppError::UserNotFound)?;
        self.repo.set_notifications_email(id, enabled).await?;
        Ok(enabled)
    }

    // ---- helpers ----

    fn tokens_for(&self, user: &UserRow) -> AppResult<AuthTokens> {
        let perms = user.permissions();
        let pair = self
            .jwt
            .issue_pair(&user.id.to_string(), &user.email, &perms)?;
        Ok(AuthTokens {
            access_token: pair.access_token,
            refresh_token: pair.refresh_token,
            authenticated: true,
        })
    }

    async fn send_code(
        &self,
        email: &str,
        purpose: &str,
        language: Option<&str>,
    ) -> AppResult<()> {
        let code = generate_code();
        let expires_at = Utc::now() + Duration::minutes(CODE_TTL_MINUTES);
        self.repo
            .upsert_code(email, &code, purpose, expires_at)
            .await?;

        let lang = self.localizer.resolve(language);
        let content = if purpose == RESET_PASSWORD {
            self.localizer.reset_password(&lang, &code)
        } else {
            self.localizer.confirm_email(&lang, &code)
        };

        // One-time codes ignore the user's email opt-out on purpose.
        self.email
            .enqueue(NewEmail {
                to: email.to_string(),
                subject: content.subject,
                body_html: content.body_html,
                body_text: content.body_text,
            })
            .await?;
        tracing::debug!(%email, %purpose, code = %code, "confirmation code issued");
        // Dev convenience: local SMTP is usually unavailable, so surface the
        // one-time code at info level in debug builds. Release builds stay quiet.
        #[cfg(debug_assertions)]
        tracing::info!(%email, %purpose, %code, "🔑 one-time code (email not delivered locally)");
        Ok(())
    }

    async fn consume_code(&self, email: &str, code: &str, purpose: &str) -> AppResult<()> {
        let row = self
            .repo
            .get_code(email, purpose)
            .await?
            .ok_or(AppError::CodeNotFound)?;
        if row.expires_at < Utc::now() {
            self.repo.delete_code(row.id).await?;
            return Err(AppError::CodeExpired);
        }
        if row.attempts >= MAX_CODE_ATTEMPTS {
            return Err(AppError::TooManyTries);
        }
        if row.code != code {
            self.repo.increment_code_attempts(row.id).await?;
            return Err(AppError::WrongCode);
        }
        self.repo.delete_code(row.id).await?;
        Ok(())
    }
}

fn normalize_email(email: &str) -> AppResult<String> {
    let email = email.trim().to_lowercase();
    if email.len() < 3 || !email.contains('@') {
        return Err(AppError::Validation("invalid email address".into()));
    }
    Ok(email)
}

fn validate_password(password: &str) -> AppResult<()> {
    if password.len() < 8 {
        return Err(AppError::Validation(
            "password must be at least 8 characters".into(),
        ));
    }
    Ok(())
}
