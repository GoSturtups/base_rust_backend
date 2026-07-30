//! Minimal, dependency-free localization.
//!
//! The client sends its language in the `Accept-Language` header on every
//! request; [`Localizer::resolve`] maps it onto a supported language (falling
//! back to the configured default). Feature modules ask the localizer for
//! ready-to-send, language-specific texts such as email templates.
//!
//! Translations live in code here for a self-contained boilerplate; swapping in
//! a file/DB-backed catalogue only requires changing this module.

use crate::config::I18nConfig;

#[derive(Debug, Clone)]
pub struct EmailContent {
    pub subject: String,
    pub title: String,
    pub body_html: String,
    pub body_text: String,
}

#[derive(Clone)]
pub struct Localizer {
    default_language: String,
    supported: Vec<String>,
}

impl Localizer {
    pub fn new(config: &I18nConfig) -> Self {
        Self {
            default_language: config.default_language.clone(),
            supported: config.supported.clone(),
        }
    }

    /// Normalize a requested language (e.g. `"ru-RU"`) to a supported code or
    /// the default.
    pub fn resolve(&self, requested: Option<&str>) -> String {
        let Some(req) = requested else {
            return self.default_language.clone();
        };
        let primary = req.split([',', '-', ';']).next().unwrap_or("").trim();
        if self
            .supported
            .iter()
            .any(|s| s.eq_ignore_ascii_case(primary))
        {
            primary.to_lowercase()
        } else {
            self.default_language.clone()
        }
    }

    pub fn default_language(&self) -> &str {
        &self.default_language
    }

    /// Confirmation-code email for registration / email verification.
    pub fn confirm_email(&self, lang: &str, code: &str) -> EmailContent {
        match self.resolve(Some(lang)).as_str() {
            "ru" => code_email(
                "Подтверждение электронной почты",
                "Подтвердите ваш email",
                "Ваш код подтверждения",
                code,
            ),
            "sr" => code_email(
                "Потврда е-поште",
                "Потврдите вашу е-пошту",
                "Ваш код за потврду",
                code,
            ),
            _ => code_email(
                "Confirm your email",
                "Confirm your email",
                "Your confirmation code",
                code,
            ),
        }
    }

    /// Password-reset code email.
    pub fn reset_password(&self, lang: &str, code: &str) -> EmailContent {
        match self.resolve(Some(lang)).as_str() {
            "ru" => code_email(
                "Сброс пароля",
                "Сброс пароля",
                "Код для сброса пароля",
                code,
            ),
            "sr" => code_email(
                "Ресетовање лозинке",
                "Ресетовање лозинке",
                "Код за ресетовање лозинке",
                code,
            ),
            _ => code_email(
                "Reset your password",
                "Reset your password",
                "Your password reset code",
                code,
            ),
        }
    }
}

fn code_email(subject: &str, title: &str, lead: &str, code: &str) -> EmailContent {
    EmailContent {
        subject: subject.to_string(),
        title: title.to_string(),
        body_text: format!("{lead}: {code}"),
        body_html: format!(
            "<h2>{title}</h2><p>{lead}:</p><p style=\"font-size:24px;font-weight:bold;letter-spacing:4px\">{code}</p>"
        ),
    }
}
