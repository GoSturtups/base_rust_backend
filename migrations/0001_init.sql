-- Initial schema for the base backend.
-- Requires PostgreSQL 13+ (uses the built-in gen_random_uuid()).

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                TEXT NOT NULL UNIQUE,
    password_hash        TEXT,
    email_confirmed      BOOLEAN NOT NULL DEFAULT false,
    permissions          TEXT[] NOT NULL DEFAULT '{}',
    firebase_uid         TEXT UNIQUE,
    language             TEXT,
    notifications_email  BOOLEAN NOT NULL DEFAULT true,
    blocked              BOOLEAN NOT NULL DEFAULT false,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One-time email confirmation / password-reset codes.
CREATE TABLE email_codes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email       TEXT NOT NULL,
    code        TEXT NOT NULL,
    purpose     TEXT NOT NULL,
    attempts    INT NOT NULL DEFAULT 0,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (email, purpose)
);

-- Outbound email queue processed by the email worker.
CREATE TABLE email_queue (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    to_address  TEXT NOT NULL,
    subject     TEXT NOT NULL,
    body_html   TEXT NOT NULL,
    body_text   TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'planned',
    attempts    INT NOT NULL DEFAULT 0,
    last_error  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX email_queue_status_idx ON email_queue (status, created_at);

-- Client devices and their push registration tokens.
CREATE TABLE devices (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_id     TEXT NOT NULL,
    push_token    TEXT,
    push_enabled  BOOLEAN NOT NULL DEFAULT true,
    platform      TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, device_id)
);

-- Notification queue processed by the notification worker.
CREATE TABLE notifications (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    body        TEXT NOT NULL,
    link        TEXT,
    status      TEXT NOT NULL DEFAULT 'planned',
    attempts    INT NOT NULL DEFAULT 0,
    last_error  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX notifications_status_idx ON notifications (status, created_at);
