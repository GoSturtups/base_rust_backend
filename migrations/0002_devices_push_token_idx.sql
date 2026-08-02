-- Index the token used by NotificationRepository::clear_token, which runs
-- `UPDATE devices SET push_token = NULL WHERE push_token = $1` every time FCM
-- rejects a token. Without an index this is a full scan of `devices`.
-- Partial index: the column is nullable and lookups are always for a concrete
-- non-NULL token, so NULL rows are excluded to keep the index small.
CREATE INDEX IF NOT EXISTS devices_push_token_idx
    ON devices (push_token)
    WHERE push_token IS NOT NULL;
