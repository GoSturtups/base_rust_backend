-- The admin user list pages with `ORDER BY created_at DESC LIMIT $1 OFFSET $2`
-- (UsersRepository::list). An index on created_at lets Postgres walk it (an
-- ascending btree is scanned backwards for DESC) instead of sorting the whole
-- table. Small/admin-only table, so this is a minor optimization.
CREATE INDEX IF NOT EXISTS users_created_at_idx ON users (created_at);
