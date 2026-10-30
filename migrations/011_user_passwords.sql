-- Workforce password authentication (SEC-AN-002) + lockout fields.
ALTER TABLE users ADD COLUMN password_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN password_changed_at TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN last_login_at TEXT NOT NULL DEFAULT '';
