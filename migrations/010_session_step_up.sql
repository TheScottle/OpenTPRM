-- Persist WebAuthn step-up timestamp for cookie session round-trips (SEC-AN-003).
ALTER TABLE sessions ADD COLUMN step_up_at TEXT NOT NULL DEFAULT '';
