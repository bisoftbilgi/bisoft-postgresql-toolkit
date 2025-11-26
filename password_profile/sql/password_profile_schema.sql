-- password_profile core schema objects
-- Executed automatically during CREATE EXTENSION via extension_sql_file!

CREATE SCHEMA IF NOT EXISTS password_profile;

CREATE TABLE IF NOT EXISTS password_profile.login_attempts (
    username TEXT PRIMARY KEY,
    fail_count INT DEFAULT 0,
    last_fail TIMESTAMPTZ DEFAULT now(),
    lockout_until TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS password_profile.password_history (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    changed_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_pwd_history_user
    ON password_profile.password_history (username, changed_at DESC);

CREATE TABLE IF NOT EXISTS password_profile.password_expiry (
    username TEXT PRIMARY KEY,
    last_changed TIMESTAMPTZ DEFAULT now(),
    must_change_by TIMESTAMPTZ,
    grace_logins_remaining INT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS password_profile.blacklist (
    password TEXT PRIMARY KEY,
    added_at TIMESTAMPTZ DEFAULT now(),
    reason TEXT
);
