-- Create dedicated schema for the extension
CREATE SCHEMA IF NOT EXISTS password_profile AUTHORIZATION CURRENT_USER;

-- Table to store password history with metadata
CREATE TABLE IF NOT EXISTS password_profile.history (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    change_date TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Table to store blacklisted (forbidden/commonly used) passwords
CREATE TABLE IF NOT EXISTS password_profile.blacklist (
    word TEXT PRIMARY KEY
);

-- Restrict general access
GRANT USAGE ON SCHEMA password_profile TO PUBLIC;

-- For security: Revoke everything from PUBLIC on the history table
REVOKE ALL ON password_profile.history FROM PUBLIC;

-- Optionally, allow only SELECT to PUBLIC on blacklist (read-only access)
REVOKE ALL ON password_profile.blacklist FROM PUBLIC;
GRANT SELECT ON password_profile.blacklist TO PUBLIC;

-- Optional: Comment on objects for better \dd support
COMMENT ON SCHEMA password_profile IS 'Schema for password policy enforcement';
COMMENT ON TABLE password_profile.history IS 'Stores password hashes and change timestamps per user';
COMMENT ON TABLE password_profile.blacklist IS 'Stores disallowed password words (blacklist)';

