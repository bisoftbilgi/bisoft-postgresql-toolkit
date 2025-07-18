-- Create a dedicated schema for the extension.
-- The user who runs CREATE EXTENSION will be the owner.
CREATE SCHEMA IF NOT EXISTS password_check AUTHORIZATION CURRENT_USER;

---
-- Table to store password history.
-- A primary key is added for better data integrity.
CREATE TABLE IF NOT EXISTS password_check.history (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    change_date TIMESTAMPTZ NOT NULL DEFAULT now()
);

---
-- Table to store a blacklist of common or forbidden passwords.
CREATE TABLE IF NOT EXISTS password_check.blacklist (
    word TEXT PRIMARY KEY
);

---
-- Set permissions for the schema and its objects.

-- Allow all roles to see the schema, but not necessarily its contents.
GRANT USAGE ON SCHEMA password_check TO PUBLIC;

-- IMPORTANT: Only the owner (the extension itself via the backend) should be
-- able to read and write to the password history.
-- DO NOT grant SELECT to PUBLIC on this table as it exposes password hashes.
-- The owner automatically has all privileges, so no further grants are needed
-- for the extension to function. We explicitly revoke public access for security.
REVOKE ALL ON password_check.history FROM PUBLIC;

-- The blacklist can be readable by everyone.
-- Only the owner should be able to modify the blacklist.
REVOKE ALL ON password_check.blacklist FROM PUBLIC;
GRANT SELECT ON password_check.blacklist TO PUBLIC;
