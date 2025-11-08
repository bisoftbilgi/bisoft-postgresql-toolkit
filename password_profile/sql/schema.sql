-- password_profile_pure Extension - Post-Installation Maintenance
-- 
-- IMPORTANT: This file is NOT automatically included during CREATE EXTENSION.
-- Tables and critical indexes are created by sql/password_profile_pure--0.0.0.sql
-- during CREATE EXTENSION.
--
-- This file provides OPTIONAL maintenance operations for production environments.
-- Run MANUALLY after CREATE EXTENSION: psql -U postgres -d yourdb -f sql/schema.sql
--
-- NOTE: VACUUM/ANALYZE/REINDEX commands cannot run during CREATE EXTENSION 
-- (single transaction limitation), so they are provided here for manual execution.

-- Additional composite indexes (beyond those already created by extension)
-- These are optional performance optimizations for high-traffic environments

-- Enhanced composite index for complex expiration queries  
CREATE INDEX IF NOT EXISTS idx_password_expiry_complex 
ON password_profile.password_expiry(must_change_by, grace_logins_remaining) 
WHERE must_change_by IS NOT NULL;

-- Partial index for recent failed attempts (sliding window analysis)
CREATE INDEX IF NOT EXISTS idx_login_attempts_recent_fails 
ON password_profile.login_attempts(last_fail DESC, fail_count) 
WHERE last_fail > NOW() - INTERVAL '1 hour';

\echo 'password_profile_pure: Additional performance indexes created'
\echo 'For maintenance operations (VACUUM/ANALYZE), run: psql -f sql/maintenance.sql'
