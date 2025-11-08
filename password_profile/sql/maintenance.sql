-- password_profile_pure Extension - Database Maintenance Operations
-- 
-- Run periodically (weekly/monthly) in production environments
-- Usage: psql -U postgres -d yourdb -f sql/maintenance.sql
--
-- These operations cannot run during CREATE EXTENSION due to transaction limitations

-- Analyze tables for query planner optimization
ANALYZE password_profile.password_history;
ANALYZE password_profile.login_attempts; 
ANALYZE password_profile.password_expiry;
ANALYZE password_profile.blacklist;

-- Vacuum to reclaim space and update statistics  
VACUUM ANALYZE password_profile.password_history;
VACUUM ANALYZE password_profile.login_attempts;
VACUUM ANALYZE password_profile.password_expiry;

-- Cleanup old password history (optional - adjust retention as needed)
-- DELETE FROM password_profile.password_history 
-- WHERE changed_at < NOW() - INTERVAL '2 years';

-- Cleanup expired lockouts (optional maintenance)
-- UPDATE password_profile.login_attempts 
-- SET lockout_until = NULL, fail_count = 0 
-- WHERE lockout_until IS NOT NULL AND lockout_until < NOW();

\echo 'password_profile_pure: Database maintenance completed'
\echo 'Tables analyzed and vacuumed for optimal performance'