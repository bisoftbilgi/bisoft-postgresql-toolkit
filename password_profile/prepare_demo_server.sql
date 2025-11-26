-- PREPARE DEMO SERVER SCRIPT
-- Run this script to clean up the server before starting the demo.
-- Usage: sudo -u postgres psql -d postgres -f prepare_demo_server.sql

-- 1. Drop the extension (this will drop the tables: login_attempts, password_history, etc.)
DROP EXTENSION IF EXISTS password_profile CASCADE;

-- 2. Drop test roles used in the demo
DROP ROLE IF EXISTS alice;
DROP ROLE IF EXISTS bob;
DROP ROLE IF EXISTS charlie;
DROP ROLE IF EXISTS david;
DROP ROLE IF EXISTS short_pw;
DROP ROLE IF EXISTS john;
DROP ROLE IF EXISTS no_upper;
DROP ROLE IF EXISTS no_digit;
DROP ROLE IF EXISTS no_special;
DROP ROLE IF EXISTS history_user;
DROP ROLE IF EXISTS hacker1;
DROP ROLE IF EXISTS hacker2;
DROP ROLE IF EXISTS test_removed;

-- 3. Drop demo database if exists (optional, or just clean it)
DROP DATABASE IF EXISTS password_demo_db;

-- 4. Create fresh demo database
CREATE DATABASE password_demo_db;

\c password_demo_db

-- 5. Install extensions
CREATE EXTENSION IF NOT EXISTS password_profile;
-- CREATE EXTENSION IF NOT EXISTS sql_firewall_rs; -- If needed

-- 6. Create initial demo data/roles
CREATE ROLE alice WITH LOGIN PASSWORD 'SecurePass123!';
CREATE ROLE bob WITH LOGIN PASSWORD 'StrongPass456!';

CREATE TABLE company_data (id SERIAL PRIMARY KEY, data TEXT);
INSERT INTO company_data VALUES (1, 'Confidential Information');
GRANT SELECT ON company_data TO alice, bob;

SELECT 'Demo server prepared successfully!' as status;
