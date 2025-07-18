-- Şema oluşturuluyor
CREATE SCHEMA IF NOT EXISTS password_check AUTHORIZATION CURRENT_USER;

-- Şifre geçmişi tablosu
CREATE TABLE IF NOT EXISTS password_check.history (
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    change_date TIMESTAMPTZ DEFAULT now()
);

-- Blacklist tablosu
CREATE TABLE IF NOT EXISTS password_check.blacklist (
    word TEXT PRIMARY KEY
);

-- Başarısız giriş denemeleri tablosu
CREATE TABLE IF NOT EXISTS password_check.login_failures (
    username TEXT PRIMARY KEY,
    fail_count INT NOT NULL,
    last_fail TIMESTAMPTZ NOT NULL
);

-- Yetkilendirme
GRANT USAGE ON SCHEMA password_check TO PUBLIC;

-- Şifre geçmişi sadece yetkili kullanıcıya yazma izni verilsin, herkes okuyabilsin:
GRANT SELECT ON password_check.history TO PUBLIC;
GRANT INSERT, DELETE ON password_check.history TO postgres;

-- Blacklist sadece okunabilir olmalı:
GRANT SELECT ON password_check.blacklist TO PUBLIC;

-- login_failures tablosu: sadece extension erişsin
GRANT SELECT, INSERT, UPDATE, DELETE ON password_check.login_failures TO postgres;

