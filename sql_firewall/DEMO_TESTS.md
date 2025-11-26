# SQL FIREWALL - DEMO REHBERİ

Bu rehber SQL Firewall'un özelliklerini PostgreSQL 16 üzerinde göstermeyi amaçlar.

## ⚠️ ÖNEMLİ UYARILAR

1.  **Transaction Block Hatası:** `ALTER SYSTEM` komutları transaction bloğu içinde çalıştırılamaz. `psql -c "komut1; komut2"` şeklinde zincirleme komut kullanırken veya DBeaver gibi araçlarda dikkatli olun. Komutları tek tek çalıştırın.
2.  **Temizlik:** Her testten sonra, o testte açtığınız özellikleri kapatmayı (Cleanup adımlarını uygulamayı) unutmayın. Aksi takdirde sonraki testler başarısız olabilir.
3.  **Reload:** `ALTER SYSTEM` ile yapılan değişikliklerin aktif olması için mutlaka `SELECT pg_reload_conf();` çalıştırılmalıdır.

## Hazırlık

```bash
# Demo ortamını hazırlayın
psql -U postgres -h localhost <<'SQL'
DROP DATABASE IF EXISTS demo_db;
CREATE DATABASE demo_db;
\c demo_db

-- Extension yükle
CREATE EXTENSION IF NOT EXISTS sql_firewall_rs;

-- Test kullanıcıları
CREATE ROLE test_user1 WITH LOGIN PASSWORD 'test123';
CREATE ROLE test_user2 WITH LOGIN PASSWORD 'test456';
GRANT ALL ON SCHEMA public TO test_user1, test_user2;

CREATE TABLE demo_table(id serial PRIMARY KEY, data text);
INSERT INTO demo_table(data) VALUES ('row1'), ('row2');
GRANT SELECT ON demo_table TO test_user1, test_user2;

SELECT 'Demo ortamı hazır!' AS status;
SQL
```

> **Not:** Background worker `sql_firewall.approval_worker_database` ayarı ile belirtilen veritabanına bağlanır. Worker durumunu kontrol etmek için: `SELECT sql_firewall_approval_worker_status();`

---

## TEST 1: ENFORCE MODE - Komut Bazlı Onay

```bash
echo "=== TEST 1: ENFORCE MODE ==="
psql -U postgres -h localhost -d demo_db <<'SQL'
ALTER SYSTEM SET sql_firewall.mode = 'enforce';
SELECT pg_reload_conf();

-- test_user1 için SELECT komutunu manuel onayla
INSERT INTO public.sql_firewall_command_approvals(role_name, command_type, is_approved)
VALUES ('test_user1', 'SELECT', true)
ON CONFLICT (role_name, command_type) DO UPDATE SET is_approved = EXCLUDED.is_approved;
SQL

# Onaylı komut (SELECT) çalışır
psql -U test_user1 -h localhost -d demo_db -c "SELECT 1 AS test;"

# INSERT komutu onaysız olduğu için bloklanır
psql -U test_user1 -h localhost -d demo_db -c "INSERT INTO demo_table(data) VALUES ('x');" 2>&1 | grep -i "error"
```

**Beklenen:**
- `SELECT 1` → Başarılı
- `INSERT` → ERROR: sql_firewall: No rule found

---

## TEST 2: LEARN MODE - Pending Approval Kuyruğu

```bash
echo "=== TEST 2: LEARN MODE ==="
psql -U postgres -h localhost -d demo_db <<'SQL'
ALTER SYSTEM SET sql_firewall.mode = 'learn';
SELECT pg_reload_conf();
SQL

# test_user1 yeni bir UPDATE komutu çalıştırır → bloklanır ve pending'e düşer
psql -U test_user1 -h localhost -d demo_db -c "UPDATE demo_table SET data = 'learn' WHERE id = 2;" 2>&1

# Pending kaydı tabloya yazıldı mı?
psql -U postgres -h localhost -d demo_db <<'SQL'
SELECT role_name, command_type, is_approved, created_at
FROM public.sql_firewall_command_approvals
WHERE role_name = 'test_user1'
ORDER BY created_at DESC
LIMIT 3;
SQL
```

**Beklenen:**
- UPDATE komutu: ERROR (pending)
- Tabloda `is_approved = false` kaydı görünür

---

## TEST 3: PERMISSIVE MODE - Loglayıp İzin Ver

```bash
echo "=== TEST 3: PERMISSIVE MODE ==="
psql -U postgres -h localhost -d demo_db <<'SQL'
ALTER SYSTEM SET sql_firewall.mode = 'permissive';
SELECT pg_reload_conf();
SQL

# DELETE komutu çalışır + warning verir + otomatik onaylanır
psql -U test_user1 -h localhost -d demo_db -c "DELETE FROM demo_table WHERE id = 1;" 2>&1

# Activity log'da kayıt arayın
psql -U postgres -h localhost -d demo_db <<'SQL'
SELECT role_name, command_type, action, reason, log_time
FROM public.sql_firewall_activity_log
ORDER BY log_time DESC LIMIT 5;
SQL

# Komutun otomatik onaylandığını kontrol et
psql -U postgres -h localhost -d demo_db <<'SQL'
SELECT role_name, command_type, is_approved 
FROM public.sql_firewall_command_approvals 
WHERE role_name = 'test_user1' AND command_type = 'DELETE';
SQL
```

**Beklenen:**
- DELETE çalışır + WARNING
- Activity log'da kayıt oluşur
- DELETE komutu `is_approved = true` olarak kaydedilir

---

## TEST 4: KEYWORD BLACKLIST

```bash
echo "=== TEST 4: KEYWORD BLACKLIST ==="
psql -U postgres -h localhost -d demo_db <<'SQL'
ALTER SYSTEM SET sql_firewall.mode = 'enforce';
ALTER SYSTEM SET sql_firewall.enable_keyword_scan = on;
ALTER SYSTEM SET sql_firewall.blacklisted_keywords = 'drop,truncate';
SELECT pg_reload_conf();
SQL

# DROP komutu bloklanır
psql -U test_user1 -h localhost -d demo_db -c "DROP TABLE demo_table;" 2>&1
```

**Beklenen:**
- ERROR: sql_firewall: Query blocked by security regex pattern.

**Cleanup:**
```sql
ALTER SYSTEM SET sql_firewall.enable_keyword_scan = off;
SELECT pg_reload_conf();
```

---

## TEST 5: REGEX RULES

```bash
echo "=== TEST 5: REGEX RULES ==="
psql -U postgres -h localhost -d demo_db <<'SQL'
-- SQL injection regex pattern ekle
INSERT INTO public.sql_firewall_regex_rules(pattern, description)
VALUES ('(?i)or\s+1\s*=\s*1', 'Block tautology injection')
ON CONFLICT (pattern) DO NOTHING;

-- Regex scanning'i aktif et
ALTER SYSTEM SET sql_firewall.enable_regex_scan = on;
SELECT pg_reload_conf();

-- SELECT komutunu onayla
INSERT INTO public.sql_firewall_command_approvals(role_name, command_type, is_approved)
VALUES ('test_user1', 'SELECT', true)
ON CONFLICT (role_name, command_type) DO UPDATE SET is_approved = true;
SQL

# SQL injection denemesi - OR 1=1 pattern'i bloklanır
psql -U test_user1 -h localhost -d demo_db -c "SELECT * FROM demo_table WHERE data = 'x' OR 1=1;" 2>&1
```

**Beklenen:**
- ERROR: sql_firewall: Query blocked by security regex pattern.

**Cleanup:**
```sql
ALTER SYSTEM SET sql_firewall.enable_regex_scan = off;
SELECT pg_reload_conf();
```

---

## TEST 6: IP BLOCKING (GUC)

```bash
echo "=== TEST 6: IP BLOCKING ==="
psql -U postgres -h localhost -d demo_db <<'SQL'
ALTER SYSTEM SET sql_firewall.enable_ip_blocking = on;
ALTER SYSTEM SET sql_firewall.blocked_ips = '203.0.113.10,198.51.100.20,::1';
SELECT pg_reload_conf();
SQL

# IPv6 localhost (::1) bloklandığı için hata alınır
psql -U test_user1 -h localhost -d demo_db -c "SELECT 'test';" 2>&1

# IPv4 (127.0.0.1) bloklu değil, çalışır
psql -U test_user1 -h 127.0.0.1 -d demo_db -c "SELECT 'IPv4 test';" 2>&1

# 127.0.0.1'i de bloklayalım
sudo -u postgres psql <<'SQL'
ALTER SYSTEM SET sql_firewall.blocked_ips = '203.0.113.10,198.51.100.20,::1,127.0.0.1';
SELECT pg_reload_conf();
SQL

# Şimdi IPv4 de bloklanır
psql -U test_user1 -h 127.0.0.1 -d demo_db -c "SELECT 'blocked';" 2>&1
```

**Beklenen:**
- ::1 bloklu: ERROR: Connection from blocked IP address
- 127.0.0.1 ilk önce çalışır, sonra bloklanır

**Test sonrası blokları temizle:**
```bash
sudo -u postgres psql <<'SQL'
ALTER SYSTEM SET sql_firewall.blocked_ips = '203.0.113.10,198.51.100.20';
ALTER SYSTEM SET sql_firewall.enable_ip_blocking = off;
SELECT pg_reload_conf();
SQL
```

---

## TEST 7: APPLICATION BLOCKING (GUC)

```bash
echo "=== TEST 7: APPLICATION BLOCKING ==="
psql -U postgres -h localhost -d demo_db <<'SQL'
ALTER SYSTEM SET sql_firewall.enable_application_blocking = on;
ALTER SYSTEM SET sql_firewall.blocked_applications = 'hacktool,sqlmap';
SELECT pg_reload_conf();
SQL

# Normal psql çalışır
PGAPPNAME=psql psql -U test_user1 -h localhost -d demo_db -c "SELECT 'normal app';" 2>&1

# hacktool bloklanır
PGAPPNAME=hacktool psql -U test_user1 -h localhost -d demo_db -c "SELECT 'hacker';" 2>&1

# sqlmap bloklanır
PGAPPNAME=sqlmap psql -U test_user1 -h localhost -d demo_db -c "SELECT 'injection';" 2>&1
```

**Beklenen:**
- psql: Çalışır
- hacktool: ERROR: Connections from application 'hacktool' are not allowed
- sqlmap: ERROR: Connections from application 'sqlmap' are not allowed

**Cleanup:**
```sql
ALTER SYSTEM SET sql_firewall.enable_application_blocking = off;
SELECT pg_reload_conf();
```

---

## TEST 8: RATE LIMITING

```bash
echo "=== TEST 8: RATE LIMITING ==="
psql -U postgres -h localhost -d demo_db <<'SQL'
ALTER SYSTEM SET sql_firewall.enable_rate_limiting = on;
ALTER SYSTEM SET sql_firewall.rate_limit_count = 3;
ALTER SYSTEM SET sql_firewall.rate_limit_seconds = 5;
SELECT pg_reload_conf();
SQL

# 6 sorgu gönder - ilk 3'ü geçer, sonraki 3'ü bloklanır
for i in {1..6}; do
  echo "Query $i:"
  psql -U test_user1 -h localhost -d demo_db -c "SELECT $i AS query_num;" 2>&1 | head -2
  sleep 0.5
done
```

**Beklenen:**
- Query 1-3: Başarılı
- Query 4-6: ERROR: Rate limit exceeded

**Cleanup:**
```sql
ALTER SYSTEM SET sql_firewall.enable_rate_limiting = off;
SELECT pg_reload_conf();
```

---

## TEST 9: QUIET HOURS

```bash
echo "=== TEST 9: QUIET HOURS ==="

# Şu anki saati öğren
CURRENT_TIME=$(sudo -u postgres psql -t -c "SELECT to_char(now(), 'HH24:MI');")
echo "Şu anki saat: $CURRENT_TIME"

psql -U postgres -h localhost -d demo_db <<'SQL'
ALTER SYSTEM SET sql_firewall.enable_quiet_hours = on;
-- Şu anki dakikayı quiet hours'a al (örnek: 13:24-13:26)
ALTER SYSTEM SET sql_firewall.quiet_hours_start = '13:24';
ALTER SYSTEM SET sql_firewall.quiet_hours_end = '13:26';
SELECT pg_reload_conf();
SQL

# Quiet hours içinde sorgu çalıştır
psql -U test_user1 -h localhost -d demo_db -c "SELECT now();" 2>&1

# Test sonrası quiet hours'u kapat
sudo -u postgres psql <<'SQL'
ALTER SYSTEM SET sql_firewall.enable_quiet_hours = off;
SELECT pg_reload_conf();
SQL
```

**Beklenen (quiet hours içindeyse):**
- WARNING: Blocked during quiet hours
- ERROR: sql_firewall: Blocked during quiet hours

**Not:** Quiet hours dışındaysanız start/end saatlerini şu anki dakikaya göre ayarlayın.

---

## TEST 10: ROLE-IP BINDING

```bash
echo "=== TEST 10: ROLE-IP BINDING ==="
psql -U postgres -h localhost -d demo_db <<'SQL'
ALTER SYSTEM SET sql_firewall.enable_role_ip_binding = on;
ALTER SYSTEM SET sql_firewall.role_ip_bindings = 'test_user2@127.0.0.1,test_user2@::1';

-- test_user2 için SELECT komutunu onayla
INSERT INTO public.sql_firewall_command_approvals(role_name, command_type, is_approved)
VALUES ('test_user2', 'SELECT', true)
ON CONFLICT (role_name, command_type) DO UPDATE SET is_approved = true;
SELECT pg_reload_conf();
SQL

# İzin verilen IP'den (localhost) bağlanır
psql -U test_user2 -h localhost -d demo_db -c "SELECT 'allowed from localhost' AS result;" 2>&1

# İzin verilen başka IP (IPv4)
psql -U test_user2 -h 127.0.0.1 -d demo_db -c "SELECT 'allowed from 127.0.0.1' AS result;" 2>&1
```

**Beklenen:**
- localhost (::1): Başarılı
- 127.0.0.1: Başarılı
- Başka IP'den bağlanırsa: ERROR

**Cleanup:**
```sql
ALTER SYSTEM SET sql_firewall.enable_role_ip_binding = off;
SELECT pg_reload_conf();
```

---

## TEST 11: SUPERUSER BYPASS

```bash
echo "=== TEST 11: SUPERUSER BYPASS ==="
psql -U postgres -h localhost -d demo_db <<'SQL'
-- Superuser bypass zaten açık (default on)
SHOW sql_firewall.allow_superuser_auth_bypass;

-- postgres kullanıcısı Enforce mode'da bile tüm komutları çalıştırabilir
SELECT 'superuser bypass test' AS status;
DROP TABLE IF EXISTS firewall_bypass_demo;
CREATE TABLE firewall_bypass_demo(id int);
INSERT INTO firewall_bypass_demo VALUES (1), (2);
SELECT * FROM firewall_bypass_demo;
DROP TABLE firewall_bypass_demo;

SELECT 'Tüm komutlar başarılı - superuser bypass çalışıyor!' AS result;
SQL
```

**Beklenen:**
- Tüm komutlar başarıyla çalışır

**Not:** Superuser bypass'i kapatmak için:
```sql
ALTER SYSTEM SET sql_firewall.allow_superuser_auth_bypass = off;
SELECT pg_reload_conf();
```

---

## TEST 12: BACKGROUND WORKER TAKİBİ

```bash
echo "=== TEST 12: BACKGROUND WORKER ==="
# Worker'ın doğru DB'ye yazdığını doğrula
# NOT: Yeni versiyonda worker varsayılan olarak 'postgres' DB'sinde çalışır ve dblink kullanır.
# Bu ayarı değiştirmek zorunlu değildir, ancak test etmek isterseniz:
psql -U postgres -h localhost <<'SQL'
ALTER SYSTEM SET sql_firewall.approval_worker_database = 'demo_db';
SQL

# ÖNEMLİ: approval_worker_database Postmaster GUC'dur, PostgreSQL restart gerekli!
sudo -u postgres pg_ctl restart -D /var/lib/pgsql/16/data -m fast

# Learn mode'a al
sudo -u postgres psql -d demo_db <<'SQL'
ALTER SYSTEM SET sql_firewall.mode = 'learn';
SELECT pg_reload_conf();
SQL

# Onaysız komut çalıştır - worker tabloya yazmalı
psql -U test_user1 -h localhost -d demo_db -c "CREATE TABLE worker_test(id int);" 2>&1

# Worker'ın yazdığı kaydı kontrol et
sudo -u postgres psql -d demo_db <<'SQL'
SELECT role_name, command_type, is_approved, created_at
FROM public.sql_firewall_command_approvals
WHERE role_name = 'test_user1'
ORDER BY created_at DESC
LIMIT 5;
SQL

# Worker loglarını kontrol et
sudo tail -20 /var/lib/pgsql/16/data/log/postgresql-*.log | grep -i "sql_firewall.*worker\|approval"
```

**Beklenen:**
- CREATE komutu bloklanır ve pending'e düşer
- `sql_firewall_command_approvals` tablosunda `is_approved = false` kaydı görünür
- PostgreSQL log'unda worker ile ilgili mesajlar görünür

---

## Temizlik

```bash
echo "=== CLEANUP ==="
psql -U postgres -h localhost <<'SQL'
-- Tüm firewall ayarlarını sıfırla
ALTER SYSTEM SET sql_firewall.mode = 'enforce';
ALTER SYSTEM SET sql_firewall.enable_ip_blocking = off;
ALTER SYSTEM SET sql_firewall.enable_application_blocking = off;
ALTER SYSTEM SET sql_firewall.enable_rate_limiting = off;
ALTER SYSTEM SET sql_firewall.enable_quiet_hours = off;
ALTER SYSTEM SET sql_firewall.enable_role_ip_binding = off;
ALTER SYSTEM SET sql_firewall.blocked_ips = '';
ALTER SYSTEM SET sql_firewall.blocked_applications = '';
ALTER SYSTEM SET sql_firewall.role_ip_bindings = '';
SELECT pg_reload_conf();

-- Test verilerini temizle
\c demo_db
TRUNCATE public.sql_firewall_activity_log;
TRUNCATE public.sql_firewall_command_approvals CASCADE;
TRUNCATE public.sql_firewall_query_fingerprints;
-- Regex rules'u varsayılana döndür (opsiyonel)
DELETE FROM public.sql_firewall_regex_rules WHERE pattern NOT IN ('(or|--|#)\s+\d+\s*=\s*\d+');

DROP TABLE IF EXISTS demo_table;
DROP ROLE IF EXISTS test_user1;
DROP ROLE IF EXISTS test_user2;

SELECT sql_firewall_pause_approval_worker();
\c postgres
DROP DATABASE IF EXISTS demo_db;
SQL
```

---

## Özet

| # | Özellik | Restart Gerekli? | Test Durumu | Açıklama |
|---|---------|------------------|-------------|----------|
| 1 | Enforce Mode | ❌ Hayır | ✅ Başarılı | Komut bazlı approval zorunlu |
| 2 | Learn Mode | ❌ Hayır | ✅ Başarılı | Pending queue + worker yazımı |
| 3 | Permissive Mode | ❌ Hayır | ✅ Başarılı | İzin ver + activity log |
| 4 | Keyword Scan | ❌ Hayır | ✅ Başarılı | Regex rules ile DROP/TRUNCATE bloklanır |
| 5 | Regex Rules | ❌ Hayır | ✅ Başarılı | SQL injection (OR 1=1) bloklanır |
| 6 | IP Blocking | ❌ Hayır | ✅ Başarılı | IPv4/IPv6 bloklaması çalışır |
| 7 | Application Blocking | ❌ Hayır | ✅ Başarılı | hacktool, sqlmap bloklanır |
| 8 | Rate Limiting | ❌ Hayır | ✅ Başarılı | İlk N sorgu geçer, sonrakiler bloklanır |
| 9 | Quiet Hours | ❌ Hayır | ✅ Başarılı | Zaman bazlı blok çalışır |
| 10 | Role-IP Binding | ❌ Hayır | ✅ Başarılı | Belirtilen IP'lerden bağlantı izni |
| 11 | Superuser Bypass | ❌ Hayır | ✅ Başarılı | Superuser tüm kuralları bypass eder |
| 12 | Background Worker | ✅ Evet | ✅ Başarılı | Pending approvals tabloya yazılır |

**ÖNEMLİ NOTLAR:**

1. **Reload vs Restart:** Çoğu GUC parametresi için `SELECT pg_reload_conf()` yeterlidir.
2. **Background Worker:** `sql_firewall.approval_worker_database` değişikliği restart gerektirir.
3. **Regex Rules:** Tabloya ekleme anında etki eder.

**Reload Komutu:**
```sql
SELECT pg_reload_conf();
```

**Test Sonucu: 12/12 Özellik Başarıyla Test Edildi!** 🎉
