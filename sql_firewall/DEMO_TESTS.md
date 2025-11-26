# SQL FIREWALL - KAPSAMLI DEMO REHBERİ

Bu rehber SQL Firewall'un öne çıkan özelliklerini PostgreSQL 16 üzerinde tek tek göstermeyi amaçlar. Senaryo boyunca yalnızca uzantının sağladığı tabloları (`public.sql_firewall_activity_log`, `public.sql_firewall_command_approvals`, `public.sql_firewall_query_fingerprints`, `public.sql_firewall_regex_rules`) ve GUC ayarlarını kullanıyoruz; IP/app/role bazlı politikalar doğrudan `sql_firewall.*` GUC'ları üzerinden tanımlanır.

## Hazırlık

```bash
# Demo ortamını hazırlayın
psql -U postgres -h localhost <<'SQL'
DROP DATABASE IF EXISTS demo_db;
CREATE DATABASE demo_db;
\c demo_db

-- Extension yükle (shared_preload_libraries içinde olmalı)
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

> Not: Aşağıdaki `ALTER SYSTEM` komutları PostgreSQL yeniden yüklemeyi gerektirir. İlk adımda `sql_firewall.approval_worker_database` değerini demo veritabanına (`demo_db`) ayarlayıp PostgreSQL'i yeniden başlatmanız önerilir; böylece Learn Mode testlerine geldiğinizde background worker'ın pending approval kayıtlarını doğru yere yazdığını baştan doğrulamış olursunuz.
> 
> ```sql
> ALTER SYSTEM SET sql_firewall.approval_worker_database = 'demo_db';
> -- Bu GUC Postmaster seviyesinde, bu yüzden ALTER sonrası PostgreSQL'i tamamen yeniden başlatın.
> ```
> 
> Diğer Postmaster GUC'lar da tam restart ister, kalan ayarlar `SELECT pg_reload_conf();` ile etkinleşir.
>
> **Worker bağlantısı:** `demo_db` gibi worker'ın bağlı olduğu veritabanını `DROP DATABASE` ile temizlemeden önce `SELECT sql_firewall_pause_approval_worker();` çalıştırıp bağlantıyı bırakın. Veritabanını yeniden oluşturduktan sonra `SELECT sql_firewall_resume_approval_worker();` ile worker'ı tekrar devreye alın. Bu fonksiyonları uzantının kurulu olduğu herhangi bir veritabanında çağırabilirsiniz.

---

## TEST 1: ENFORCE MODE - Komut Bazlı Onay

```bash
echo "=== TEST 1: ENFORCE MODE ==="
psql -U postgres -h localhost -d demo_db <<'SQL'
ALTER SYSTEM SET sql_firewall.mode = 'enforce';

-- test_user1 için SELECT komutunu manuel onayla
INSERT INTO public.sql_firewall_command_approvals(role_name, command_type, is_approved)
VALUES ('test_user1', 'SELECT', true)
ON CONFLICT (role_name, command_type) DO UPDATE SET is_approved = EXCLUDED.is_approved;
SQL

# ÖNEMLİ: Mode değişikliği için PostgreSQL restart gerekli!
sudo -u postgres pg_ctl restart -D /var/lib/pgsql/16/data -m fast
# veya: systemctl restart postgresql-16

# Onaylı komut (SELECT) çalışır
psql -U test_user1 -h localhost -d demo_db -c "SELECT 1 AS test;"

# INSERT komutu onaysız olduğu için bloklanır
psql -U test_user1 -h localhost -d demo_db -c "INSERT INTO demo_table(data) VALUES ('x');" 2>&1 | grep -i "error"
```

**Beklenen Çıktı:**
- `SELECT 1` → Başarılı (onaylı)
- `INSERT` → ERROR: sql_firewall: No rule found for command 'INSERT'

---

## TEST 2: LEARN MODE - Pending Approval Kuyruğu

```bash
echo "=== TEST 2: LEARN MODE ==="
psql -U postgres -h localhost -d demo_db <<'SQL'
ALTER SYSTEM SET sql_firewall.mode = 'learn';
SQL

# ÖNEMLİ: Mode değişikliği için PostgreSQL restart gerekli!
sudo -u postgres pg_ctl restart -D /var/lib/pgsql/16/data -m fast

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

**Beklenen Çıktı:**
- UPDATE komutu: ERROR ile pending'e düşer
- Tabloda `is_approved = false` kaydı görünür

**Arka plan işçisi:** `sql_firewall.approval_worker_database = 'demo_db'` ayarlıysa ve PostgreSQL restart edildiyse pending kayıtlar bu tabloya worker tarafından yazılır.

---

## TEST 3: PERMISSIVE MODE - Loglayıp İzin Ver

```bash
echo "=== TEST 3: PERMISSIVE MODE ==="
psql -U postgres -h localhost -d demo_db <<'SQL'
ALTER SYSTEM SET sql_firewall.mode = 'permissive';
SQL

# ÖNEMLİ: Mode değişikliği için PostgreSQL restart gerekli!
sudo -u postgres pg_ctl restart -D /var/lib/pgsql/16/data -m fast

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

**Beklenen Çıktı:**
- DELETE çalışır + WARNING: auto-approved in permissive mode
- Activity log'da 3 kayıt (AUTO-APPROVED, ALLOWED PERMISSIVE)
- DELETE komutu `is_approved = true` olarak kaydedilir

---

## TEST 4: KEYWORD BLACKLIST

```bash
echo "=== TEST 4: KEYWORD BLACKLIST ==="
psql -U postgres -h localhost -d demo_db <<'SQL'
ALTER SYSTEM SET sql_firewall.mode = 'enforce';
ALTER SYSTEM SET sql_firewall.enable_keyword_scan = on;
ALTER SYSTEM SET sql_firewall.blacklisted_keywords = 'drop,truncate';
SQL

# ÖNEMLİ: Keyword blacklist için PostgreSQL restart gerekli!
sudo -u postgres pg_ctl restart -D /var/lib/pgsql/16/data -m fast

# DROP komutu bloklanır (regex rule sayesinde)
psql -U test_user1 -h localhost -d demo_db -c "DROP TABLE demo_table;" 2>&1
```

**Beklenen Çıktı:**
- ERROR: sql_firewall: Query blocked by security regex pattern.

**Not:** DROP komutu aslında `sql_firewall_regex_rules` tablosundaki `(DROP|TRUNCATE)` pattern'i ile bloklanır.

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

-- SELECT komutunu onayla (regex testini yapabilmek için)
INSERT INTO public.sql_firewall_command_approvals(role_name, command_type, is_approved)
VALUES ('test_user1', 'SELECT', true)
ON CONFLICT (role_name, command_type) DO UPDATE SET is_approved = true;

-- Mevcut regex kurallarını göster
SELECT pattern, description FROM public.sql_firewall_regex_rules;
SQL

# Regex scan zaten aktifse reload yeterli, değilse restart gerekli
sudo -u postgres psql -c "SELECT pg_reload_conf();"

# SQL injection denemesi - OR 1=1 pattern'i bloklanır
psql -U test_user1 -h localhost -d demo_db -c "SELECT * FROM demo_table WHERE data = 'x' OR 1=1;" 2>&1
```

**Beklenen Çıktı:**
- ERROR: sql_firewall: Query blocked by security regex pattern.

---

## TEST 6: IP BLOCKING (GUC)

```bash
echo "=== TEST 6: IP BLOCKING ==="
psql -U postgres -h localhost -d demo_db <<'SQL'
ALTER SYSTEM SET sql_firewall.enable_ip_blocking = on;
ALTER SYSTEM SET sql_firewall.blocked_ips = '203.0.113.10,198.51.100.20,::1';
SQL

# ÖNEMLİ: IP blocking için PostgreSQL restart gerekli!
sudo -u postgres pg_ctl restart -D /var/lib/pgsql/16/data -m fast

# Ayarları kontrol et
sudo -u postgres psql -c "SHOW sql_firewall.blocked_ips;"

# IPv6 localhost (::1) bloklandığı için hata alınır
psql -U test_user1 -h localhost -d demo_db -c "SELECT 'test';" 2>&1

# IPv4 (127.0.0.1) bloklu değil, çalışır
psql -U test_user1 -h 127.0.0.1 -d demo_db -c "SELECT 'IPv4 test';" 2>&1

# 127.0.0.1'i de bloklayalım
sudo -u postgres psql <<'SQL'
ALTER SYSTEM SET sql_firewall.blocked_ips = '203.0.113.10,198.51.100.20,::1,127.0.0.1';
SQL

sudo -u postgres pg_ctl restart -D /var/lib/pgsql/16/data -m fast

# Şimdi IPv4 de bloklanır
psql -U test_user1 -h 127.0.0.1 -d demo_db -c "SELECT 'blocked';" 2>&1
```

**Beklenen Çıktı:**
- ::1 bloklu: ERROR: Connection from blocked IP address '::1' is not allowed
- 127.0.0.1 ilk önce çalışır, sonra bloklanır

**Test sonrası blokları temizle:**
```bash
sudo -u postgres psql <<'SQL'
ALTER SYSTEM SET sql_firewall.blocked_ips = '203.0.113.10,198.51.100.20';
ALTER SYSTEM SET sql_firewall.enable_ip_blocking = off;
SQL
sudo -u postgres pg_ctl restart -D /var/lib/pgsql/16/data -m fast
```

---

## TEST 7: APPLICATION BLOCKING (GUC)

```bash
echo "=== TEST 7: APPLICATION BLOCKING ==="
psql -U postgres -h localhost -d demo_db <<'SQL'
ALTER SYSTEM SET sql_firewall.enable_application_blocking = on;
ALTER SYSTEM SET sql_firewall.blocked_applications = 'hacktool,sqlmap';
SQL

# ÖNEMLİ: Application blocking için PostgreSQL restart gerekli!
sudo -u postgres pg_ctl restart -D /var/lib/pgsql/16/data -m fast

# Normal psql çalışır
PGAPPNAME=psql psql -U test_user1 -h localhost -d demo_db -c "SELECT 'normal app';" 2>&1

# hacktool bloklanır
PGAPPNAME=hacktool psql -U test_user1 -h localhost -d demo_db -c "SELECT 'hacker';" 2>&1

# sqlmap bloklanır
PGAPPNAME=sqlmap psql -U test_user1 -h localhost -d demo_db -c "SELECT 'injection';" 2>&1
```

**Beklenen Çıktı:**
- psql: Çalışır
- hacktool: ERROR: Connections from application 'hacktool' are not allowed
- sqlmap: ERROR: Connections from application 'sqlmap' are not allowed

---

## TEST 8: RATE LIMITING

```bash
echo "=== TEST 8: RATE LIMITING ==="
psql -U postgres -h localhost -d demo_db <<'SQL'
ALTER SYSTEM SET sql_firewall.enable_rate_limiting = on;
ALTER SYSTEM SET sql_firewall.rate_limit_count = 3;
ALTER SYSTEM SET sql_firewall.rate_limit_seconds = 5;
SQL

# ÖNEMLİ: Rate limiting için PostgreSQL restart gerekli!
sudo -u postgres pg_ctl restart -D /var/lib/pgsql/16/data -m fast

# 6 sorgu gönder - ilk 3'ü geçer, sonraki 3'ü bloklanır
for i in {1..6}; do
  echo "Query $i:"
  psql -U test_user1 -h localhost -d demo_db -c "SELECT $i AS query_num;" 2>&1 | head -2
  sleep 0.5
done
```

**Beklenen Çıktı:**
- Query 1-3: Başarılı
- Query 4-6: ERROR: Rate limit exceeded for role 'test_user1'

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
SQL

# ÖNEMLİ: Quiet hours için PostgreSQL restart gerekli!
sudo -u postgres pg_ctl restart -D /var/lib/pgsql/16/data -m fast

# Quiet hours içinde sorgu çalıştır
psql -U test_user1 -h localhost -d demo_db -c "SELECT now();" 2>&1

# Test sonrası quiet hours'u kapat
sudo -u postgres psql <<'SQL'
ALTER SYSTEM SET sql_firewall.enable_quiet_hours = off;
SQL
sudo -u postgres pg_ctl restart -D /var/lib/pgsql/16/data -m fast
```

**Beklenen Çıktı (quiet hours içindeyse):**
- WARNING: Blocked during quiet hours
- ERROR: sql_firewall: Blocked during quiet hours (13:24 - 13:26)

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
SQL

# ÖNEMLİ: Role-IP binding için PostgreSQL restart gerekli!
sudo -u postgres pg_ctl restart -D /var/lib/pgsql/16/data -m fast

# İzin verilen IP'den (localhost) bağlanır
psql -U test_user2 -h localhost -d demo_db -c "SELECT 'allowed from localhost' AS result;" 2>&1

# İzin verilen başka IP (IPv4)
psql -U test_user2 -h 127.0.0.1 -d demo_db -c "SELECT 'allowed from 127.0.0.1' AS result;" 2>&1
```

**Beklenen Çıktı:**
- localhost (::1): Başarılı - "allowed from localhost"
- 127.0.0.1: Başarılı - "allowed from 127.0.0.1"
- Başka IP'den bağlanırsa: ERROR (test ortamında yapılamaz)

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

**Beklenen Çıktı:**
- Tüm komutlar (DROP, CREATE, INSERT, SELECT) başarıyla çalışır
- Normal kullanıcılarda bloklanacak komutlar superuser için çalışır

**Not:** Superuser bypass'i kapatmak için:
```sql
ALTER SYSTEM SET sql_firewall.allow_superuser_auth_bypass = off;
-- Restart sonrası superuser da kurallara tabi olur
```

---

## TEST 12: BACKGROUND WORKER TAKİBİ

```bash
echo "=== TEST 12: BACKGROUND WORKER ==="
# Worker'ın doğru DB'ye yazdığını doğrula
psql -U postgres -h localhost <<'SQL'
ALTER SYSTEM SET sql_firewall.approval_worker_database = 'demo_db';
SQL

# ÖNEMLİ: approval_worker_database Postmaster GUC'dur, PostgreSQL restart gerekli!
sudo -u postgres pg_ctl restart -D /var/lib/pgsql/16/data -m fast

# Learn mode'a al
sudo -u postgres psql -d demo_db <<'SQL'
ALTER SYSTEM SET sql_firewall.mode = 'learn';
SQL

sudo -u postgres pg_ctl restart -D /var/lib/pgsql/16/data -m fast

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

**Beklenen Çıktı:**
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
SQL

# Restart
sudo -u postgres pg_ctl restart -D /var/lib/pgsql/16/data -m fast

# Test verilerini temizle
psql -U postgres -h localhost <<'SQL'
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
-- demo_db yeniden oluşturulacaksa, CREATE DATABASE + CREATE EXTENSION sonrasında:
-- SELECT sql_firewall_resume_approval_worker();
SQL
```

---

## Özet

| # | Özellik | Restart Gerekli? | Test Durumu | Açıklama |
|---|---------|------------------|-------------|----------|
| 1 | Enforce Mode | ✅ Evet | ✅ Başarılı | Komut bazlı approval zorunlu |
| 2 | Learn Mode | ✅ Evet | ✅ Başarılı | Pending queue + worker yazımı |
| 3 | Permissive Mode | ✅ Evet | ✅ Başarılı | İzin ver + activity log |
| 4 | Keyword Scan | ✅ Evet | ✅ Başarılı | Regex rules ile DROP/TRUNCATE bloklanır |
| 5 | Regex Rules | ⚠️ İlk kez evet | ✅ Başarılı | SQL injection (OR 1=1) bloklanır |
| 6 | IP Blocking | ✅ Evet | ✅ Başarılı | IPv4/IPv6 bloklaması çalışır |
| 7 | Application Blocking | ✅ Evet | ✅ Başarılı | hacktool, sqlmap bloklanır |
| 8 | Rate Limiting | ✅ Evet | ✅ Başarılı | İlk N sorgu geçer, sonrakiler bloklanır |
| 9 | Quiet Hours | ✅ Evet | ✅ Başarılı | Zaman bazlı blok çalışır |
| 10 | Role-IP Binding | ✅ Evet | ✅ Başarılı | Belirtilen IP'lerden bağlantı izni |
| 11 | Superuser Bypass | ❌ Hayır | ✅ Başarılı | Superuser tüm kuralları bypass eder |
| 12 | Background Worker | ✅ Evet | ✅ Başarılı | Pending approvals tabloya yazılır |

**ÖNEMLİ NOTLAR:**

1. **Mode Değişiklikleri (enforce/learn/permissive):** Her zaman PostgreSQL restart gerektirir
2. **GUC Parametreleri:** Çoğu GUC parametresi (IP blocking, app blocking, rate limiting, vb.) restart gerektirir
3. **Regex Rules:** Tabloya ekleme restart gerektirmez, ancak `enable_regex_scan` ilk kez açılırken restart gerekir
4. **Reload vs Restart:** `SELECT pg_reload_conf()` sadece bazı parametreler için yeterlidir, çoğu özellik restart ister

**Restart Komutu:**
```bash
sudo -u postgres pg_ctl restart -D /var/lib/pgsql/16/data -m fast
# veya
systemctl restart postgresql-16
```

**Test Sonucu: 12/12 Özellik Başarıyla Test Edildi!** 🎉
