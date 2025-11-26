
## Hazırlık

```bash
# Demo database ve kullanıcılar oluştur
# NOT: Background worker'lar aktif olduğu için DROP DATABASE takılabilir.
# Bunun yerine veritabanını temizleyip yeniden kullanıyoruz.

# Veritabanı yoksa oluştur
sudo -u postgres psql -d postgres -c "SELECT 1 FROM pg_database WHERE datname = 'password_demo_db'" | grep -q 1 || sudo -u postgres createdb password_demo_db

# Veritabanını temizle ve extensionları yükle
sudo -u postgres psql -d password_demo_db << 'SQL'
-- Extension yükle (tablolar otomatik oluşur)
CREATE EXTENSION IF NOT EXISTS password_profile;
CREATE EXTENSION IF NOT EXISTS sql_firewall_rs;

-- Test kullanıcıları (eğer yoksa oluştur)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'alice') THEN
        CREATE ROLE alice WITH LOGIN PASSWORD 'SecurePass123!';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'bob') THEN
        CREATE ROLE bob WITH LOGIN PASSWORD 'StrongPass456!';
    END IF;
END
$$;

-- Demo tablosu
DROP TABLE IF EXISTS company_data;
CREATE TABLE company_data (id SERIAL PRIMARY KEY, data TEXT);
INSERT INTO company_data VALUES (1, 'Confidential Information');
GRANT SELECT ON company_data TO alice, bob;

SELECT 'Demo ortamı hazır!' as status;
SQL
```

**Beklenen Çıktı:**
```
CREATE EXTENSION
CREATE EXTENSION
DO
DROP TABLE
CREATE TABLE
INSERT 0 1
GRANT
       status       
--------------------
 Demo ortamı hazır!
```

> **NOT:** Extension `shared_preload_libraries` içinde olmalı. PostgreSQL restart edildikten sonra extension'ın background worker'ları otomatik başlar.

---

## TEST 1: ŞİFRE KOMPLEKSLİK KURALLARI

Password Profile, şifrelerin minimum uzunluk, büyük/küçük harf, rakam ve özel karakter içermesini zorunlu kılar.

### Aktif GUC Parametreleri:
- `password_profile.password_min_length = 8` (varsayılan)
- `password_profile.require_uppercase = on`
- `password_profile.require_lowercase = on`
- `password_profile.require_digit = on`
- `password_profile.require_special = on`
- `password_profile.prevent_username = on`

```bash
echo "=== TEST 1: PASSWORD COMPLEXITY ==="

# 1a. Çok kısa şifre (min_length=8)
echo "Test 1a: Kısa şifre (12345)"
sudo -u postgres psql -d password_demo_db -c "CREATE ROLE short_pw WITH LOGIN PASSWORD '12345';" 2>&1 | grep -E "ERROR|WARNING"

# 1b. Kullanıcı adı içeren şifre (prevent_username=on)
echo ""
echo "Test 1b: Kullanıcı adı içeren şifre (john123)"
sudo -u postgres psql -d password_demo_db -c "CREATE ROLE john WITH LOGIN PASSWORD 'john123';" 2>&1 | grep -E "ERROR|WARNING"

# 1c. Büyük harf eksik
echo ""
echo "Test 1c: Büyük harf eksik (lowercase123!)"
sudo -u postgres psql -d password_demo_db -c "CREATE ROLE no_upper WITH LOGIN PASSWORD 'lowercase123!';" 2>&1 | grep -E "ERROR|WARNING"

# 1d. Rakam eksik
echo ""
echo "Test 1d: Rakam eksik (NoDigits!)"
sudo -u postgres psql -d password_demo_db -c "CREATE ROLE no_digit WITH LOGIN PASSWORD 'NoDigits!';" 2>&1 | grep -E "ERROR|WARNING"

# 1e. Özel karakter eksik
echo ""
echo "Test 1e: Özel karakter eksik (NoSpecial123)"
sudo -u postgres psql -d password_demo_db -c "CREATE ROLE no_special WITH LOGIN PASSWORD 'NoSpecial123';" 2>&1 | grep -E "ERROR|WARNING"

# 1f. Geçerli şifre (tüm kurallara uygun)
echo ""
echo "Test 1f: Geçerli şifre (SecurePass2024!)"
sudo -u postgres psql -d password_demo_db -c "DROP ROLE IF EXISTS charlie; CREATE ROLE charlie WITH LOGIN PASSWORD 'SecurePass2024!'; SELECT 'Charlie oluşturuldu!' as result;"
```

**Beklenen Çıktı:**
```
Test 1a: Kısa şifre (12345)
WARNING:  [PASSWORD_PROFILE][REJECTED][user=short_pw] Password too short
ERROR:  Password validation failed: Password too short

Test 1b: Kullanıcı adı içeren şifre (john123)
WARNING:  [PASSWORD_PROFILE][REJECTED][user=john] Password too short
ERROR:  Password validation failed: Password too short

Test 1c: Büyük harf eksik (lowercase123!)
WARNING:  [PASSWORD_PROFILE][REJECTED][user=no_upper] Password must contain at least one uppercase letter
ERROR:  Password validation failed: Password must contain at least one uppercase letter

Test 1d: Rakam eksik (NoDigits!)
WARNING:  [PASSWORD_PROFILE][REJECTED][user=no_digit] Password must contain at least one digit
ERROR:  Password validation failed: Password must contain at least one digit

Test 1e: Özel karakter eksik (NoSpecial123)
WARNING:  [PASSWORD_PROFILE][REJECTED][user=no_special] Password must contain at least one special character
ERROR:  Password validation failed: Password must contain at least one special character

Test 1f: Geçerli şifre (SecurePass2024!)
DROP ROLE
CREATE ROLE
        result        
----------------------
 Charlie oluşturuldu!
```

---

## TEST 2: FAILED LOGIN ATTEMPTS & ACCOUNT LOCKOUT

Password Profile, başarısız giriş denemelerini izler ve belirli sayıda hatalı denemeden sonra hesabı otomatik kilitler.

### Aktif GUC Parametreleri:
- `password_profile.max_failed_attempts = 3` (varsayılan)
- `password_profile.lockout_duration_minutes = 2` (varsayılan)

```bash
echo "=== TEST 2: FAILED LOGIN & LOCKOUT ==="

# Alice ile 3 başarısız deneme (yanlış şifre)
echo "Test 2a: Başarısız deneme 1"
PGPASSWORD=wrong psql -h 127.0.0.1 -U alice -d password_demo_db -c "SELECT 1;" 2>&1 | head -1

echo ""
echo "Test 2b: Başarısız deneme 2"
PGPASSWORD=wrong psql -h 127.0.0.1 -U alice -d password_demo_db -c "SELECT 1;" 2>&1 | head -1

echo ""
echo "Test 2c: Başarısız deneme 3"
PGPASSWORD=wrong psql -h 127.0.0.1 -U alice -d password_demo_db -c "SELECT 1;" 2>&1 | head -1

sleep 2

# Login attempts tablosunu kontrol et
echo ""
echo "Test 2d: Login attempts tablosunu kontrol et"
sudo -u postgres psql -d password_demo_db -c "SELECT username, fail_count, lockout_until FROM password_profile.login_attempts WHERE username='alice';"

# 4. deneme (hesap kilitli olmalı - doğru şifre bile olsa)
echo ""
echo "Test 2e: 4. deneme (doğru şifre ile - hesap kilitli)"
PGPASSWORD='SecurePass123!' psql -h 127.0.0.1 -U alice -d password_demo_db -c "SELECT 1;" 2>&1 | head -2

# 5. deneme (hala kilitli)
echo ""
echo "Test 2f: 5. deneme (hala kilitli)"
PGPASSWORD='SecurePass123!' psql -h 127.0.0.1 -U alice -d password_demo_db -c "SELECT 1;" 2>&1 | head -2
```

**Beklenen Çıktı:**
```
Test 2a: Başarısız deneme 1
psql: error: connection to server at "127.0.0.1", port 5432 failed: FATAL:  password authentication failed for user "alice"

Test 2b: Başarısız deneme 2
psql: error: connection to server at "127.0.0.1", port 5432 failed: FATAL:  password authentication failed for user "alice"

Test 2c: Başarısız deneme 3
psql: error: connection to server at "127.0.0.1", port 5432 failed: FATAL:  password authentication failed for user "alice"

Test 2d: Login attempts tablosunu kontrol et
 username | fail_count |        lockout_until        
----------+------------+-----------------------------
 alice    |          3 | 2025-11-26 11:15:30.123+03
(1 row)

Test 2e: 4. deneme (doğru şifre ile - hesap kilitli)
psql: error: connection to server at "127.0.0.1", port 5432 failed: FATAL:  Account locked for user: alice. Try again after 1 minute 30 seconds

Test 2f: 5. deneme (hala kilitli)
psql: error: connection to server at "127.0.0.1", port 5432 failed: FATAL:  Account locked for user: alice. Try again after 1 minute 20 seconds
```

> **NOT:** Hesap kilidi `lockout_duration_minutes` süresi kadar devam eder. Bu süre sonunda otomatik olarak kilidi açılır.

---

## TEST 3: CLEAR LOGIN ATTEMPTS (Kilidi Kaldır)

Kilitli bir hesabın kilidini manuel olarak kaldırma fonksiyonu.

```bash
echo "=== TEST 3: CLEAR LOGIN ATTEMPTS ==="

# Alice'in kilidini kaldır
echo "Test 3a: Alice'in kilidini kaldır"
sudo -u postgres psql -d password_demo_db -c "SELECT clear_login_attempts('alice');"

# Kontrol et - kayıt temizlenmeli
echo ""
echo "Test 3b: Login attempts tablosunu kontrol et"
sudo -u postgres psql -d password_demo_db -c "SELECT username, fail_count, lockout_until FROM password_profile.login_attempts WHERE username='alice';"

# Şimdi doğru şifre ile giriş yapabilmeli
echo ""
echo "Test 3c: Doğru şifre ile giriş"
PGPASSWORD='SecurePass123!' psql -h 127.0.0.1 -U alice -d password_demo_db -c "SELECT 'Başarılı login!' as result;"

# Başarılı girişten sonra tablo durumu
echo ""
echo "Test 3d: Başarılı girişten sonra tablo durumu"
sudo -u postgres psql -d password_demo_db -c "SELECT username, fail_count, lockout_until FROM password_profile.login_attempts WHERE username='alice';"
```

**Beklenen Çıktı:**
```
Test 3a: Alice'in kilidini kaldır
      clear_login_attempts      
--------------------------------
 Login attempts cleared for alice
(1 row)

Test 3b: Login attempts tablosunu kontrol et
 username | fail_count | lockout_until 
----------+------------+---------------
(0 rows)

Test 3c: Doğru şifre ile giriş
        result        
----------------------
 Başarılı login!
(1 row)

Test 3d: Başarılı girişten sonra tablo durumu
 username | fail_count | lockout_until 
----------+------------+---------------
(0 rows)
```

> **NOT:** `clear_login_attempts()` fonksiyonu kullanıcının tüm başarısız giriş kayıtlarını siler ve hesabın kilidini açar.

---

## TEST 4: PASSWORD HISTORY (Son 5 Şifre Tekrar Kullanılamaz)

Password Profile, son N şifreyi otomatik olarak kaydeder ve kullanıcıların eski şifrelerini tekrar kullanmasını engeller.

### Aktif GUC Parametreleri:
- `password_profile.password_history_count = 5` (varsayılan)

```bash
echo "=== TEST 4: PASSWORD HISTORY ==="

# Test kullanıcısı oluştur
echo "Test 4a: Yeni kullanıcı oluştur ve ilk şifre history'e kaydedilir"
sudo -u postgres psql -d password_demo_db << 'SQL'
DROP ROLE IF EXISTS history_user;
CREATE ROLE history_user WITH LOGIN PASSWORD 'FirstPassword123!';
SQL

# Şifre değiştir (otomatik history'e kaydedilir)
echo ""
echo "Test 4b: Şifre değiştir (2. şifre)"
sudo -u postgres psql -d password_demo_db -c "ALTER ROLE history_user WITH PASSWORD 'SecondPassword456!';"

# Tekrar değiştir (otomatik history'e kaydedilir)
echo ""
echo "Test 4c: Şifre değiştir (3. şifre)"
sudo -u postgres psql -d password_demo_db -c "ALTER ROLE history_user WITH PASSWORD 'ThirdPassword789!';"

# Password history'e bak
echo ""
echo "Test 4d: Password history tablosunu kontrol et"
sudo -u postgres psql -d password_demo_db << 'SQL'
SELECT username, changed_at, 
       substring(password_hash from 1 for 20) || '...' as password_hash_preview
FROM password_profile.password_history 
WHERE username = 'history_user' 
ORDER BY changed_at DESC 
LIMIT 3;
SQL

# Eski şifreyi (FirstPassword123!) kullanmayı dene
echo ""
echo "Test 4e: Eski şifreyi (FirstPassword123!) kullanmayı dene"
sudo -u postgres psql -d password_demo_db -c "ALTER ROLE history_user WITH PASSWORD 'FirstPassword123!';" 2>&1 | grep -E "ERROR|WARNING"

# 2. eski şifreyi (SecondPassword456!) kullanmayı dene
echo ""
echo "Test 4f: 2. eski şifreyi (SecondPassword456!) kullanmayı dene"
sudo -u postgres psql -d password_demo_db -c "ALTER ROLE history_user WITH PASSWORD 'SecondPassword456!';" 2>&1 | grep -E "ERROR|WARNING"

# Yeni bir şifre (FourthPassword000!) kullan - başarılı olmalı
echo ""
echo "Test 4g: Yeni bir şifre (FourthPassword000!) kullan"
sudo -u postgres psql -d password_demo_db -c "ALTER ROLE history_user WITH PASSWORD 'FourthPassword000!'; SELECT 'Şifre değiştirildi!' as result;"

# History count kontrolü
echo ""
echo "Test 4h: Toplam kaç şifre history'de"
sudo -u postgres psql -d password_demo_db -c "SELECT COUNT(*) as total_passwords FROM password_profile.password_history WHERE username = 'history_user';"
```

**Beklenen Çıktı:**
```
Test 4a: Yeni kullanıcı oluştur ve ilk şifre history'e kaydedilir
DROP ROLE
CREATE ROLE

Test 4b: Şifre değiştir (2. şifre)
ALTER ROLE

Test 4c: Şifre değiştir (3. şifre)
ALTER ROLE

Test 4d: Password history tablosunu kontrol et
   username    |          changed_at           |  password_hash_preview  
---------------+-------------------------------+-------------------------
 history_user  | 2025-11-26 11:20:15.123+03   | $2b$12$abcdef123456...
 history_user  | 2025-11-26 11:20:14.456+03   | $2b$12$xyz789012345...
 history_user  | 2025-11-26 11:20:13.789+03   | $2b$12$qwerty098765...
(3 rows)

Test 4e: Eski şifreyi (FirstPassword123!) kullanmayı dene
WARNING:  [PASSWORD_PROFILE][REJECTED][user=history_user] Password was used recently. Cannot reuse last 5 passwords.
ERROR:  Password validation failed: Password was used recently. Cannot reuse last 5 passwords.

Test 4f: 2. eski şifreyi (SecondPassword456!) kullanmayı dene
WARNING:  [PASSWORD_PROFILE][REJECTED][user=history_user] Password was used recently. Cannot reuse last 5 passwords.
ERROR:  Password validation failed: Password was used recently. Cannot reuse last 5 passwords.

Test 4g: Yeni bir şifre (FourthPassword000!) kullan
ALTER ROLE
        result        
----------------------
 Şifre değiştirildi!
(1 row)

Test 4h: Toplam kaç şifre history'de
 total_passwords 
-----------------
               4
(1 row)
```

> **NOT:** Şifre değişiklikleri artık otomatik olarak `password_profile.password_history` tablosuna kaydedilir. Manuel kayıt gerekmez.

---

## TEST 5: PASSWORD BLACKLIST

Password Profile, yaygın ve zayıf şifrelerin kullanımını engellemek için blacklist özelliği sağlar.

```bash
echo "=== TEST 5: PASSWORD BLACKLIST ==="

# Yaygın şifreleri blacklist'e ekle
echo "Test 5a: Blacklist'e yaygın şifreler ekle"
sudo -u postgres psql -d password_demo_db << 'SQL'
SELECT add_to_blacklist('Password123', 'Common password');
SELECT add_to_blacklist('Admin123', 'Common admin password');
SELECT add_to_blacklist('Qwerty123', 'Keyboard pattern');
SELECT add_to_blacklist('Welcome1!', 'Welcome password');
SELECT add_to_blacklist('Abc123456!', 'Simple sequential');
SQL

# Blacklist'i göster
echo ""
echo "Test 5b: Blacklist'i göster"
sudo -u postgres psql -d password_demo_db -c "SELECT password, reason, created_at FROM password_profile.blacklist ORDER BY created_at DESC LIMIT 5;"

# Blacklist'teki şifre ile kullanıcı oluşturmayı dene
echo ""
echo "Test 5c: Blacklist'teki şifre ile kullanıcı oluşturma (Password123)"
sudo -u postgres psql -d password_demo_db -c "CREATE ROLE hacker1 WITH LOGIN PASSWORD 'Password123';" 2>&1 | grep -E "ERROR|WARNING"

echo ""
echo "Test 5d: Blacklist'teki başka bir şifre (Admin123)"
sudo -u postgres psql -d password_demo_db -c "CREATE ROLE hacker2 WITH LOGIN PASSWORD 'Admin123';" 2>&1 | grep -E "ERROR|WARNING"

# Blacklist'te olmayan geçerli şifre
echo ""
echo "Test 5e: Blacklist'te olmayan geçerli şifre (David2024!)"
sudo -u postgres psql -d password_demo_db -c "DROP ROLE IF EXISTS david; CREATE ROLE david WITH LOGIN PASSWORD 'David2024!'; SELECT 'David oluşturuldu!' as result;"

# Blacklist'ten kaldırma
echo ""
echo "Test 5f: Blacklist'ten şifre kaldır"
sudo -u postgres psql -d password_demo_db -c "SELECT remove_from_blacklist('Password123');"

# Kaldırıldıktan sonra kullanılabilir mi?
echo ""
echo "Test 5g: Kaldırılan şifre artık kullanılabilir mi?"
sudo -u postgres psql -d password_demo_db -c "DROP ROLE IF EXISTS test_removed; CREATE ROLE test_removed WITH LOGIN PASSWORD 'Password123';" 2>&1
```

**Beklenen Çıktı:**
```
Test 5a: Blacklist'e yaygın şifreler ekle
    add_to_blacklist    
------------------------
 Added to blacklist
(1 row)
...

Test 5b: Blacklist'i göster
  password   |       reason        |          created_at
-------------+---------------------+------------------------------
 Abc123456!  | Simple sequential   | 2025-11-26 11:25:10.123+03
 Welcome1!   | Welcome password    | 2025-11-26 11:25:09.456+03
 Qwerty123   | Keyboard pattern    | 2025-11-26 11:25:08.789+03
 Admin123    | Common admin pass   | 2025-11-26 11:25:08.123+03
 Password123 | Common password     | 2025-11-26 11:25:07.456+03
(5 rows)

Test 5c: Blacklist'teki şifre ile kullanıcı oluşturma (Password123)
WARNING:  [PASSWORD_PROFILE][REJECTED][user=hacker1] Password is in blacklist (too common)
ERROR:  Password validation failed: Password is in blacklist (too common)

Test 5d: Blacklist'teki başka bir şifre (Admin123)
WARNING:  [PASSWORD_PROFILE][REJECTED][user=hacker2] Password is in blacklist (too common)
ERROR:  Password validation failed: Password is in blacklist (too common)

Test 5e: Blacklist'te olmayan geçerli şifre (David2024!)
DROP ROLE
CREATE ROLE
        result        
----------------------
 David oluşturuldu!
(1 row)

Test 5f: Blacklist'ten şifre kaldır
  remove_from_blacklist  
-------------------------
 Removed from blacklist
(1 row)

Test 5g: Kaldırılan şifre artık kullanılabilir mi?
DROP ROLE
CREATE ROLE
```

> **NOT:** Blacklist kontrolü büyük/küçük harf duyarlıdır. "password123" ve "Password123" farklı şifrelerdir.

---

## TEST 6: PASSWORD EXPIRY & GRACE LOGINS

```bash
echo "=== TEST 6: PASSWORD EXPIRY ==="

# Charlie için şifre süresini geçmiş yap
sudo -u postgres psql -d password_demo_db << 'SQL'
INSERT INTO password_profile.password_expiry (username, last_changed, must_change_by, grace_logins_remaining)
VALUES ('charlie', NOW() - INTERVAL '100 days', NOW() - INTERVAL '10 days', 3)
ON CONFLICT (username) DO UPDATE 
SET must_change_by = NOW() - INTERVAL '10 days', 
    grace_logins_remaining = 3;

SELECT username, must_change_by, grace_logins_remaining 
FROM password_profile.password_expiry WHERE username='charlie';
SQL

# Grace login denemesi 1
echo ""
echo "Grace login 1:"
PGPASSWORD='Charlie2024!' psql -h 127.0.0.1 -U charlie -d password_demo_db -c "SELECT 'Grace login 1' as result;" 2>&1 | grep -E "expired|Grace|result"

# Grace login denemesi 2
echo "Grace login 2:"
PGPASSWORD='Charlie2024!' psql -h 127.0.0.1 -U charlie -d password_demo_db -c "SELECT 'Grace login 2' as result;" 2>&1 | grep -E "expired|Grace|result"

# Grace login denemesi 3
echo "Grace login 3:"
PGPASSWORD='Charlie2024!' psql -h 127.0.0.1 -U charlie -d password_demo_db -c "SELECT 'Grace login 3' as result;" 2>&1 | grep -E "expired|Grace|result"

sleep 2

# Grace login kalan kontrol
sudo -u postgres psql -d password_demo_db -c "SELECT username, grace_logins_remaining FROM password_profile.password_expiry WHERE username='charlie';"

# 4. deneme (grace login bitti)
echo ""
echo "4. deneme (grace login tükendi):"
PGPASSWORD='Charlie2024!' psql -h 127.0.0.1 -U charlie -d password_demo_db -c "SELECT 1;" 2>&1 | head -2
```

**Beklenen:**
- ✅ Grace login 1, 2, 3 → Başarılı (warning ile)
- grace_logins_remaining → 0'a düştü
- ❌ 4. deneme → FATAL: Password expired

---

## TEST 5: HELPER FUNCTIONS

```bash
echo "=== TEST 5: HELPER FUNCTIONS ==="

# is_user_locked kontrolü
sudo -u postgres psql -d password_demo_db -c "SELECT is_user_locked('alice');"

# check_password_expiry
sudo -u postgres psql -d password_demo_db -c "SELECT check_password_expiry('charlie');"

# get_password_stats
sudo -u postgres psql -d password_demo_db -c "SELECT get_password_stats('bob');"

# check_user_access (combined check)
sudo -u postgres psql -d password_demo_db -c "SELECT check_user_access('alice');"

# Lock cache stats
sudo -u postgres psql -d password_demo_db -c "SELECT * FROM get_lock_cache_stats();"
```

---

## TEST 8: SUPERUSER BYPASS

```bash
echo "=== TEST 8: SUPERUSER BYPASS ==="

# postgres kullanıcısı için fail count olmamalı
PGPASSWORD=wrong psql -h 127.0.0.1 -U postgres -d password_demo_db -c "SELECT 1;" 2>&1 | head -1

# Kontrol et (postgres kaydedilmemeli)
sudo -u postgres psql -d password_demo_db -c "SELECT COUNT(*) as postgres_fail_count FROM password_profile.login_attempts WHERE username='postgres';"
```

**Beklenen:**
- Superuser için failed login tracking YOK
- postgres_fail_count → 0

---

## TEST 9: ROLE-SPECIFIC GUC OVERRIDES

```bash
echo "=== TEST 9: ROLE-SPECIFIC SETTINGS ==="

# David için custom ayarlar
sudo -u postgres psql -d password_demo_db << 'SQL'
-- David için özel lockout süresi (5 dakika)
ALTER ROLE david SET password_profile.lockout_minutes = 5;

-- David için max fail count (5)
ALTER ROLE david SET password_profile.failed_login_max = 5;

-- Kontrol et
SELECT rolname, rolconfig FROM pg_roles WHERE rolname='david';
SQL

# David ile 3 başarısız deneme (5'e kadar izin var)
for i in {1..3}; do
    echo "David deneme $i:"
    PGPASSWORD=wrong psql -h 127.0.0.1 -U david -d password_demo_db -c "SELECT 1;" 2>&1 | head -1
    sleep 1
done

# Kontrol et (henüz kilitlenmemeli)
sudo -u postgres psql -d password_demo_db -c "SELECT username, fail_count, lockout_until FROM password_profile.login_attempts WHERE username='david';"
```

**Beklenen:**
- fail_count → 3
- lockout_until → NULL (henüz kilitli değil, 5'e kadar izin var)

---

## TEST 10: BLACKLIST'TEN ÇIKARMA

```bash
echo "=== TEST 10: REMOVE FROM BLACKLIST ==="

# Blacklist'ten kaldır
sudo -u postgres psql -d password_demo_db -c "SELECT remove_from_blacklist('Password123');"

# Kontrol et
sudo -u postgres psql -d password_demo_db -c "SELECT COUNT(*) as count FROM password_profile.blacklist WHERE password='Password123';"

# Şimdi kullanılabilmeli
sudo -u postgres psql -d password_demo_db -c "CREATE ROLE test_user WITH LOGIN PASSWORD 'Password123';"
```

**Beklenen:**
- ✅ Blacklist'ten kaldırıldı
- ✅ Şimdi "Password123" kullanılabilir

---

## TEST 11: ACTIVITY LOG İNCELEME

```bash
echo "=== TEST 11: ACTIVITY MONITORING ==="

# Son 10 login attempt
sudo -u postgres psql -d password_demo_db << 'SQL'
SELECT 
    username,
    fail_count,
    last_fail,
    CASE 
        WHEN lockout_until IS NOT NULL AND lockout_until > NOW() THEN 'LOCKED'
        ELSE 'ACTIVE'
    END as status
FROM password_profile.login_attempts
ORDER BY last_fail DESC NULLS LAST;

-- Kullanıcı bazında özet
SELECT 
    username,
    COUNT(*) as password_changes
FROM password_profile.password_history
GROUP BY username
ORDER BY password_changes DESC;
SQL
```

---

## DEMO TAMAMLANDI! 🎉

```bash
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║           PASSWORD PROFILE DEMO TAMAMLANDI!               ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Tüm özellikler test edildi:"
echo "✅ Password Complexity Rules"
echo "✅ Failed Login Tracking"
echo "✅ Account Lockout (3 failed attempts)"
echo "✅ Password Blacklist"
echo "✅ Password History (reuse prevention)"
echo "✅ Password Expiry & Grace Logins"
echo "✅ Helper Functions"
echo "✅ Superuser Bypass"
echo "✅ Role-specific GUC Overrides"
echo "✅ Blacklist Management"
echo "✅ Activity Monitoring"
echo ""
```

