# PASSWORD PROFILE - KAPSAMLI DEMO REHBERİ

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

---

## TEST 1: ŞİFRE KOMPLEKSLİK KURALLARI

```bash
echo "=== TEST 1: PASSWORD COMPLEXITY ==="

# Çok kısa şifre (min_length=8)
sudo -u postgres psql -d password_demo_db -c "CREATE ROLE short_pw WITH LOGIN PASSWORD '12345';" 2>&1 | grep -E "ERROR|WARNING"

# Kullanıcı adı içeren şifre (prevent_username=on)
sudo -u postgres psql -d password_demo_db -c "CREATE ROLE john WITH LOGIN PASSWORD 'john123';" 2>&1 | grep -E "ERROR|WARNING"

# Geçerli şifre
sudo -u postgres psql -d password_demo_db -c "CREATE ROLE charlie WITH LOGIN PASSWORD 'SecurePass2024!'; SELECT 'Charlie oluşturuldu!' as result;"
```

**Beklenen:**
- ❌ "12345" → Password too short
- ❌ "john123" → Password contains username
- ✅ "SecurePass2024!" → Başarılı

---

## TEST 2: FAILED LOGIN ATTEMPTS & ACCOUNT LOCKOUT

```bash
echo "=== TEST 2: FAILED LOGIN & LOCKOUT ==="

# Alice ile 3 başarısız deneme
echo "Başarısız deneme 1:"
PGPASSWORD=wrong psql -h 127.0.0.1 -U alice -d password_demo_db -c "SELECT 1;" 2>&1 | head -1

echo "Başarısız deneme 2:"
PGPASSWORD=wrong psql -h 127.0.0.1 -U alice -d password_demo_db -c "SELECT 1;" 2>&1 | head -1

echo "Başarısız deneme 3:"
PGPASSWORD=wrong psql -h 127.0.0.1 -U alice -d password_demo_db -c "SELECT 1;" 2>&1 | head -1

sleep 2

# Login attempts tablosunu kontrol et
sudo -u postgres psql -d password_demo_db -c "SELECT username, fail_count, lockout_until FROM password_profile.login_attempts WHERE username='alice';"

# 4. deneme (hesap kilitli olmalı)
echo ""
echo "4. deneme (doğru şifre bile olsa kilitli):"
PGPASSWORD='SecurePass123!' psql -h 127.0.0.1 -U alice -d password_demo_db -c "SELECT 1;" 2>&1 | head -2
```

**Beklenen:**
- İlk 3 deneme → FATAL: password authentication failed
- Tablo → fail_count=3, lockout_until=(2 dakika sonrası)
- 4. deneme → FATAL: Account locked! (1 minute 30 seconds kalan süre)

---

## TEST 3: CLEAR LOGIN ATTEMPTS (Kilidi Kaldır)

```bash
echo "=== TEST 3: CLEAR LOGIN ATTEMPTS ==="

# Kilidi kaldır
sudo -u postgres psql -d password_demo_db -c "SELECT clear_login_attempts('alice');"

# Kontrol et
sudo -u postgres psql -d password_demo_db -c "SELECT username, fail_count FROM password_profile.login_attempts WHERE username='alice';"

# Şimdi doğru şifre ile giriş yapabilmeli
echo "Doğru şifre ile login:"
PGPASSWORD='SecurePass123!' psql -h 127.0.0.1 -U alice -d password_demo_db -c "SELECT 'Başarılı login!' as result;"
```

**Beklenen:**
- ✅ clear_login_attempts → "Login attempts cleared"
- ✅ Tablo → fail_count=0 veya kayıt yok
- ✅ Login başarılı

---

## TEST 4: PASSWORD HISTORY (Son 5 Şifre Tekrar Kullanılamaz)

```bash
echo "=== TEST 4: PASSWORD HISTORY ==="

# Test kullanıcısı oluştur
sudo -u postgres psql -d password_demo_db << 'SQL'
DROP ROLE IF EXISTS history_user;
CREATE ROLE history_user WITH LOGIN PASSWORD 'FirstPassword123!';

-- İlk şifreyi kaydet
SELECT record_password_change('history_user', 'FirstPassword123!');

-- Şifre değiştir ve kaydet
ALTER ROLE history_user WITH PASSWORD 'SecondPassword456!';
SELECT record_password_change('history_user', 'SecondPassword456!');

-- Tekrar değiştir
ALTER ROLE history_user WITH PASSWORD 'ThirdPassword789!';
SELECT record_password_change('history_user', 'ThirdPassword789!');

-- Password history'e bak
SELECT username, changed_at FROM password_profile.password_history 
WHERE username = 'history_user' 
ORDER BY changed_at DESC 
LIMIT 3;
SQL

echo ""
echo "Eski şifreyi (FirstPassword123!) kullanmayı dene:"
sudo -u postgres psql -d password_demo_db -c "ALTER ROLE history_user WITH PASSWORD 'FirstPassword123!';" 2>&1 | grep -E "ERROR|WARNING"

echo ""
echo "Yeni bir şifre (FourthPassword000!) kullan:"
sudo -u postgres psql -d password_demo_db -c "ALTER ROLE history_user WITH PASSWORD 'FourthPassword000!'; SELECT 'Şifre değiştirildi!' as result;"
```

**Beklenen:**
- ❌ Eski şifre (FirstPassword123!) → Password was used recently. Cannot reuse last 5 passwords
- ✅ Yeni şifre (FourthPassword000!) → Başarılı

**NOT:** `record_password_change()` fonksiyonu ile şifre değişikliklerini history'e kaydetmelisiniz.

---

## TEST 5: PASSWORD BLACKLIST

```bash
echo "=== TEST 5: PASSWORD BLACKLIST ==="

# Yaygın şifreleri blacklist'e ekle
sudo -u postgres psql -d password_demo_db << 'SQL'
SELECT add_to_blacklist('Password123', 'Common password');
SELECT add_to_blacklist('Admin123', 'Common admin password');
SELECT add_to_blacklist('Qwerty123', 'Keyboard pattern');

-- Blacklist'i göster
SELECT password, reason FROM password_profile.blacklist;
SQL

# Blacklist'teki şifre ile kullanıcı oluşturmayı dene
echo ""
echo "Blacklist'teki şifre ile kullanıcı oluşturma:"
sudo -u postgres psql -d password_demo_db -c "CREATE ROLE hacker WITH LOGIN PASSWORD 'Password123';" 2>&1 | grep -E "ERROR|WARNING"

# Blacklist'te olmayan şifre
sudo -u postgres psql -d password_demo_db -c "CREATE ROLE david WITH LOGIN PASSWORD 'David2024!'; SELECT 'David oluşturuldu!' as result;"
```

**Beklenen:**
- ❌ "Password123" → Password is blacklisted
- ✅ "David2024!" → Başarılı

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

