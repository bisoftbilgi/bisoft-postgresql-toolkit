# SQL Firewall RS - Rust PostgreSQL Güvenlik Extension'ı

PostgreSQL veritabanlarını SQL injection, yetkisiz erişim ve zararlı sorgulara karşı korumak için Rust ile yazılmış, yüksek performanslı bir güvenlik katmanı.

## 🚀 Özellikler

### 🛡️ Güvenlik Modları
- **Learn Mode**: Sorguları öğrenir, onay bekletir
- **Permissive Mode**: Uyarır ama engelleme
- **Enforce Mode**: Onaysız sorguları kesin engeller

### 🔒 Koruma Mekanizmaları
1. **Keyword Blacklisting**: Tehlikeli SQL keyword'lerini engelle
2. **Regex Pattern Matching**: SQL injection pattern'lerini tespit et
3. **Quiet Hours**: Belirli saatlerde tüm sorguları engelle
4. **Rate Limiting**: Kullanıcı başına sorgu limiti
5. **Command-Based Rate Limiting**: SELECT, INSERT, UPDATE, DELETE için ayrı limitler
6. **Approval System**: Komut bazlı onay mekanizması

### 📊 İzleme
- Detaylı activity logging
- Real-time query monitoring
- Security event tracking

## 📋 Gereksinimler

- PostgreSQL 16.x
- Rust 1.70+ 
- pgrx 0.16.1
- Linux (test edildi)

## ⚙️ Kurulum

### 1. pgrx Kurulumu
```bash
cargo install cargo-pgrx --version 0.16.1
cargo pgrx init --pg16 /usr/pgsql-16/bin/pg_config
```

### 2. Extension'ı Derleme
```bash
cd sql_firewall_rs
cargo build --release --no-default-features --features pg16
```

### 3. PostgreSQL'e Kurulum
```bash
cargo pgrx install --release
```

### 4. PostgreSQL Yapılandırması
`postgresql.conf` dosyasına ekleyin:
```conf
shared_preload_libraries = 'sql_firewall_rs'
```

PostgreSQL'i yeniden başlatın:
```bash
sudo systemctl restart postgresql-16
```

### 5. Extension'ı Aktifleştirme
```sql
CREATE EXTENSION sql_firewall_rs;
```

## 🎯 Hızlı Başlangıç

### Gerekli Tabloları Oluşturma
```sql
-- Activity log tablosu
CREATE TABLE sql_firewall_activity_log (
    id SERIAL PRIMARY KEY,
    log_time TIMESTAMP DEFAULT now(),
    role_name NAME NOT NULL,
    database_name NAME NOT NULL,
    action TEXT NOT NULL,
    reason TEXT,
    query_text TEXT,
    command_type TEXT
);

-- Komut onayları tablosu
CREATE TABLE sql_firewall_command_approvals (
    id SERIAL PRIMARY KEY,
    role_name NAME NOT NULL,
    command_type TEXT NOT NULL,
    is_approved BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT now(),
    UNIQUE(role_name, command_type)
);

-- Regex kuralları tablosu
CREATE TABLE sql_firewall_regex_rules (
    id SERIAL PRIMARY KEY,
    pattern TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('BLOCK', 'ALLOW')),
    is_active BOOLEAN DEFAULT true,
    description TEXT,
    created_at TIMESTAMP DEFAULT now()
);
```

### Temel Kullanım

#### 1. Learn Mode (Öğrenme)
```sql
SET sql_firewall.mode = 'learn';

-- Sorguları çalıştır, sistem öğrenir
SELECT * FROM users;
INSERT INTO logs VALUES ('test');

-- Öğrenilen komutları göster
SELECT * FROM sql_firewall_command_approvals;
```

#### 2. Keyword Blocking
```sql
SET sql_firewall.enable_keyword_scan = true;
SET sql_firewall.blacklisted_keywords = 'drop,truncate,pg_sleep';

-- Bu sorgu bloklanır
SELECT pg_sleep(10); -- ❌ HATA
```

#### 3. Quiet Hours (Sessiz Saatler)
```sql
SET sql_firewall.enable_quiet_hours = true;
SET sql_firewall.quiet_hours_start = '22:00';
SET sql_firewall.quiet_hours_end = '06:00';

-- 22:00 - 06:00 arası tüm sorgular engellenir
```

#### 4. Rate Limiting
```sql
-- Global rate limit
SET sql_firewall.enable_rate_limiting = true;
SET sql_firewall.rate_limit_count = 100;
SET sql_firewall.rate_limit_seconds = 60;

-- Komut bazlı limitler
SET sql_firewall.select_limit_count = 50;
SET sql_firewall.command_limit_seconds = 60;
```

#### 5. Regex Rules
```sql
-- SQL injection pattern'lerini engelle
INSERT INTO sql_firewall_regex_rules (pattern, action, description)
VALUES 
    ('.*;\s*DROP\s+TABLE.*', 'BLOCK', 'SQL injection: DROP TABLE'),
    ('.*UNION\s+SELECT.*', 'BLOCK', 'SQL injection: UNION-based');
```

#### 6. Enforce Mode
```sql
-- Belirli komutları onayla
UPDATE sql_firewall_command_approvals 
SET is_approved = true 
WHERE command_type IN ('SELECT', 'INSERT');

-- Enforce mode'a geç
SET sql_firewall.mode = 'enforce';

-- Sadece onaylı komutlar çalışır
SELECT * FROM users;  -- ✅ OK
UPDATE users SET name = 'test';  -- ❌ HATA
```

## 🧪 Test

### Otomatik Test Çalıştırma
```bash
./run_tests.sh
```

### Manuel Test
```bash
psql -U postgres -d testdb -f test_firewall.sql
```

## 📖 Yapılandırma Parametreleri

| Parametre | Tip | Default | Açıklama |
|-----------|-----|---------|----------|
| `sql_firewall.mode` | enum | learn | Firewall modu (learn/permissive/enforce) |
| `sql_firewall.enable_keyword_scan` | bool | true | Keyword tarama aktif/pasif |
| `sql_firewall.enable_regex_scan` | bool | true | Regex tarama aktif/pasif |
| `sql_firewall.enable_quiet_hours` | bool | false | Sessiz saatler aktif/pasif |
| `sql_firewall.quiet_hours_start` | string | NULL | Başlangıç (HH:MM) |
| `sql_firewall.quiet_hours_end` | string | NULL | Bitiş (HH:MM) |
| `sql_firewall.blacklisted_keywords` | string | NULL | Yasaklı kelimeler (virgülle ayrılmış) |
| `sql_firewall.enable_rate_limiting` | bool | false | Global rate limit |
| `sql_firewall.rate_limit_count` | int | 100 | Limit başına sorgu sayısı |
| `sql_firewall.rate_limit_seconds` | int | 60 | Limit penceresi (saniye) |
| `sql_firewall.select_limit_count` | int | 0 | SELECT limiti (0=sınırsız) |
| `sql_firewall.insert_limit_count` | int | 0 | INSERT limiti |
| `sql_firewall.update_limit_count` | int | 0 | UPDATE limiti |
| `sql_firewall.delete_limit_count` | int | 0 | DELETE limiti |

## 📊 Monitoring

### Activity Log'larını İzleme
```sql
-- Son 10 aktivite
SELECT log_time, role_name, command_type, action, LEFT(query_text, 50)
FROM sql_firewall_activity_log
ORDER BY log_time DESC
LIMIT 10;

-- Bloklanan sorgular
SELECT COUNT(*), role_name, command_type
FROM sql_firewall_activity_log
WHERE action LIKE '%BLOCKED%'
GROUP BY role_name, command_type;

-- Komut istatistikleri
SELECT 
    command_type,
    COUNT(*) as total,
    SUM(CASE WHEN action LIKE '%BLOCKED%' THEN 1 ELSE 0 END) as blocked,
    SUM(CASE WHEN action LIKE '%ALLOWED%' THEN 1 ELSE 0 END) as allowed
FROM sql_firewall_activity_log
GROUP BY command_type;
```

## 🐛 Debugging

```sql
-- Mevcut durumu göster
SELECT sql_firewall_status();

-- Tüm ayarları göster
SHOW sql_firewall.mode;
SHOW sql_firewall.enable_keyword_scan;

-- Log seviyesini artır
SET log_min_messages = DEBUG1;
```

## 🔧 Performans Tuning

### En İyi Uygulamalar
1. **Learn mode'u kısa süre kullanın** - Sadece initial setup için
2. **Regex pattern sayısını minimize edin** - Her pattern overhead ekler
3. **Activity log'u düzenli temizleyin** - Performans için
4. **Index'leri optimize edin** - Log tablolarında

### Log Temizleme
```sql
-- 30 günden eski log'ları temizle
DELETE FROM sql_firewall_activity_log 
WHERE log_time < NOW() - INTERVAL '30 days';

-- Vacuum çalıştır
VACUUM ANALYZE sql_firewall_activity_log;
```

## 📝 Bilinen Sınırlamalar

- Superuser sorgularını tamamen bloklamaz (güvenlik önlemi)
- Prepared statement'lar için sınırlı destek
- Multi-statement transaction'larda bazı edge case'ler

## 🤝 Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/amazing`)
3. Commit yapın (`git commit -m 'Add amazing feature'`)
4. Push edin (`git push origin feature/amazing`)
5. Pull Request açın

## 📄 Lisans

MIT License - Detaylar için LICENSE dosyasına bakın

## 🔗 Kaynaklar

- [pgrx Documentation](https://github.com/pgcentralfoundation/pgrx)
- [PostgreSQL Extension Guide](https://www.postgresql.org/docs/current/extend.html)
- [Rust Programming Language](https://www.rust-lang.org/)

## 💬 Destek

- GitHub Issues: Sorun bildirimi ve özellik istekleri için
- Kod İnceleme: `CODE_REVIEW.md` dosyasına bakın

---

**Not**: Bu extension production ortamında kullanılmadan önce kapsamlı test edilmelidir. Load testing ve security audit yapılması önerilir.
