use regex::Regex;
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::collections::HashSet;
use std::fs;
use std::io::SeekFrom;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::fs as afs;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::time::{sleep, Duration};
use glob::glob;
use config::{Config, File as ConfigFile};

const SINCEDB_DIR: &str = "./sincedb/";

#[derive(Deserialize)]
struct AppConfig {
    db_url: String,
    hostname: String,
    log_pattern: String,
}

#[derive(Clone)]
struct ExtractedLog {
    timestamp: String,
    user: String,
    db: String,
    level: String,
    message: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(SINCEDB_DIR)?;

    // Config Yükle
    let raw_config = Config::builder().add_source(ConfigFile::with_name("config")).build()?;
    let app_config: AppConfig = raw_config.try_deserialize()?;

    // Veritabanı Havuzu
    let pool = PgPoolOptions::new().max_connections(5).connect(&app_config.db_url).await?;
    ensure_tables(&pool).await?;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<ExtractedLog>(10000);
    let pool_clone = pool.clone();
    let hostname_clone = app_config.hostname.clone();

    // Consumer: Logları İkiye Ayırıp Veritabanına Yazan Zeki Kısım
    tokio::spawn(async move {
        loop {
            if let Some(entry) = rx.recv().await {
                if entry.level == "ERROR" || entry.level == "FATAL" || entry.level == "PANIC" {
                    let _ = insert_error_log(&pool_clone, &entry, &hostname_clone).await;
                } else if entry.message.contains("duration:") && entry.message.contains("plan:") {
                    let _ = insert_auto_explain_log(&pool_clone, &entry, &hostname_clone).await;
                }
            }
        }
    });

    // Producer: Dinamik Dosya Tarayıcı (Aynı pg_logger mantığı)
    let tracked_files = Arc::new(Mutex::new(HashSet::<PathBuf>::new()));
    
    // PostgreSQL log yapısı için Regex
    let re = Regex::new(r"(?x)^(?P<ts>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d+\s[A-Z]+).*?user=(?P<user>[^,]*),db=(?P<db>[^,]*).*?(?P<level>ERROR|FATAL|PANIC|LOG|STATEMENT):\s+(?P<msg>(?s).*)").unwrap();

    println!("🚀 pg_logs_extractor (Rust Edition) başlatıldı! Loglar bekleniyor...");

    loop {
        if let Ok(entries) = glob(&app_config.log_pattern) {
            for entry in entries.filter_map(|e| e.ok()) {
                let mut tracked = tracked_files.lock().unwrap();
                if !tracked.contains(&entry) {
                    println!("Taranıyor: {:?}", entry);
                    tracked.insert(entry.clone());
                    let tx_c = tx.clone();
                    let re_c = re.clone();
                    tokio::spawn(async move {
                        let _ = tail_file(entry, re_c, tx_c).await;
                    });
                }
            }
        }
        sleep(Duration::from_secs(10)).await;
    }
}

// Yeni DDL Tabloları
async fn ensure_tables(pool: &PgPool) -> Result<(), sqlx::Error> {
    let error_stmt = "CREATE TABLE IF NOT EXISTS error_logs (id BIGSERIAL PRIMARY KEY, log_time TIMESTAMPTZ, username TEXT, database_name TEXT, error_level TEXT, message TEXT, server_name TEXT)";
    let explain_stmt = "CREATE TABLE IF NOT EXISTS auto_explain_logs (id BIGSERIAL PRIMARY KEY, log_time TIMESTAMPTZ, username TEXT, database_name TEXT, duration_ms REAL, query_plan TEXT, server_name TEXT)";
    sqlx::query(error_stmt).execute(pool).await?;
    sqlx::query(explain_stmt).execute(pool).await?;
    Ok(())
}

async fn insert_error_log(pool: &PgPool, entry: &ExtractedLog, server_name: &str) -> Result<(), sqlx::Error> {
    let q = "INSERT INTO error_logs (log_time, username, database_name, error_level, message, server_name) VALUES ($1::timestamptz, $2, $3, $4, $5, $6)";
    sqlx::query(q).bind(&entry.timestamp).bind(&entry.user).bind(&entry.db).bind(&entry.level).bind(&entry.message).bind(server_name).execute(pool).await?;
    println!("🚨 ERROR log yakalandı ve yazıldı!");
    Ok(())
}

async fn insert_auto_explain_log(pool: &PgPool, entry: &ExtractedLog, server_name: &str) -> Result<(), sqlx::Error> {
    // Mesajın içinden milisaniyeyi çeken regex
    let ms_re = Regex::new(r"duration:\s*([\d\.]+)\s*ms").unwrap();
    let duration: f32 = ms_re.captures(&entry.message)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse().ok())
        .unwrap_or(0.0);

    let q = "INSERT INTO auto_explain_logs (log_time, username, database_name, duration_ms, query_plan, server_name) VALUES ($1::timestamptz, $2, $3, $4, $5, $6)";
    sqlx::query(q).bind(&entry.timestamp).bind(&entry.user).bind(&entry.db).bind(duration).bind(&entry.message).bind(server_name).execute(pool).await?;
    println!("⏱️ Auto_Explain log yakalandı! Süre: {} ms", duration);
    Ok(())
}

// Dosya Okuyucu
async fn tail_file(path: PathBuf, re: Regex, tx: tokio::sync::mpsc::Sender<ExtractedLog>) -> tokio::io::Result<()> {
    let mut current_offset = 0;
    let file = afs::File::open(&path).await?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let mut current_log = String::new();
    let ts_start_re = Regex::new(r"^\d{4}-\d{2}-\d{2}").unwrap();

    loop {
        line.clear();
        let len = reader.read_line(&mut line).await?;
        if len == 0 { sleep(Duration::from_millis(500)).await; continue; }
        
        let trimmed = line.trim_end();
        if ts_start_re.is_match(trimmed) {
            if !current_log.is_empty() {
                if let Some(caps) = re.captures(&current_log) {
                    let _ = tx.send(ExtractedLog {
                        timestamp: caps["ts"].to_string(),
                        user: caps["user"].to_string(),
                        db: caps["db"].to_string(),
                        level: caps["level"].to_string(),
                        message: caps["msg"].replace('\n', " \n ").trim().to_string(),
                    }).await;
                }
            }
            current_log = trimmed.to_string();
        } else {
            current_log.push('\n');
            current_log.push_str(trimmed);
        }
        current_offset += len as u64;
    }
}
