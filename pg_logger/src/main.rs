use chrono::{Datelike, Local};
use config::{Config, File as ConfigFile};
use glob::glob;
use polars::prelude::*;
use regex::Regex;
use serde::Deserialize;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::postgres::PgPoolOptions;
use sqlx::{MySqlPool, PgPool};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::SeekFrom;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::fs as afs;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

const SINCEDB_DIR: &str = "./sincedb/";
const OUTPUT_DIR: &str = "./output/";

#[derive(Clone, Copy)]
enum OutputMode {
    Parquet,
    Postgresql,
    Mysql,
}

#[derive(Deserialize)]
struct RawAppConfig {
    output_mode: String,
    db_url: Option<String>,
    db_table: Option<String>,
    hostname: Option<String>,
    ip: Option<String>,
    log_pattern: Option<String>, // DINAMIK LOG DOSYASI
    flush_interval_secs: Option<u64>,
    batch_size: Option<usize>,
}

struct AppConfig {
    mode: OutputMode,
    db_url: Option<String>,
    db_table: String,
    hostname: String,
    ip: String,
    log_pattern: String,
    flush_interval_secs: u64,
    batch_size: usize,
}

#[derive(Clone)]
struct LogEntry {
    timestamp: String,
    user: String,
    db: String,
    hostname: String,
    ip: String,
    message: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(SINCEDB_DIR)?;
    fs::create_dir_all(OUTPUT_DIR)?;

    let app_config = load_config()?;
    let output_mode = app_config.mode;
    let flush_interval_secs = app_config.flush_interval_secs;
    let batch_size = app_config.batch_size;
    let log_pattern = app_config.log_pattern.clone();

    let postgres_pool = match output_mode {
        OutputMode::Postgresql => {
            let db_url = app_config.db_url.as_deref().ok_or("db_url zorunlu")?;
            let pool = PgPoolOptions::new().max_connections(5).connect(db_url).await?;
            ensure_postgres_tables(&pool).await?; // YENI DDL FONKSIYONU
            Some(pool)
        }
        _ => None,
    };

    let mysql_pool = match output_mode {
        OutputMode::Mysql => {
            let db_url = app_config.db_url.as_deref().ok_or("db_url zorunlu")?;
            let pool = MySqlPoolOptions::new().max_connections(5).connect(db_url).await?;
            ensure_mysql_table(&pool, &app_config.db_table).await?;
            Some(pool)
        }
        _ => None,
    };

    let hostname = app_config.hostname.clone();
    let ip = app_config.ip.clone();

    let (tx, mut rx) = mpsc::channel::<LogEntry>(10000);

    tokio::spawn(async move {
        let mut buffer: Vec<LogEntry> = Vec::new();
        let mut last_flush = std::time::Instant::now();

        loop {
            let received = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
            if let Ok(Some(entry)) = received {
                buffer.push(entry);
            }

            if !buffer.is_empty() && (last_flush.elapsed() >= Duration::from_secs(flush_interval_secs) || buffer.len() >= batch_size) {
                match output_mode {
                    OutputMode::Parquet => { let _ = flush_common_parquet(&mut buffer); }
                    OutputMode::Postgresql => {
                        if let Some(pool) = &postgres_pool {
                            let _ = flush_postgres_split(pool, &mut buffer).await;
                        }
                    }
                    OutputMode::Mysql => {
                        if let Some(pool) = &mysql_pool {
                            let _ = flush_mysql(pool, "mysql_logs", &mut buffer).await;
                        }
                    }
                }
                last_flush = std::time::Instant::now();
            }
        }
    });

    let tracked_files = Arc::new(Mutex::new(HashSet::<PathBuf>::new()));
    let re = Regex::new(r"(?x)^(?P<ts>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d+).*?user=(?P<user>[^,]+),db=(?P<db>[^,]+).*?LOG:\s+(?P<msg>(?s).*)").unwrap();

    loop {
        if let Ok(entries) = glob(&log_pattern) {
            for entry in entries.filter_map(|e| e.ok()) {
                let mut tracked = tracked_files.lock().unwrap();
                if !tracked.contains(&entry) {
                    println!("PostgreSQL Log Kesfedildi: {:?}", entry);
                    tracked.insert(entry.clone());
                    let tx_c = tx.clone();
                    let re_c = re.clone();
                    let path_c = entry.clone();
                    let hostname_c = hostname.clone();
                    let ip_c = ip.clone();
                    tokio::spawn(async move {
                        let _ = tail_file(path_c, re_c, tx_c, hostname_c, ip_c).await;
                    });
                }
            }
        }
        sleep(Duration::from_secs(10)).await;
    }
}

fn load_config() -> Result<AppConfig, Box<dyn std::error::Error>> {
    let raw: RawAppConfig = Config::builder().add_source(ConfigFile::with_name("config")).build()?.try_deserialize()?;
    let mode = match raw.output_mode.to_lowercase().as_str() {
        "parquet" => OutputMode::Parquet,
        "postgresql" | "postgres" => OutputMode::Postgresql,
        "mysql" | "mariadb" => OutputMode::Mysql,
        other => return Err(format!("Gecersiz mode: {other}").into()),
    };

    Ok(AppConfig {
        mode,
        db_url: raw.db_url,
        db_table: raw.db_table.unwrap_or_else(|| "postgres_logs".to_string()),
        hostname: raw.hostname.unwrap_or_else(|| "unknown-host".to_string()),
        ip: raw.ip.unwrap_or_else(|| "0.0.0.0".to_string()),
        log_pattern: raw.log_pattern.unwrap_or_else(|| "/var/log/postgresql/postgresql*.log".to_string()),
        flush_interval_secs: raw.flush_interval_secs.unwrap_or(10),
        batch_size: raw.batch_size.unwrap_or(1000),
    })
}

async fn ensure_postgres_tables(pool: &PgPool) -> Result<(), sqlx::Error> {
    let conn_stmt = "CREATE TABLE IF NOT EXISTS connection_logs (
        id BIGSERIAL PRIMARY KEY, log_time TIMESTAMPTZ NOT NULL, username TEXT, database_name TEXT, client_ip TEXT, action TEXT, cluster_name TEXT, server_name TEXT, server_ip TEXT, application_name TEXT
    )";
    let audit_stmt = "CREATE TABLE IF NOT EXISTS audit_logs (
        id BIGSERIAL PRIMARY KEY, log_time TIMESTAMPTZ NOT NULL, username TEXT, database_name TEXT, session_id TEXT, statement_id TEXT, audit_type TEXT, statement_text TEXT, command TEXT, object_type TEXT, object_name TEXT, cluster_name TEXT, server_name TEXT, server_ip TEXT, client_ip TEXT, application_name TEXT
    )";
    sqlx::query(conn_stmt).execute(pool).await?;
    sqlx::query(audit_stmt).execute(pool).await?;
    Ok(())
}


async fn flush_postgres_split(pool: &PgPool, entries: &mut Vec<LogEntry>) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let conn_insert = "INSERT INTO connection_logs (log_time, username, database_name, server_name, action) VALUES ($1::timestamptz, $2, $3, $4, $5)";
    let audit_insert = "INSERT INTO audit_logs (log_time, username, database_name, server_name, statement_text, audit_type) VALUES ($1::timestamptz, $2, $3, $4, $5, 'pgAudit')";

    for entry in entries.iter() {
        if entry.message.contains("AUDIT:") {
            sqlx::query(audit_insert).bind(&entry.timestamp).bind(&entry.user).bind(&entry.db).bind(&entry.hostname).bind(&entry.message).execute(&mut *tx).await?;
        } else {
            sqlx::query(conn_insert).bind(&entry.timestamp).bind(&entry.user).bind(&entry.db).bind(&entry.hostname).bind(&entry.message).execute(&mut *tx).await?;
        }
    }
    tx.commit().await?;
    println!("PostgreSQL'e yazildi: {} kayit (Split Mode)", entries.len());
    entries.clear();
    Ok(())
}

async fn ensure_mysql_table(pool: &MySqlPool, table_name: &str) -> Result<(), sqlx::Error> {
    let stmt = format!("CREATE TABLE IF NOT EXISTS {table_name} (id BIGINT AUTO_INCREMENT PRIMARY KEY, log_timestamp varchar(100), user_name varchar(100), database_name varchar(100), hostname varchar(100), ip_address varchar(100), message varchar(1000), inserted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
    sqlx::query(&stmt).execute(pool).await?; Ok(())
}
async fn flush_mysql(pool: &MySqlPool, table_name: &str, entries: &mut Vec<LogEntry>) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let insert_stmt = format!("INSERT INTO {table_name} (log_timestamp, user_name, database_name, hostname, ip_address, message) VALUES (?, ?, ?, ?, ?, ?)");
    for entry in entries.iter() { sqlx::query(&insert_stmt).bind(&entry.timestamp).bind(&entry.user).bind(&entry.db).bind(&entry.hostname).bind(&entry.ip).bind(&entry.message).execute(&mut *tx).await?; }
    tx.commit().await?; println!("MySQL'e yazildi: {} kayit", entries.len()); entries.clear(); Ok(())
}
fn flush_common_parquet(entries: &mut Vec<LogEntry>) -> Result<(), Box<dyn std::error::Error>> { entries.clear(); Ok(()) } // Yer kaplamasin diye simdilik bosalttik

async fn tail_file(path: PathBuf, re: Regex, tx: mpsc::Sender<LogEntry>, hostname: String, ip: String) -> tokio::io::Result<()> {
    let file_name = path.file_name().unwrap().to_str().unwrap();
    let sincedb_path = format!("{}{}.offset", SINCEDB_DIR, file_name);
    let mut current_offset = fs::read_to_string(&sincedb_path).ok().and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0);
    let file = afs::File::open(&path).await?;
    let mut reader = BufReader::new(file);
    let meta = afs::metadata(&path).await?;
    if meta.len() < current_offset { current_offset = 0; }
    reader.seek(SeekFrom::Start(current_offset)).await?;
    let mut line = String::new(); let mut current_log = String::new();
    let ts_start_re = Regex::new(r"^\d{4}-\d{2}-\d{2}").unwrap();

    loop {
        line.clear();
        let len = reader.read_line(&mut line).await?;
        if len == 0 { sleep(Duration::from_millis(500)).await; continue; }
        let trimmed = line.trim_end();
        if ts_start_re.is_match(trimmed) {
            if !current_log.is_empty() {
                if let Some(caps) = re.captures(&current_log) {
                    let _ = tx.send(LogEntry { timestamp: caps["ts"].to_string(), user: caps["user"].to_string(), db: caps["db"].to_string(), hostname: hostname.clone(), ip: ip.clone(), message: caps["msg"].replace('\n', " ").trim().to_string() }).await;
                }
            }
            current_log = trimmed.to_string();
        } else {
            current_log.push('\n'); current_log.push_str(trimmed);
        }
        current_offset += len as u64;
        let _ = afs::write(&sincedb_path, current_offset.to_string()).await;
    }
}
