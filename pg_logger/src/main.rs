use chrono::{Datelike, Local};
use glob::glob;
use polars::prelude::*;
use regex::Regex;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::SeekFrom;
use std::path::{PathBuf};
use std::sync::{Arc, Mutex};
use tokio::fs as afs;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

const SINCEDB_DIR: &str = "./sincedb/";
const OUTPUT_DIR: &str = "./output/";
const LOG_PATTERN: &str = "/var/log/postgresql/postgresql*.log";


#[derive(Clone, Copy)]
enum OutputMode {
    Parquet,
    Postgresql,
}

#[derive(Deserialize)]
struct RawAppConfig {
    output_mode: String,
    db_url: Option<String>,
    db_table: Option<String>,
    hostname: Option<String>,
    ip: Option<String>,
    flush_interval_secs: Option<u64>,
    batch_size: Option<usize>,
}

struct AppConfig {
    mode: OutputMode,
    db_url: Option<String>,
    db_table: String,
    hostname: String,
    ip: String,
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

    let postgres_pool = match output_mode {
        OutputMode::Postgresql => {
            let db_url = app_config
                .db_url
                .as_deref()
                .ok_or("output_mode=postgresql  db_url should be given")?;
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(db_url)
                .await?;
            ensure_postgres_table(&pool, &app_config.db_table).await?;
            Some(pool)
        }
        OutputMode::Parquet => None,
    };
    let db_table = app_config.db_table.clone();
    let hostname = app_config.hostname.clone();
    let ip = app_config.ip.clone();

    let (tx, mut rx) = mpsc::channel::<LogEntry>(10000);

    // Consumer: output_mode'a gore hedefe yaz
    tokio::spawn(async move {
        let mut buffer: Vec<LogEntry> = Vec::new();
        let mut last_flush = std::time::Instant::now();

        loop {
            let received = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
            if let Ok(Some(entry)) = received {
                buffer.push(entry);
            }

            if !buffer.is_empty()
                && (last_flush.elapsed() >= Duration::from_secs(flush_interval_secs)
                    || buffer.len() >= batch_size)
            {
                match output_mode {
                    OutputMode::Parquet => {
                        let _ = flush_common_parquet(&mut buffer);
                    }
                    OutputMode::Postgresql => {
                        if let Some(pool) = &postgres_pool {
                            let _ = flush_postgres(pool, &db_table, &mut buffer).await;
                        }
                    }
                }
                last_flush = std::time::Instant::now();
            }
        }
    });

    // Producer: dinamik dosya kesfi
    let tracked_files = Arc::new(Mutex::new(HashSet::<PathBuf>::new()));
    let re = Regex::new(r"(?x)^(?P<ts>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d+).*?user=(?P<user>[^,]+),db=(?P<db>[^,]+).*?LOG:\s+(?P<msg>(?s).*)").unwrap();

    loop {
        if let Ok(entries) = glob(LOG_PATTERN) {
            for entry in entries.filter_map(|e| e.ok()) {
                let mut tracked = tracked_files.lock().unwrap();
                if !tracked.contains(&entry) {
                    println!("Found: {:?}", entry);
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
    let raw: RawAppConfig = Config::builder()
        .add_source(ConfigFile::with_name("config"))
        .build()?
        .try_deserialize()?;

    let mode = match raw.output_mode.to_lowercase().as_str() {
        "parquet" => OutputMode::Parquet,
        "postgresql" | "postgres" => OutputMode::Postgresql,
        other => {
            return Err(format!("Invalid output_mode: {other}. Possible values: parquet/postgresql").into())
        }
    };

    let db_table = raw.db_table.unwrap_or_else(|| "postgres_logs".to_string());
    validate_table_name(&db_table)?;

    Ok(AppConfig {
        mode,
        db_url: raw.db_url,
        db_table,
        hostname: raw.hostname.unwrap_or_else(|| "unknown-host".to_string()),
        ip: raw.ip.unwrap_or_else(|| "0.0.0.0".to_string()),
        flush_interval_secs: raw.flush_interval_secs.unwrap_or(10),
        batch_size: raw.batch_size.unwrap_or(1000),
    })
}

fn validate_table_name(table_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let valid = Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$")?;
    if !valid.is_match(table_name) {
        return Err(format!("Invalid db_table: {table_name}").into());
    }
    Ok(())
}

async fn ensure_postgres_table(pool: &PgPool, table_name: &str) -> Result<(), sqlx::Error> {
    let stmt = format!(
        "CREATE TABLE IF NOT EXISTS {table_name} (
            id BIGSERIAL PRIMARY KEY,
            log_timestamp TEXT NOT NULL,
            user_name TEXT NOT NULL,
            database_name TEXT NOT NULL,
            hostname TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            message TEXT NOT NULL,
            inserted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )"
    );
    sqlx::query(&stmt).execute(pool).await?;
    Ok(())
}

async fn flush_postgres(
    pool: &PgPool,
    table_name: &str,
    entries: &mut Vec<LogEntry>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let insert_stmt = format!(
        "INSERT INTO {table_name} (log_timestamp, user_name, database_name, hostname, ip_address, message) VALUES ($1, $2, $3, $4, $5, $6)"
    );

    for entry in entries.iter() {
        sqlx::query(&insert_stmt)
            .bind(&entry.timestamp)
            .bind(&entry.user)
            .bind(&entry.db)
            .bind(&entry.hostname)
            .bind(&entry.ip)
            .bind(&entry.message)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;
    println!("Written to PostgreSQL: {} records -> {}", entries.len(), table_name);
    entries.clear();
    Ok(())
}

async fn tail_file(
    path: PathBuf,
    re: Regex,
    tx: mpsc::Sender<LogEntry>,
    hostname: String,
    ip: String,
) -> tokio::io::Result<()> {
    let file_name = path.file_name().unwrap().to_str().unwrap();
    let sincedb_path = format!("{}{}.offset", SINCEDB_DIR, file_name);

    let mut current_offset = fs::read_to_string(&sincedb_path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);

    let file = afs::File::open(&path).await?;
    let mut reader = BufReader::new(file);

    // logrotate truncate kontrolu
    let meta = afs::metadata(&path).await?;
    if meta.len() < current_offset {
        println!("Truncate detected ({:?}), resetting.", path);
        current_offset = 0;
    }
    reader.seek(SeekFrom::Start(current_offset)).await?;

    let mut line = String::new();
    let mut current_log = String::new();
    let ts_start_re = Regex::new(r"^\d{4}-\d{2}-\d{2}").unwrap();

    loop {
        line.clear();
        let len = reader.read_line(&mut line).await?;

        if len == 0 {
            if let Ok(m) = afs::metadata(&path).await {
                if m.len() < current_offset {
                    println!("File reset detected: {:?}", path);
                    current_offset = 0;
                    reader.seek(SeekFrom::Start(0)).await?;
                    continue;
                }
            }
            sleep(Duration::from_millis(500)).await;
            continue;
        }

        let trimmed = line.trim_end();
        if ts_start_re.is_match(trimmed) {
            if !current_log.is_empty() {
                if let Some(caps) = re.captures(&current_log) {
                    let _ = tx
                        .send(LogEntry {
                            timestamp: caps["ts"].to_string(),
                            user: caps["user"].to_string(),
                            db: caps["db"].to_string(),
                            hostname: hostname.clone(),
                            ip: ip.clone(),
                            message: caps["msg"].replace('\n', " ").trim().to_string(),
                        })
                        .await;
                }
            }
            current_log = trimmed.to_string();
        } else {
            current_log.push('\n');
            current_log.push_str(trimmed);
        }

        current_offset += len as u64;
        let _ = afs::write(&sincedb_path, current_offset.to_string()).await;
    }
}

fn flush_common_parquet(entries: &mut Vec<LogEntry>) -> Result<(), Box<dyn std::error::Error>> {
    let now = Local::now();
    let export_path = format!("{}{}/{:02}/{:02}/", OUTPUT_DIR, now.year(), now.month(), now.day());
    fs::create_dir_all(&export_path)?;

    let file_name = format!("common_logs_{}.parquet", now.format("%H%M%S"));
    let full_path = PathBuf::from(export_path).join(file_name);

    let ts: Vec<&str> = entries.iter().map(|e| e.timestamp.as_str()).collect();
    let us: Vec<&str> = entries.iter().map(|e| e.user.as_str()).collect();
    let db: Vec<&str> = entries.iter().map(|e| e.db.as_str()).collect();
    let host: Vec<&str> = entries.iter().map(|e| e.hostname.as_str()).collect();
    let ip: Vec<&str> = entries.iter().map(|e| e.ip.as_str()).collect();
    let msg: Vec<&str> = entries.iter().map(|e| e.message.as_str()).collect();

    let mut df = DataFrame::new(vec![
        Series::new("timestamp", ts),
        Series::new("user", us),
        Series::new("database", db),
        Series::new("hostname", host),
        Series::new("ip", ip),
        Series::new("message", msg),
    ])?;

    let file = File::create(&full_path)?;
    ParquetWriter::new(file)
        .with_compression(ParquetCompression::Snappy)
        .finish(&mut df)?;

    println!("Written to Parquet: {} records -> {:?}", entries.len(), full_path);
    entries.clear();
    Ok(())
}
