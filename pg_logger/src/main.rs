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

struct LogEntry {
    timestamp: String,
    user: String,
    db: String,
    message: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(SINCEDB_DIR)?;
    fs::create_dir_all(OUTPUT_DIR)?;

    let (tx, mut rx) = mpsc::channel::<LogEntry>(10000);

    // --- CONSUMER: MERKEZİ PARQUET YAZICI ---
    tokio::spawn(async move {
        let mut ts = Vec::new(); let mut us = Vec::new();
        let mut db = Vec::new(); let mut msg = Vec::new();
        let mut last_flush = std::time::Instant::now();

        loop {
            let received = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
            if let Ok(Some(entry)) = received {
                ts.push(entry.timestamp); us.push(entry.user);
                db.push(entry.db); msg.push(entry.message);
            }

            if !ts.is_empty() && (last_flush.elapsed() >= Duration::from_secs(10) || ts.len() >= 1000) {
                let _ = flush_common_parquet(&mut ts, &mut us, &mut db, &mut msg);
                last_flush = std::time::Instant::now();
            }
        }
    });

    // --- PRODUCER: DİNAMİK DOSYA KEŞİF ---
    let tracked_files = Arc::new(Mutex::new(HashSet::<PathBuf>::new()));
    let re = Regex::new(r"(?x)^(?P<ts>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d+).*?user=(?P<user>[^,]+),db=(?P<db>[^,]+).*?LOG:\s+(?P<msg>(?s).*)").unwrap();

    loop {
        if let Ok(entries) = glob(LOG_PATTERN) {
            for entry in entries.filter_map(|e| e.ok()) {
                let mut tracked = tracked_files.lock().unwrap();
                if !tracked.contains(&entry) {
                    println!("🔎 Keşfedildi: {:?}", entry);
                    tracked.insert(entry.clone());
                    let tx_c = tx.clone(); let re_c = re.clone(); let path_c = entry.clone();
                    tokio::spawn(async move {
                        let _ = tail_file(path_c, re_c, tx_c).await;
                    });
                }
            }
        }
        sleep(Duration::from_secs(10)).await;
    }
}

async fn tail_file(path: PathBuf, re: Regex, tx: mpsc::Sender<LogEntry>) -> tokio::io::Result<()> {
    let file_name = path.file_name().unwrap().to_str().unwrap();
    let sincedb_path = format!("{}{}.offset", SINCEDB_DIR, file_name);

    let mut current_offset = fs::read_to_string(&sincedb_path).ok()
        .and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0);

    let file = afs::File::open(&path).await?;
    let mut reader = BufReader::new(file);

    // --- LOGROTATE KONTROLÜ (TRUNCATE) ---
    let meta = afs::metadata(&path).await?;
    if meta.len() < current_offset {
        println!("🔄 Truncate tespit edildi ({:?}), başa dönülüyor.", path);
        current_offset = 0;
    }
    reader.seek(SeekFrom::Start(current_offset)).await?;

    let mut line = String::new();
    let mut current_log = String::new();
    let ts_start_re = Regex::new(r"^\d{4}-\d{2}-\d{2}").unwrap();

    loop {
        line.clear();
        let len = reader.read_line(&mut line).await?;

        // Dosya boyutu kontrolü (Dosya aniden boşaltılırsa)
        if len == 0 {
            if let Ok(m) = afs::metadata(&path).await {
                if m.len() < current_offset {
                    println!("🔄 Dosya sıfırlandı: {:?}", path);
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
                    let _ = tx.send(LogEntry {
                        timestamp: caps["ts"].to_string(),
                        user: caps["user"].to_string(),
                        db: caps["db"].to_string(),
                        message: caps["msg"].replace('\n', " ").trim().to_string(),
                    }).await;
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

fn flush_common_parquet(ts: &mut Vec<String>, us: &mut Vec<String>, db: &mut Vec<String>, msg: &mut Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let now = Local::now();
    let export_path = format!("{}{}/{:02}/{:02}/", OUTPUT_DIR, now.year(), now.month(), now.day());
    fs::create_dir_all(&export_path)?;

    let file_name = format!("common_logs_{}.parquet", now.format("%H%M%S"));
    let full_path = PathBuf::from(export_path).join(file_name);

    let mut df = DataFrame::new(vec![
        Series::new("timestamp", ts.as_slice()),
        Series::new("user", us.as_slice()),
        Series::new("database", db.as_slice()),
        Series::new("message", msg.as_slice()),
    ])?;

    let file = File::create(&full_path)?;
    ParquetWriter::new(file).with_compression(ParquetCompression::Snappy).finish(&mut df)?;

    println!("💾 Mühürlendi: {} kayıt -> {:?}", ts.len(), full_path);
    ts.clear(); us.clear(); db.clear(); msg.clear();
    Ok(())
}