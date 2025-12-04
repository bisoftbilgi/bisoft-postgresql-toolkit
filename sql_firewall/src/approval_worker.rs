// ============================================================================
// Background Worker - Process Pending Approvals
// ============================================================================
// Runs independently from main transactions, reads from shared memory queue
// and writes to database. Survives transaction rollbacks.
//
// ARCHITECTURE: Single worker processes approvals for ALL databases.
// Queue contains database_name, worker reconnects to appropriate database
// for each approval.

use crate::pending_approvals;
use crate::sql::{bool_arg, name_arg, text_arg};
use pgrx::bgworkers::{BackgroundWorker, SignalWakeFlags};
use pgrx::pg_sys;
use pgrx::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static WORKER_PAUSE_REQUESTED: AtomicBool = AtomicBool::new(false);
static WORKER_PID: AtomicI32 = AtomicI32::new(0);
static WORKER_STATUS: AtomicU32 = AtomicU32::new(WorkerStatus::Stopped as u32);

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerStatus {
    Stopped = 0,
    Starting = 1,
    Waiting = 2,
    Running = 3,
    ShuttingDown = 4,
}

#[no_mangle]
pub unsafe extern "C" fn approval_worker_main(_arg: pg_sys::Datum) {
    BackgroundWorker::attach_signal_handlers(SignalWakeFlags::SIGHUP | SignalWakeFlags::SIGTERM);
    WORKER_PID.store(pg_sys::MyProcPid, Ordering::SeqCst);
    set_status(WorkerStatus::Starting);
    wait_while_paused();

    // 🔥 FIX: Read OID from bgw_extra (set by Launcher), IGNORE GUC!
    let target_oid = unsafe {
        let bgw = pg_sys::MyBgworkerEntry;
        if bgw.is_null() {
            pgrx::error!("sql_firewall: worker MyBgworkerEntry is null!");
        }
        
        let extra_ptr = (*bgw).bgw_extra.as_ptr();
        let extra_cstr = std::ffi::CStr::from_ptr(extra_ptr);
        let extra_str = extra_cstr.to_string_lossy();
        
        pgrx::log!("sql_firewall: worker reading bgw_extra: '{}'", extra_str);
        
        match extra_str.parse::<u32>() {
            Ok(oid_u32) => {
                let oid = pg_sys::Oid::from(oid_u32);
                pgrx::log!("sql_firewall: worker connecting to DB OID: {}", oid);
                pg_sys::BackgroundWorkerInitializeConnectionByOid(oid, pg_sys::InvalidOid, 0);
                oid_u32
            }
            Err(e) => {
                pgrx::error!("sql_firewall: worker failed to parse OID from bgw_extra '{}': {}", extra_str, e);
            }
        }
    };
    
    pgrx::log!("sql_firewall: worker connected to DB OID: {}", target_oid);
    
    // Force SIGTERM to default handler (terminate process) to ensure clean shutdown
    unsafe {
        pg_sys::pqsignal(pg_sys::SIGTERM as i32, None);
        pg_sys::BackgroundWorkerUnblockSignals();
    }
    
    set_status(WorkerStatus::Running);

    pgrx::log!("sql_firewall: approval worker started (launcher-based, processes all databases)");

    // 🛡️ SECURITY CHECK: Is SQL Firewall extension installed in this database?
    let is_extension_active: Result<bool, spi::Error> = BackgroundWorker::transaction(|| {
        let exists = Spi::get_one::<i64>(
            "SELECT count(*) FROM pg_extension WHERE extname = 'sql_firewall_rs'"
        );
        Ok(exists.unwrap_or(Some(0)).unwrap_or(0) > 0)
    });
    
    if !is_extension_active.unwrap_or(false) {
        pgrx::log!("sql_firewall: Extension NOT installed in DB OID {}. Worker exiting gracefully.", target_oid);
        return;
    }
    
    pgrx::log!("sql_firewall: Extension found active in DB OID {}. Shield ON 🛡️", target_oid);

    // Initialize cursor to current write position (start reading from now)
    // Alternatively: start from 0 to process all existing events
    let mut my_cursor = pending_approvals::get_write_pos();
    pgrx::log!("sql_firewall: worker cursor initialized at {}", my_cursor);

    loop {
        if BackgroundWorker::sigterm_received() {
            pgrx::log!("sql_firewall: approval worker shutting down");
            break;
        }
        if pause_requested() {
            pgrx::log!("sql_firewall: approval worker pause requested - disconnecting");
            break;
        }

        let current_write_pos = pending_approvals::get_write_pos();

        // Check if we have new events to process
        if my_cursor < current_write_pos {
            // Backpressure protection: if we're too far behind, skip lost events
            let buffer_size = pending_approvals::get_capacity() as u64;
            if current_write_pos - my_cursor > buffer_size {
                pgrx::warning!(
                    "sql_firewall: worker too slow! Skipping {} lost events.",
                    current_write_pos - my_cursor - buffer_size
                );
                my_cursor = current_write_pos - buffer_size;
            }

            // Process events from cursor to current write position
            while my_cursor < current_write_pos {
                // Check for shutdown signal inside the loop
                if BackgroundWorker::sigterm_received() {
                    pgrx::log!("sql_firewall: approval worker shutting down (during processing)");
                    break;
                }

                // Read event at current cursor position
                let event = match pending_approvals::read_at_index(my_cursor) {
                    Some(e) => e,
                    None => {
                        my_cursor += 1;
                        continue;
                    }
                };

                // Process event based on type (launcher processes all databases)
                match event.event_type {
                pending_approvals::EventType::Approval => unsafe {
                    let approval_data = &event.data.approval;
                    let role_name = pending_approvals::string_from_bytes(&approval_data.role_name);
                    let command_type = pending_approvals::string_from_bytes(&approval_data.command_type);
                    let database_name = pending_approvals::string_from_bytes(&approval_data.database_name);

                    if let (Some(role), Some(cmd), Some(_db)) = (role_name, command_type, database_name) {
                        pgrx::log!(
                            "sql_firewall: worker processing approval - role={}, command={}",
                            role,
                            cmd
                        );

                        // Directly call SECURITY DEFINER function
                        // Note: Worker is connected to default database, approval table should exist there
                        let result = BackgroundWorker::transaction(|| {
                            // SECURITY FIX: Use prepared statement instead of string formatting
                            Spi::run_with_args(
                                "SELECT public.sql_firewall_internal_upsert_approval($1, $2, $3)",
                                &[
                                    name_arg(&role),
                                    text_arg(&cmd),
                                    bool_arg(approval_data.is_approved),
                                ]
                            )?;
                            
                            Ok::<(), spi::Error>(())
                        });

                        if let Err(e) = result {
                            pgrx::warning!(
                                "sql_firewall: worker failed to record approval for role={}, command={}: {:?}",
                                role, cmd, e
                            );
                        } else {
                            pgrx::log!(
                                "sql_firewall: recorded approval: role={}, command={}, is_approved={}",
                                role, cmd, approval_data.is_approved
                            );
                        }
                    } else {
                        pgrx::warning!("sql_firewall: worker failed to decode approval - role_name or command_type is None");
                    }
                },
                pending_approvals::EventType::BlockedQuery => unsafe {
                    let blocked_data = &event.data.blocked_query;
                    let role_name = pending_approvals::string_from_bytes(&blocked_data.role_name);
                    let database_name = pending_approvals::string_from_bytes(&blocked_data.database_name);
                    let query = pending_approvals::string_from_bytes(&blocked_data.query);
                    let app_name = pending_approvals::string_from_bytes(&blocked_data.application_name);
                    let client_addr = pending_approvals::string_from_bytes(&blocked_data.client_addr);
                    let command_type = pending_approvals::string_from_bytes(&blocked_data.command_type);
                    let reason = pending_approvals::string_from_bytes(&blocked_data.reason);

                    if let (Some(role), Some(db), Some(q), Some(app), Some(cmd), Some(rsn)) = 
                        (role_name, database_name, query, app_name, command_type, reason) {
                        
                        pgrx::log!("sql_firewall: worker processing blocked query: role={}, db={}, cmd={}", role, db, cmd);
                        
                        use crate::sql::text_arg;
                        
                        pgrx::log!("sql_firewall: worker preparing blocked query INSERT");
                        
                        // MUST use BackgroundWorker::transaction for SPI operations in background worker
                        let result = BackgroundWorker::transaction(|| {
                            // Real schema: query_text, username, database_name, client_info, block_reason
                            let query_sql = 
                                "INSERT INTO firewall.blocked_queries 
                                 (query_text, username, database_name, client_info, block_reason) 
                                 VALUES ($1, $2, $3, $4, $5)";
                            
                            // Build client_info string
                            let client_info = if let Some(addr) = client_addr {
                                format!("app={}, addr={}", app, addr)
                            } else {
                                format!("app={}", app)
                            };
                            
                            // Build block_reason string
                            let block_reason = format!("command={}, reason={}", cmd, rsn);
                            
                            pgrx::log!("sql_firewall: worker executing INSERT");
                            
                            // Use Spi::run_with_args inside BackgroundWorker::transaction
                            Spi::run_with_args(
                                query_sql, 
                                &[
                                    text_arg(&q),
                                    text_arg(&role),
                                    text_arg(&db),
                                    text_arg(&client_info),
                                    text_arg(&block_reason),
                                ]
                            )
                        });

                        match result {
                            Ok(_) => {
                                pgrx::log!("sql_firewall: successfully logged blocked query");
                            },
                            Err(e) => {
                                pgrx::warning!("sql_firewall: worker failed to insert blocked query: {:?}", e);
                            }
                        }
                    } else {
                        pgrx::warning!("sql_firewall: worker failed to decode blocked query - missing required fields");
                    }
                },
                pending_approvals::EventType::FingerprintHit => unsafe {
                    let fp_data = &event.data.fingerprint_hit;
                    let fingerprint = pending_approvals::string_from_bytes(&fp_data.fingerprint_hex);
                    let normalized = pending_approvals::string_from_bytes(&fp_data.normalized_query);
                    let role_name = pending_approvals::string_from_bytes(&fp_data.role_name);
                    let command_type = pending_approvals::string_from_bytes(&fp_data.command_type);
                    let sample_query = pending_approvals::string_from_bytes(&fp_data.sample_query);

                    if let (Some(fp), Some(norm), Some(role), Some(cmd), Some(sample)) = 
                        (fingerprint, normalized, role_name, command_type, sample_query) {
                        pgrx::log!("sql_firewall: worker recording fingerprint hit - fp={}", fp);

                        // SECURITY FIX: Use prepared statement for fingerprint recording
                        let result = BackgroundWorker::transaction(|| {
                            Spi::run_with_args(
                                "INSERT INTO public.sql_firewall_query_fingerprints 
                                 (fingerprint, normalized_query, role_name, command_type, sample_query, first_seen_at, last_seen_at, hit_count, is_approved)
                                 VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1, true)
                                 ON CONFLICT (fingerprint, role_name, command_type) 
                                 DO UPDATE SET 
                                   last_seen_at = CURRENT_TIMESTAMP,
                                   hit_count = sql_firewall_query_fingerprints.hit_count + 1",
                                &[
                                    text_arg(&fp),
                                    text_arg(&norm),
                                    name_arg(&role),
                                    text_arg(&cmd),
                                    text_arg(&sample),
                                ]
                            )?;
                            Ok::<(), spi::Error>(())
                        });

                        if let Err(e) = result {
                            pgrx::warning!("sql_firewall: worker failed to record fingerprint: {:?}", e);
                        } else {
                            pgrx::log!("sql_firewall: worker recorded fingerprint - fp={}", fp);
                        }
                    }
                },
            }

            // Advance cursor after processing event
            my_cursor += 1;
            }
        } else {
            // No new events - sleep briefly
            BackgroundWorker::wait_latch(Some(Duration::from_millis(100)));
            check_for_interrupts!();
        }
    }

    set_status(WorkerStatus::ShuttingDown);
    WORKER_PID.store(0, Ordering::SeqCst);
    pgrx::log!("sql_firewall: approval worker stopped");
    set_status(WorkerStatus::Stopped);
}

fn wait_while_paused() {
    if !pause_requested() {
        return;
    }

    pgrx::log!(
        "sql_firewall: approval worker paused - waiting before connecting to database"
    );
    loop {
        set_status(WorkerStatus::Waiting);
        if !pause_requested() || BackgroundWorker::sigterm_received() {
            break;
        }
        BackgroundWorker::wait_latch(Some(Duration::from_millis(200)));
    }
    set_status(WorkerStatus::Starting);
    if !BackgroundWorker::sigterm_received() {
        pgrx::log!("sql_firewall: approval worker resuming - connecting to database");
    }
}

fn pause_requested() -> bool {
    WORKER_PAUSE_REQUESTED.load(Ordering::SeqCst)
}

fn set_status(status: WorkerStatus) {
    WORKER_STATUS.store(status as u32, Ordering::SeqCst);
}

pub fn request_worker_pause() {
    WORKER_PAUSE_REQUESTED.store(true, Ordering::SeqCst);
}

pub fn request_worker_resume() {
    WORKER_PAUSE_REQUESTED.store(false, Ordering::SeqCst);
}

pub fn worker_status() -> WorkerStatus {
    match WORKER_STATUS.load(Ordering::SeqCst) {
        value if value == WorkerStatus::Starting as u32 => WorkerStatus::Starting,
        value if value == WorkerStatus::Waiting as u32 => WorkerStatus::Waiting,
        value if value == WorkerStatus::Running as u32 => WorkerStatus::Running,
        value if value == WorkerStatus::ShuttingDown as u32 => WorkerStatus::ShuttingDown,
        _ => WorkerStatus::Stopped,
    }
}

impl WorkerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            WorkerStatus::Stopped => "stopped",
            WorkerStatus::Starting => "starting",
            WorkerStatus::Waiting => "paused",
            WorkerStatus::Running => "running",
            WorkerStatus::ShuttingDown => "stopping",
        }
    }
}

pub fn wait_for_worker_states(targets: &[WorkerStatus], timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        let status = worker_status();
        if targets.contains(&status) {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

// Note: Launcher-based worker doesn't need liveness check
// Worker is managed by launcher lifecycle

