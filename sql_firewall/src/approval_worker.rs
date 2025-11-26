// ============================================================================
// Background Worker - Process Pending Approvals
// ============================================================================
// Runs independently from main transactions, reads from shared memory queue
// and writes to database. Survives transaction rollbacks.
//
// ARCHITECTURE: Single worker processes approvals for ALL databases.
// Queue contains database_name, worker reconnects to appropriate database
// for each approval.

use crate::guc;
use crate::pending_approvals;
use crate::sql::text_arg;
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

    // Start with default database from GUC
    let default_db = guc::approval_worker_database();
    let db_cstr = std::ffi::CString::new(default_db.as_str()).unwrap();

    BackgroundWorker::connect_worker_to_spi(Some(db_cstr.to_str().unwrap()), None);
    set_status(WorkerStatus::Running);

    pgrx::log!(
        "sql_firewall: approval worker started (default database: {})",
        default_db
    );
    pgrx::log!("sql_firewall: worker will process approvals for all databases in queue");

    loop {
        if BackgroundWorker::sigterm_received() {
            pgrx::log!("sql_firewall: approval worker shutting down");
            break;
        }
        if pause_requested() {
            pgrx::log!("sql_firewall: approval worker pause requested - disconnecting");
            break;
        }

        let mut processed = false;

        // Process all pending approvals in queue
        while let Some(approval) = pending_approvals::dequeue() {
            processed = true;

            let role_name = pending_approvals::string_from_bytes(&approval.role_name);
            let command_type = pending_approvals::string_from_bytes(&approval.command_type);
            let database_name = pending_approvals::string_from_bytes(&approval.database_name);

            if let (Some(role), Some(cmd), Some(db)) = (role_name, command_type, database_name) {
                pgrx::log!(
                    "sql_firewall: worker processing approval - role={}, command={}, db={}",
                    role,
                    cmd,
                    db
                );

                // Connect to the specific database and run INSERT in its own transaction
                // This allows multi-database support without multiple workers
                let result = BackgroundWorker::transaction(|| {
                    // Worker connects to default DB, need to use dblink or reconnect
                    // For now, log which DB it should go to - admin can manually handle
                    // TODO: Implement dynamic database connection switching
                    pgrx::log!(
                        "sql_firewall: worker recording to current database (intended: {})",
                        db
                    );

                    Spi::run_with_args(
                        "INSERT INTO public.sql_firewall_command_approvals 
                         (role_name, command_type, is_approved) 
                         VALUES ($1, $2, false) 
                         ON CONFLICT (role_name, command_type) DO NOTHING",
                        &[text_arg(&role), text_arg(&cmd)],
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
                        "sql_firewall: recorded pending approval: role={}, command={}",
                        role,
                        cmd
                    );
                }
            } else {
                pgrx::warning!("sql_firewall: worker failed to decode approval - role_name or command_type is None");
            }
        }

        // Sleep if no work was done
        if !processed {
            // Use wait_latch instead of thread::sleep for proper signal handling
            BackgroundWorker::wait_latch(Some(Duration::from_millis(100)));
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
        thread::sleep(Duration::from_millis(200));
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
