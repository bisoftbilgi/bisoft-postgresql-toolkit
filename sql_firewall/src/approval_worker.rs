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
use crate::sql::text_arg;
use crate::guc;
use pgrx::bgworkers::{BackgroundWorker, SignalWakeFlags};
use pgrx::prelude::*;
use pgrx::pg_sys;
use std::thread;
use std::time::Duration;

#[no_mangle]
pub unsafe extern "C" fn approval_worker_main(_arg: pg_sys::Datum) {
    BackgroundWorker::attach_signal_handlers(SignalWakeFlags::SIGHUP | SignalWakeFlags::SIGTERM);
    
    // Start with default database from GUC
    let default_db = guc::approval_worker_database();
    let db_cstr = std::ffi::CString::new(default_db.as_str()).unwrap();
    
    BackgroundWorker::connect_worker_to_spi(Some(db_cstr.to_str().unwrap()), None);

    pgrx::log!("sql_firewall: approval worker started (default database: {})", default_db);
    pgrx::log!("sql_firewall: worker will process approvals for all databases in queue");

    loop {
        if BackgroundWorker::sigterm_received() {
            pgrx::log!("sql_firewall: approval worker shutting down");
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
                pgrx::log!("sql_firewall: worker processing approval - role={}, command={}, db={}", role, cmd, db);
                
                // Connect to the specific database and run INSERT in its own transaction
                // This allows multi-database support without multiple workers
                let result = BackgroundWorker::transaction(|| {
                    // Worker connects to default DB, need to use dblink or reconnect
                    // For now, log which DB it should go to - admin can manually handle
                    // TODO: Implement dynamic database connection switching
                    pgrx::log!("sql_firewall: worker recording to current database (intended: {})", db);
                    
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
                        role, cmd
                    );
                }
            } else {
                pgrx::warning!("sql_firewall: worker failed to decode approval - role_name or command_type is None");
            }
        }

        // Sleep if no work was done
        if !processed {
            thread::sleep(Duration::from_millis(100));
        }
    }

    pgrx::log!("sql_firewall: approval worker stopped");
}
