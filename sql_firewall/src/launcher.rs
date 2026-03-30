use pgrx::prelude::*;
use pgrx::bgworkers::*;
use pgrx::pg_sys;
use std::collections::HashSet;
use std::time::Instant;

/// Firewall Launcher - Supervisor Worker
/// Monitors pg_database and spawns per-database workers
#[pg_guard]
#[no_mangle]
pub extern "C-unwind" fn firewall_launcher_main(_arg: pg_sys::Datum) {
    unsafe {
    BackgroundWorker::attach_signal_handlers(SignalWakeFlags::SIGHUP | SignalWakeFlags::SIGTERM);

    pgrx::log!("sql_firewall: launcher starting");
    
    // Track which databases have workers spawned
    let mut managed_dbs: HashSet<pg_sys::Oid> = HashSet::new();
    
    // Connect to postgres database for querying pg_database
    BackgroundWorker::connect_worker_to_spi(Some("postgres"), None);
    
    pgrx::log!("sql_firewall: launcher connected to postgres, monitoring databases");
    
    let scan_interval_secs = 5u64;
    // Set last_scan far enough in the past so the first scan runs immediately
    let mut last_scan = Instant::now() - std::time::Duration::from_secs(scan_interval_secs + 1);

    loop {
        // ── Wait using PostgreSQL latch (canonical BGW sleep) ──────────
        // WaitLatch honours WL_POSTMASTER_DEATH and, after ResetLatch +
        // CHECK_FOR_INTERRUPTS, guarantees that SIGTERM triggers proc_exit
        // automatically.  SPI sinval messages may set the latch early; we
        // handle that by only running the SPI scan when enough wall-clock
        // time has elapsed.
        let rc = pg_sys::WaitLatch(
            pg_sys::MyLatch,
            (pg_sys::WL_LATCH_SET | pg_sys::WL_TIMEOUT | pg_sys::WL_POSTMASTER_DEATH) as i32,
            1000,                       // wake every 1 s at most
            pg_sys::PG_WAIT_EXTENSION,
        );
        pg_sys::ResetLatch(pg_sys::MyLatch);

        // CHECK_FOR_INTERRUPTS will call proc_exit() if ShutdownRequestPending
        // is set (SIGTERM during fast shutdown).  This is the canonical way for
        // a BGW to honour SIGTERM; the Rust-side GOT_SIGTERM flag is a backup.
        pg_sys::check_for_interrupts!();

        if BackgroundWorker::sigterm_received() {
            pgrx::log!("sql_firewall: launcher received SIGTERM, shutting down");
            break;
        }

        // Postmaster died – exit immediately
        if (rc & pg_sys::WL_POSTMASTER_DEATH as i32) != 0 {
            pgrx::log!("sql_firewall: postmaster died, launcher exiting");
            break;
        }

        // Only perform the SPI scan once per scan_interval_secs
        if last_scan.elapsed().as_secs() < scan_interval_secs {
            continue;
        }
        last_scan = Instant::now();
        
        // Scan for databases and spawn workers
        let managed_clone = managed_dbs.clone();  // Clone for use in closure
        
        let scan_result = BackgroundWorker::transaction(move || {
            let mut stale_oids = Vec::new();
            let mut new_databases = Vec::new();

            // Prune stale managed workers:
            // 1) Database no longer exists
            // 2) Worker no longer appears active for that DB
            for oid in &managed_clone {
                let oid_u32 = u32::from(*oid);

                let db_exists_query = format!(
                    "SELECT EXISTS(SELECT 1 FROM pg_database WHERE oid = {} AND datallowconn = true AND datistemplate = false AND datname != 'postgres')",
                    oid_u32
                );

                let worker_active_query = format!(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datid = {} AND backend_type LIKE 'sql_firewall_worker_%')",
                    oid_u32
                );

                let db_exists = Spi::get_one::<bool>(&db_exists_query)
                    .ok()
                    .flatten()
                    .unwrap_or(false);

                let worker_active = Spi::get_one::<bool>(&worker_active_query)
                    .ok()
                    .flatten()
                    .unwrap_or(false);

                if !db_exists || !worker_active {
                    stale_oids.push(*oid);
                }
            }
            
            // Build exclusion list for SQL - exclude managed databases from query
            let mut excluded_oids = String::new();
            for oid in &managed_clone {
                if stale_oids.contains(oid) {
                    continue;
                }
                if !excluded_oids.is_empty() {
                    excluded_oids.push(',');
                }
                excluded_oids.push_str(&u32::from(*oid).to_string());
            }
            
            let query = if excluded_oids.is_empty() {
                "SELECT d.oid::int4, d.datname::text \
                 FROM pg_database d \
                 WHERE d.datallowconn = true AND d.datistemplate = false AND d.datname != 'postgres' \
                 AND NOT EXISTS ( \
                     SELECT 1 FROM pg_stat_activity a \
                     WHERE a.datid = d.oid AND a.backend_type LIKE 'sql_firewall_worker_%' \
                 ) \
                 ORDER BY d.oid \
                 LIMIT 1".to_string()
            } else {
                format!(
                    "SELECT d.oid::int4, d.datname::text \
                     FROM pg_database d \
                     WHERE d.datallowconn = true AND d.datistemplate = false AND d.datname != 'postgres' \
                     AND d.oid NOT IN ({}) \
                     AND NOT EXISTS ( \
                         SELECT 1 FROM pg_stat_activity a \
                         WHERE a.datid = d.oid AND a.backend_type LIKE 'sql_firewall_worker_%' \
                     ) \
                     ORDER BY d.oid \
                     LIMIT 1",
                    excluded_oids
                )
            };
            
            if let Ok((Some(oid_i32), Some(name))) = Spi::get_two::<i32, String>(&query) {
                let oid = pg_sys::Oid::from(oid_i32 as u32);
                pgrx::log!("sql_firewall: Found new DB '{}' (oid={})", name, oid);
                new_databases.push((oid, name));
            }
            
            Ok::<(Vec<pg_sys::Oid>, Vec<(pg_sys::Oid, String)>), spi::Error>((stale_oids, new_databases))
        });
        
        // Spawn workers for new databases
        match scan_result {
            Ok((stale_oids, new_dbs)) => {
                for oid in stale_oids {
                    managed_dbs.remove(&oid);
                }

                for (oid, name) in new_dbs {
                    pgrx::log!("sql_firewall: launcher spawning worker for database '{}' (oid={})", name, oid);
                    
                    // Register dynamic background worker
                    let worker_name = format!("sql_firewall_worker_{}", name);
                    let worker_name_cstr = std::ffi::CString::new(worker_name.as_str()).unwrap();
                    let library_cstr = std::ffi::CString::new("sql_firewall_rs").unwrap();
                    let function_cstr = std::ffi::CString::new("approval_worker_main").unwrap();
                    
                    let mut worker: pg_sys::BackgroundWorker = std::mem::zeroed();
                    
                    // Set worker name
                    std::ptr::copy_nonoverlapping(
                        worker_name_cstr.as_ptr() as *const u8,
                        worker.bgw_name.as_mut_ptr() as *mut u8,
                        std::cmp::min(worker_name.len(), pg_sys::BGW_MAXLEN as usize - 1),
                    );

                    // CRITICAL: Set bgw_type so pg_stat_activity.backend_type is populated.
                    // Without this, backend_type stays as the default "background worker" and
                    // the launcher's worker_active_query never finds the worker, causing it
                    // to mark every managed DB as stale and re-spawn a new worker every second.
                    // That flood of workers exhausts max_worker_processes and makes pg_ctl stop hang.
                    std::ptr::copy_nonoverlapping(
                        worker_name_cstr.as_ptr() as *const u8,
                        worker.bgw_type.as_mut_ptr() as *mut u8,
                        std::cmp::min(worker_name.len(), pg_sys::BGW_MAXLEN as usize - 1),
                    );

                    // Worker needs shared memory and database connection
                    worker.bgw_flags = pg_sys::BGWORKER_SHMEM_ACCESS as i32 
                        | pg_sys::BGWORKER_BACKEND_DATABASE_CONNECTION as i32;
                    worker.bgw_start_time = pg_sys::BgWorkerStartTime::BgWorkerStart_RecoveryFinished;
                    worker.bgw_restart_time = pg_sys::BGW_NEVER_RESTART;
                    
                    // Set library and function
                    std::ptr::copy_nonoverlapping(
                        library_cstr.as_ptr() as *const u8,
                        worker.bgw_library_name.as_mut_ptr() as *mut u8,
                        std::cmp::min("sql_firewall_rs".len(), pg_sys::BGW_MAXLEN as usize - 1),
                    );
                    
                    std::ptr::copy_nonoverlapping(
                        function_cstr.as_ptr() as *const u8,
                        worker.bgw_function_name.as_mut_ptr() as *mut u8,
                        std::cmp::min("approval_worker_main".len(), pg_sys::BGW_MAXLEN as usize - 1),
                    );
                    
                    // CRITICAL: Pass database OID via bgw_extra (string-based, safe)
                    let oid_string = u32::from(oid).to_string();
                    let oid_bytes = oid_string.as_bytes();
                    let copy_len = std::cmp::min(oid_bytes.len(), 127); // Leave room for null terminator
                    
                    std::ptr::copy_nonoverlapping(
                        oid_bytes.as_ptr(),
                        worker.bgw_extra.as_mut_ptr() as *mut u8,
                        copy_len,
                    );
                    // Null terminate
                    worker.bgw_extra[copy_len] = 0;
                    
                    worker.bgw_main_arg = pg_sys::Datum::from(0_usize); // Not used
                    // Do NOT set bgw_notify_pid: if set to MyProcPid the
                    // postmaster signals the launcher latch the instant the
                    // worker process starts, causing wait_latch to return
                    // before the new worker has had time to register in
                    // pg_stat_activity.  The next scan would then find the
                    // database "uncovered", spawn a duplicate, hit the
                    // max_worker_processes limit, and crash.  Polling every
                    // 1 s is sufficient for our use-case.
                    worker.bgw_notify_pid = 0;
                    
                    // Register the dynamic worker
                    let mut handle: *mut pg_sys::BackgroundWorkerHandle = std::ptr::null_mut();
                    let success = pg_sys::RegisterDynamicBackgroundWorker(&mut worker as *mut _, &mut handle);
                    
                    if success {
                        managed_dbs.insert(oid);
                        pgrx::log!("sql_firewall: worker spawned successfully for '{}'", name);
                    } else {
                        pgrx::warning!("sql_firewall: failed to spawn worker for '{}' - RegisterDynamicBackgroundWorker returned false", name);
                    }
                }
            }
            Err(e) => {
                pgrx::warning!("sql_firewall: launcher scan failed: {:?}", e);
            }
        }
    }
    
    pgrx::log!("sql_firewall: launcher stopped");
    }
}
