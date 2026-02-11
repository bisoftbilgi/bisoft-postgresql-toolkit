use pgrx::prelude::*;
use pgrx::bgworkers::*;
use pgrx::pg_sys;
use std::collections::HashSet;
use std::time::Duration;

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
    
    loop {
        // Check for shutdown signal
        if BackgroundWorker::sigterm_received() {
            pgrx::log!("sql_firewall: launcher shutting down");
            break;
        }
        
        // Scan for databases and spawn workers
        pgrx::log!("sql_firewall: launcher scanning databases...");
        let managed_clone = managed_dbs.clone();  // Clone for use in closure
        
        let scan_result = BackgroundWorker::transaction(move || {
            pgrx::log!("sql_firewall: launcher inside transaction");
            
            let mut new_databases = Vec::new();
            
            // Build exclusion list for SQL - exclude managed databases from query
            let mut excluded_oids = String::new();
            for oid in &managed_clone {
                if !excluded_oids.is_empty() {
                    excluded_oids.push(',');
                }
                excluded_oids.push_str(&u32::from(*oid).to_string());
            }
            
            let query = if excluded_oids.is_empty() {
                "SELECT oid::int4, datname::text FROM pg_database WHERE datallowconn = true AND datistemplate = false AND datname != 'postgres'".to_string()
            } else {
                format!("SELECT oid::int4, datname::text FROM pg_database WHERE datallowconn = true AND datistemplate = false AND datname != 'postgres' AND oid NOT IN ({})", excluded_oids)
            };
            
            pgrx::log!("sql_firewall: launcher executing SPI query: {}", query);
            
            // Fetch ALL new databases - repeatedly query until no more found
            loop {
                let results = Spi::get_two::<i32, String>(&query);
                
                if let Ok((Some(oid_i32), Some(name))) = results {
                    let oid = pg_sys::Oid::from(oid_i32 as u32);
                    
                    // Check if already in our new_databases list this iteration
                    if new_databases.iter().any(|(existing_oid, _)| *existing_oid == oid) {
                        break; // We've cycled back, stop
                    }
                    
                    pgrx::log!("sql_firewall: Found new DB '{}' (oid={})", name, oid);
                    new_databases.push((oid, name.clone()));
                    
                    // Update exclusion list for next iteration
                    if !excluded_oids.is_empty() {
                        excluded_oids.push(',');
                    }
                    excluded_oids.push_str(&(oid_i32 as u32).to_string());
                } else {
                    break; // No more databases found
                }
            }
            
            pgrx::log!("sql_firewall: launcher found {} new databases", new_databases.len());
            Ok::<Vec<(pg_sys::Oid, String)>, spi::Error>(new_databases)
        });
        
        // Spawn workers for new databases
        match scan_result {
            Ok(new_dbs) => {
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
                    
                    // Worker needs shared memory and database connection
                    worker.bgw_flags = pg_sys::BGWORKER_SHMEM_ACCESS as i32 
                        | pg_sys::BGWORKER_BACKEND_DATABASE_CONNECTION as i32;
                    worker.bgw_start_time = pg_sys::BgWorkerStartTime::BgWorkerStart_RecoveryFinished;
                    worker.bgw_restart_time = 10; // Restart after 10 seconds if crashes
                    
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
                    worker.bgw_notify_pid = pg_sys::MyProcPid;
                    
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
        
        // Wait 1 second before next scan (shorter for faster shutdown)
        BackgroundWorker::wait_latch(Some(Duration::from_secs(1)));
        
        // Check for shutdown signal immediately after wait
        if BackgroundWorker::sigterm_received() {
            pgrx::log!("sql_firewall: launcher received SIGTERM, shutting down");
            break;
        }
    }
    
    pgrx::log!("sql_firewall: launcher stopped");
    }
}
