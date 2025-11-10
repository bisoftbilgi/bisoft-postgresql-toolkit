use pgrx::bgworkers::BackgroundWorkerBuilder;
use pgrx::pg_sys;
use pgrx::prelude::*;
use std::time::Duration;

mod alerts;
mod approval_worker;
mod context;
mod fingerprint_cache;
mod fingerprints;
mod firewall;
mod guc;
mod hooks;
mod pending_approvals;
mod port;
mod rate_state;
mod spi_checks;
mod sql;
mod structured_log;

pub use approval_worker::approval_worker_main;

pgrx::pg_module_magic!();
pgrx::extension_sql_file!("../sql/firewall_schema.sql", name = "firewall_schema");

static mut PREV_SHMEM_REQUEST_HOOK: Option<unsafe extern "C-unwind" fn()> = None;
static mut PREV_SHMEM_STARTUP_HOOK: Option<unsafe extern "C-unwind" fn()> = None;

#[pgrx::pg_guard]
pub extern "C-unwind" fn _PG_init() {
    unsafe {
        PREV_SHMEM_REQUEST_HOOK = pg_sys::shmem_request_hook;
        pg_sys::shmem_request_hook = Some(shmem_request_hook);

        PREV_SHMEM_STARTUP_HOOK = pg_sys::shmem_startup_hook;
        pg_sys::shmem_startup_hook = Some(shmem_startup_hook);
    }

    // Register background worker for processing pending approvals
    BackgroundWorkerBuilder::new("sql_firewall_approval_worker")
        .set_function("approval_worker_main")
        .set_library("sql_firewall_rs") // MUST match Cargo.toml [package] name
        .set_argument(None::<i32>.into_datum())
        .set_restart_time(Some(Duration::from_secs(1)))
        .enable_spi_access()
        .load();
    pgrx::info!("sql_firewall: approval worker background worker registered");

    guc::register();
    hooks::install();
    pgrx::log!("sql_firewall_rs: extension loaded");
}

#[pgrx::pg_guard]
pub extern "C-unwind" fn _PG_fini() {
    hooks::uninstall();
    unsafe {
        pg_sys::shmem_request_hook = PREV_SHMEM_REQUEST_HOOK;
        pg_sys::shmem_startup_hook = PREV_SHMEM_STARTUP_HOOK;
        PREV_SHMEM_REQUEST_HOOK = None;
        PREV_SHMEM_STARTUP_HOOK = None;
    }
    pgrx::log!("sql_firewall_rs: extension unloaded");
}

#[pgrx::pg_guard]
unsafe extern "C-unwind" fn shmem_request_hook() {
    if let Some(prev) = PREV_SHMEM_REQUEST_HOOK {
        prev();
    }
    pg_sys::RequestAddinShmemSpace(fingerprint_cache::shared_memory_bytes());
    pg_sys::RequestAddinShmemSpace(rate_state::shared_memory_bytes());
    pg_sys::RequestAddinShmemSpace(pending_approvals::shared_memory_bytes());
}

#[pgrx::pg_guard]
unsafe extern "C-unwind" fn shmem_startup_hook() {
    if let Some(prev) = PREV_SHMEM_STARTUP_HOOK {
        prev();
    }
    fingerprint_cache::init();
    rate_state::init();
    pending_approvals::init();
}

#[pg_extern]
fn sql_firewall_status() -> String {
    format!("sql_firewall_rs running in {:?} mode", guc::mode())
}

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use pgrx::prelude::*;

    #[pg_test]
    fn status_reports_mode() {
        let status = crate::sql_firewall_status();
        assert!(
            status.contains("sql_firewall_rs running"),
            "unexpected status text: {status}"
        );
    }
}

#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {}

    #[must_use]
    pub fn postgresql_conf_options() -> Vec<&'static str> {
        vec![]
    }
}
