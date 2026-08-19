use crate::auth_event;
use crate::clear_login_attempts_internal;
use crate::record_failed_login;
use pgrx::bgworkers::{BackgroundWorker, SignalWakeFlags};
use pgrx::pg_sys;
use std::time::Duration;

#[no_mangle]
pub unsafe extern "C-unwind" fn auth_event_consumer_main(_arg: pg_sys::Datum) {
    // `attach_signal_handlers` installs pgrx's own SIGTERM/SIGHUP handlers
    // (which set an internal flag and post the worker's latch) and already
    // calls `BackgroundWorkerUnblockSignals()` internally. Do NOT follow
    // this with `pqsignal(SIGTERM, None)` -- that resets SIGTERM back to
    // its default action (terminate the process), which is why the worker
    // used to die with "terminated by signal 15" on `pg_ctl restart -m
    // fast` instead of exiting through the loop below and triggering
    // abnormal-shutdown crash recovery. Do not unblock signals a second
    // time either; `attach_signal_handlers` already did it.
    BackgroundWorker::attach_signal_handlers(SignalWakeFlags::SIGHUP | SignalWakeFlags::SIGTERM);
    BackgroundWorker::connect_worker_to_spi(Some("postgres"), None);

    pgrx::log!("password_profile: auth event consumer worker started");

    // `sigterm_received()` and `wait_latch()`'s return value both consume the
    // same one-shot SIGTERM flag, so a shutdown can only be observed once by
    // whichever check runs first. A labeled outer loop lets the inner
    // dequeue loop exit the whole worker (not just itself) the moment it
    // sees that flag, instead of leaving the outer loop to spin with no way
    // to detect the already-consumed shutdown request.
    'outer: loop {
        if BackgroundWorker::sigterm_received() {
            pgrx::log!("password_profile: auth event consumer shutting down");
            break;
        }

        // SIGHUP aldıysak (pg_reload_conf() veya kill -HUP) GUC'ları yeniden yükle.
        // Bu sayede failed_login_max gibi ayarlar restart gerektirmeden geçer.
        if BackgroundWorker::sighup_received() {
            unsafe {
                pg_sys::ProcessConfigFile(pg_sys::GucContext::PGC_SIGHUP);
            }
            pgrx::log!("password_profile: auth event consumer reloaded config (SIGHUP)");
        }

        let mut processed = false;
        while let Some(event) = auth_event::dequeue() {
            if BackgroundWorker::sigterm_received() {
                pgrx::log!(
                    "password_profile: auth event consumer shutting down (during processing)"
                );
                break 'outer;
            }
            // NOTE: check_for_interrupts!() must NOT be called here (outside a transaction /
            // catch_unwind boundary). If CHECK_FOR_INTERRUPTS() fires an ereport(ERROR) it
            // converts to a Rust panic with no catcher, causing _URC_END_OF_STACK (error 5)
            // and SIGABRT. Interrupt checking happens naturally inside BackgroundWorker::transaction().

            processed = true;

            if let Some(username) = auth_event::username_from_bytes(&event.username) {
                let result = BackgroundWorker::transaction(|| {
                    if event.is_failure {
                        record_failed_login(&username)?;
                    } else {
                        clear_login_attempts_internal(&username, false)?;
                    }
                    Ok::<(), Box<dyn std::error::Error>>(())
                });

                if let Err(e) = result {
                    pgrx::warning!("password_profile: worker transaction failed: {:?}", e);
                }
            }
        }

        if !processed {
            // NOTE: check_for_interrupts!() omitted here intentionally – see comment above.
            // `wait_latch` returns false when it observes a SIGTERM (via the same
            // flag `sigterm_received()` checks) or postmaster death; honoring that
            // return value -- instead of discarding it -- is what lets a SIGTERM
            // received while idle here actually stop the worker.
            if !BackgroundWorker::wait_latch(Some(Duration::from_millis(25))) {
                pgrx::log!("password_profile: auth event consumer shutting down (idle wait)");
                break;
            }
        }
    }

    pgrx::log!("password_profile: auth event consumer worker stopped");
}
