use crate::auth_event;
use crate::clear_login_attempts_internal;
use crate::record_failed_login;
use pgrx::bgworkers::{BackgroundWorker, SignalWakeFlags};
use pgrx::pg_sys;
use std::time::Duration;

#[no_mangle]
pub unsafe extern "C-unwind" fn auth_event_consumer_main(_arg: pg_sys::Datum) {
    BackgroundWorker::attach_signal_handlers(SignalWakeFlags::SIGHUP | SignalWakeFlags::SIGTERM);
    BackgroundWorker::connect_worker_to_spi(Some("postgres"), None);

    unsafe {
        #[cfg(any(feature = "pg16", feature = "pg17"))]
        pg_sys::pqsignal(pg_sys::SIGTERM as i32, None);
        pg_sys::BackgroundWorkerUnblockSignals();
    }

    pgrx::log!("password_profile: auth event consumer worker started");

    loop {
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
                pgrx::log!("password_profile: auth event consumer shutting down (during processing)");
                break;
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
            BackgroundWorker::wait_latch(Some(Duration::from_millis(25)));
            // NOTE: check_for_interrupts!() omitted here intentionally – see comment above.
            // wait_latch already yields control and SIGTERM is checked at the top of the
            // loop via sigterm_received().
        }
    }

    pgrx::log!("password_profile: auth event consumer worker stopped");
}
