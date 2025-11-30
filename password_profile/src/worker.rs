use crate::auth_event;
use crate::clear_login_attempts_internal;
use crate::record_failed_login;
use pgrx::bgworkers::{BackgroundWorker, SignalWakeFlags};
use pgrx::pg_sys;
use pgrx::prelude::*;
use std::time::Duration;

#[no_mangle]
pub unsafe extern "C" fn auth_event_consumer_main(_arg: pg_sys::Datum) {
    BackgroundWorker::attach_signal_handlers(SignalWakeFlags::SIGHUP | SignalWakeFlags::SIGTERM);
    BackgroundWorker::connect_worker_to_spi(Some("postgres"), None);

    // Force SIGTERM to default handler (terminate process) to ensure clean shutdown
    unsafe {
        pg_sys::pqsignal(pg_sys::SIGTERM as i32, None);
        pg_sys::BackgroundWorkerUnblockSignals();
    }

    pgrx::log!("password_profile: auth event consumer worker started");

    loop {
        if BackgroundWorker::sigterm_received() {
            pgrx::log!("password_profile: auth event consumer shutting down");
            break;
        }

        let mut processed = false;
        while let Some(event) = auth_event::dequeue() {
            if BackgroundWorker::sigterm_received() {
                pgrx::log!("password_profile: auth event consumer shutting down (during processing)");
                break;
            }
            check_for_interrupts!();

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
            // Use wait_latch instead of thread::sleep for proper signal handling
            BackgroundWorker::wait_latch(Some(Duration::from_millis(25)));
            check_for_interrupts!();
        }
    }

    pgrx::log!("password_profile: auth event consumer worker stopped");
}
