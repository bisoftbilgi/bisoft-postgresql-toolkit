use crate::{
    context::ExecutionContext,
    guc,
    sql::{spi_update, text_arg},
};
use libc::{self, c_char};
use pgrx::{pg_sys, Spi};
use std::ffi::CString;

pub fn emit_block_alert(ctx: &ExecutionContext, command: &str, reason: &str) {
    if !guc::alert_notifications_enabled() && !guc::syslog_alerts_enabled() {
        return;
    }

    let role = ctx.role.as_deref().unwrap_or("unknown");
    let database = ctx.database.as_deref().unwrap_or("unknown");
    let application = ctx.application_name.as_deref().unwrap_or("unknown");
    let client_ip = ctx.client_addr.as_deref().unwrap_or("unknown");

    let payload = format!(
        r#"{{"event":"query_block","role":"{}","database":"{}","command":"{}","reason":"{}","application":"{}","client_ip":"{}"}}"#,
        escape_json(role),
        escape_json(database),
        escape_json(command),
        escape_json(reason),
        escape_json(application),
        escape_json(client_ip),
    );

    maybe_notify(&payload);
    maybe_syslog(&format!(
        "sql_firewall_rs block role={} db={} cmd={} reason={} app={} ip={}",
        role, database, command, reason, application, client_ip
    ));
}

pub fn emit_connection_alert(
    role: Option<&str>,
    ip: Option<&str>,
    application: Option<&str>,
    reason: &str,
) {
    if !guc::alert_notifications_enabled() && !guc::syslog_alerts_enabled() {
        return;
    }

    let payload = format!(
        r#"{{"event":"connection_block","role":"{}","client_ip":"{}","application":"{}","reason":"{}"}}"#,
        escape_json(role.unwrap_or("unknown")),
        escape_json(ip.unwrap_or("unknown")),
        escape_json(application.unwrap_or("unknown")),
        escape_json(reason),
    );

    maybe_notify(&payload);
    maybe_syslog(&format!(
        "sql_firewall_rs connection block role={} ip={} app={} reason={}",
        role.unwrap_or("unknown"),
        ip.unwrap_or("unknown"),
        application.unwrap_or("unknown"),
        reason
    ));
}

fn maybe_notify(payload: &str) {
    if !guc::alert_notifications_enabled() || !unsafe { pg_sys::IsTransactionState() } {
        return;
    }

    let channel = guc::alert_channel();
    Spi::connect_mut(|client| {
        if let Err(err) = spi_update(
            client,
            "SELECT pg_notify($1, $2)",
            &[text_arg(&channel), text_arg(payload)],
        ) {
            pgrx::warning!("sql_firewall: failed to emit alert notify: {err}");
        }
    });
}

const SYSLOG_IDENT: &[u8] = b"sql_firewall_rs\0";

fn maybe_syslog(message: &str) {
    if !guc::syslog_alerts_enabled() {
        return;
    }
    if let Ok(c_string) = CString::new(message) {
        unsafe {
            libc::openlog(syslog_ident(), libc::LOG_PID, libc::LOG_USER);
            libc::syslog(libc::LOG_NOTICE, c_string.as_ptr());
            libc::closelog();
        }
    }
}

fn syslog_ident() -> *const c_char {
    SYSLOG_IDENT.as_ptr() as *const c_char
}

fn escape_json(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
