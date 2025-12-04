use std::cell::Cell;
use std::mem::MaybeUninit;
use std::os::raw::c_char;
use std::ptr;

use pgrx::pg_sys::{self, errcodes::PgSqlErrorCode};

use crate::{alerts, context::ExecutionContext, guc, spi_checks, structured_log};

thread_local! {
    static INSIDE_FIREWALL: Cell<bool> = Cell::new(false);
}

struct ReentryGuard;

impl ReentryGuard {
    fn enter() -> Option<Self> {
        let mut entered = false;
        INSIDE_FIREWALL.with(|flag| {
            if flag.get() {
                entered = false;
            } else {
                flag.set(true);
                entered = true;
            }
        });
        if entered {
            Some(Self)
        } else {
            None
        }
    }
}

impl Drop for ReentryGuard {
    fn drop(&mut self) {
        INSIDE_FIREWALL.with(|flag| flag.set(false));
    }
}

#[derive(Debug, Copy, Clone)]
pub enum QueryOrigin {
    Executor,
    Utility,
}

pub fn inspect_query(_origin: QueryOrigin, query: &str, ctx: &ExecutionContext, command: &str) {
    // KILL SWITCH: Bypass all firewall processing if disabled (emergency override)
    if !guc::firewall_enabled() {
        return;
    }

    if query.trim().is_empty() {
        return;
    }

    // CRITICAL: Bypass sql_firewall tables to prevent infinite loop
    if is_firewall_internal_query(query) {
        return;
    }

    let _guard = match ReentryGuard::enter() {
        Some(g) => g,
        None => return,
    };

    let superuser = is_superuser();
    if superuser && guc::allow_superuser_auth_bypass() {
        return;
    }

    if let Some(reason) = session_policy_violation(ctx) {
        alerts::emit_connection_alert(
            ctx.role.as_deref(),
            ctx.client_addr.as_deref(),
            ctx.application_name.as_deref(),
            &reason,
        );
        pgrx::ereport!(
            ERROR,
            PgSqlErrorCode::ERRCODE_INSUFFICIENT_PRIVILEGE,
            &reason
        );
    }

    // CRITICAL FIX: Check quiet hours FIRST before any logging
    // If in quiet hours, throw error IMMEDIATELY without calling log_activity or other SPI checks
    if let Some(reason) = quiet_hours_violation_reason() {
        if guc::quiet_hours_logging_enabled() {
            if let Some((start, end)) = guc::quiet_hours_window() {
                structured_log::log_quiet_hours(ctx, command, &start, &end);
            }
            spi_checks::log_activity(ctx, command, "BLOCKED (QUIET HOURS)", Some(&reason), query);
        }
        pgrx::ereport!(
            ERROR,
            PgSqlErrorCode::ERRCODE_INSUFFICIENT_PRIVILEGE,
            &reason
        );
        // ereport! aborts, so we never reach here
    }

    // Now safe to proceed with normal firewall checks that may call log_activity
    if let Some(keyword) = blocked_keyword(query) {
        structured_log::log_keyword_block(ctx, command, &keyword);
        let message = format!("sql_firewall: Blocked due to blacklisted keyword '{keyword}'.");
        pgrx::ereport!(
            ERROR,
            PgSqlErrorCode::ERRCODE_SYNTAX_ERROR_OR_ACCESS_RULE_VIOLATION,
            &message
        );
    }

    // Get mode for approval checks (still needed)
    let mode = guc::mode();

    // Debug logging - commented out for production
    // let keyword = guc::keyword_scan_enabled();
    // let regex = guc::regex_scan_enabled();
    // let quiet = guc::quiet_hours_enabled();
    //
    // pgrx::log!(
    //     "sql_firewall_rs {:?}: mode={mode:?} keyword_scan={keyword} regex_scan={regex} quiet_hours={quiet}",
    //     origin
    // );
    //
    // if let Some((start, end)) = guc::quiet_hours_window() {
    //     pgrx::log!("sql_firewall_rs quiet hours window {start} - {end}");
    // }
    //
    // trace_query(origin, query);

    if let Some(reason) = spi_checks::regex_block_reason(ctx, command, query) {
        pgrx::ereport!(
            ERROR,
            PgSqlErrorCode::ERRCODE_INSUFFICIENT_PRIVILEGE,
            &reason
        );
    }

    if let Some(reason) = spi_checks::rate_limit_violation(ctx, command, query) {
        pgrx::ereport!(
            ERROR,
            PgSqlErrorCode::ERRCODE_CONFIGURATION_LIMIT_EXCEEDED,
            &reason
        );
    }

    if let Some(reason) = spi_checks::approval_requirement(ctx, command, mode, query) {
        pgrx::ereport!(
            ERROR,
            PgSqlErrorCode::ERRCODE_INSUFFICIENT_PRIVILEGE,
            &reason
        );
    }
}

#[allow(dead_code)]
fn trace_query(origin: QueryOrigin, query: &str) {
    let sample = if query.len() > 256 {
        format!("{}...", &query[..256])
    } else {
        query.to_owned()
    };
    pgrx::log!("sql_firewall_rs {:?} sample: {}", origin, sample);
}

fn quiet_hours_violation_reason() -> Option<String> {
    if !guc::quiet_hours_enabled() {
        return None;
    }

    let (start_raw, end_raw) = guc::quiet_hours_window()?;
    let start = parse_hhmm_minutes(&start_raw)?;
    let end = parse_hhmm_minutes(&end_raw)?;

    let now = current_minutes_of_day()?;

    let in_window = if start < end {
        now >= start && now < end
    } else {
        now >= start || now < end
    };

    if in_window {
        Some(format!(
            "sql_firewall: Blocked during quiet hours ({start_raw} - {end_raw})."
        ))
    } else {
        None
    }
}

fn parse_hhmm_minutes(value: &str) -> Option<i32> {
    let mut parts = value.split(':');
    let hour = parts.next()?.trim().parse::<i32>().ok()?;
    let minute = parts.next()?.trim().parse::<i32>().ok()?;
    if !(0..=23).contains(&hour) || !(0..=59).contains(&minute) {
        return None;
    }
    Some(hour * 60 + minute)
}

fn current_minutes_of_day() -> Option<i32> {
    let now = unsafe { pg_sys::GetCurrentTimestamp() };
    let mut tz: i32 = 0;
    let mut tm = MaybeUninit::<pg_sys::pg_tm>::uninit();
    let mut fsec: pg_sys::fsec_t = 0;
    let mut tz_name: *const c_char = ptr::null();
    let rc = unsafe {
        pg_sys::timestamp2tm(
            now,
            &mut tz,
            tm.as_mut_ptr(),
            &mut fsec,
            &mut tz_name,
            ptr::null_mut(),
        )
    };
    if rc != 0 {
        return None;
    }
    let tm = unsafe { tm.assume_init() };
    Some((tm.tm_hour * 60) + tm.tm_min)
}

fn blocked_keyword(query: &str) -> Option<String> {
    if !guc::keyword_scan_enabled() {
        return None;
    }

    let keywords = guc::blacklisted_keywords();
    if keywords.is_empty() {
        return None;
    }

    let lower_query = query.to_ascii_lowercase();
    for keyword in keywords {
        if keyword.is_empty() {
            continue;
        }
        for (idx, _) in lower_query.match_indices(&keyword) {
            if is_boundary_before(&lower_query, idx)
                && is_boundary_after(&lower_query, idx + keyword.len())
            {
                return Some(keyword);
            }
        }
    }

    None
}

fn is_boundary_before(text: &str, byte_idx: usize) -> bool {
    if byte_idx == 0 {
        return true;
    }
    text[..byte_idx]
        .chars()
        .next_back()
        .map(|ch| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .unwrap_or(true)
}

fn is_boundary_after(text: &str, byte_idx: usize) -> bool {
    if byte_idx >= text.len() {
        return true;
    }
    text[byte_idx..]
        .chars()
        .next()
        .map(|ch| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .unwrap_or(true)
}

fn is_superuser() -> bool {
    unsafe { pg_sys::superuser() }
}

fn is_firewall_internal_query(query: &str) -> bool {
    // CRITICAL: Prevent recursive loops by bypassing ALL firewall-related queries
    // Case-insensitive check to catch all variants
    let q_upper = query.to_uppercase();
    
    // Bypass ANY query that mentions firewall tables or internal functions
    let is_internal = q_upper.contains("SQL_FIREWALL_COMMAND_APPROVALS") 
        || q_upper.contains("SQL_FIREWALL_QUERY_FINGERPRINTS")
        || q_upper.contains("SQL_FIREWALL_ACTIVITY_LOG")
        || q_upper.contains("SQL_FIREWALL_REGEX_RULES")
        || q_upper.contains("SQL_FIREWALL_BLOCKED_QUERIES")
        || q_upper.contains("SQL_FIREWALL_INTERNAL_");  // Catches all internal function calls
    
    is_internal
}

#[allow(dead_code)]
fn log_quiet_hours_block(ctx: &ExecutionContext, command: &str, query: &str, reason: &str) {
    let role = ctx.role.as_deref().unwrap_or("unknown");
    let database = ctx.database.as_deref().unwrap_or("unknown");
    let snippet = if query.len() > 200 {
        format!("{}...", &query[..200])
    } else {
        query.to_owned()
    };

    spi_checks::log_activity(ctx, command, "BLOCKED (QUIET HOURS)", Some(reason), query);

    pgrx::warning!(
        "sql_firewall: Quiet-hours block | role={} db={} command={} reason={} sample={}",
        role,
        database,
        command,
        reason,
        snippet
    );
}

fn session_policy_violation(ctx: &ExecutionContext) -> Option<String> {
    let client_ip = ctx.client_addr.as_deref();
    let application = ctx.application_name.as_deref();
    let role = ctx.role.as_deref();

    if guc::ip_blocking_enabled() {
        if let Some(ip) = client_ip {
            let blocked = guc::blocked_ips()
                .iter()
                .any(|entry| entry.eq_ignore_ascii_case(ip));
            if blocked {
                return Some(format!(
                    "sql_firewall: Connection from blocked IP address '{}' is not allowed.",
                    ip
                ));
            }
        }
    }

    if guc::application_blocking_enabled() {
        if let Some(app) = application {
            let app_lower = app.to_ascii_lowercase();
            let blocked = guc::blocked_applications()
                .iter()
                .any(|entry| entry.to_ascii_lowercase() == app_lower);
            if blocked {
                return Some(format!(
                    "sql_firewall: Connections from application '{}' are not allowed.",
                    app
                ));
            }
        }
    }

    if guc::role_ip_binding_enabled() {
        if let (Some(role_name), Some(ip)) = (role, client_ip) {
            let bindings = guc::role_ip_bindings();
            let matches: Vec<&(String, String)> =
                bindings.iter().filter(|(r, _)| r == role_name).collect();
            if !matches.is_empty() && matches.iter().all(|(_, allowed_ip)| allowed_ip != ip) {
                return Some(format!(
                    "sql_firewall: Role '{}' is not allowed to connect from IP '{}'.",
                    role_name, ip
                ));
            }
        }
    }

    None
}
