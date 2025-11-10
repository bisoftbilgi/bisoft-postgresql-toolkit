use std::{
    borrow::Cow,
    sync::atomic::{AtomicI64, Ordering},
};

use pgrx::{datum::DatumWithOid, pg_sys, Spi};

use crate::{
    alerts,
    context::ExecutionContext,
    fingerprints,
    guc::{self, FirewallMode},
    rate_state,
    sql::{int4_arg, name_arg, spi_select_one, spi_update, text_arg},
};

pub fn regex_block_reason(ctx: &ExecutionContext, command: &str, query: &str) -> Option<String> {
    if !guc::regex_scan_enabled() || query.is_empty() || !in_transaction() {
        return None;
    }

    // CRITICAL: More precise check - skip only actual firewall table access
    let lower = query.to_ascii_lowercase();
    if (lower.contains("from ") || lower.contains("into ") || lower.contains("update ")) &&
       (lower.contains("sql_firewall_activity_log") || 
        lower.contains("sql_firewall_command_approvals") ||
        lower.contains("sql_firewall_query_fingerprints") ||
        lower.contains("sql_firewall_regex_rules")) {
        return None;
    }

    let matched = Spi::connect_mut(|client| {
        // CRITICAL: Set statement timeout to prevent ReDoS attacks
        // Set 100ms timeout for regex check
        let _ = spi_update(client, "SET LOCAL statement_timeout = 100", &[]);
        
        let result = match spi_select_one::<bool>(
            client,
            "SELECT EXISTS (SELECT 1 FROM public.sql_firewall_regex_rules \
             WHERE is_active = true AND action = 'BLOCK' AND $1 ~* pattern LIMIT 1)",
            &[text_arg(query)],
        ) {
            Ok(result) => result.unwrap_or(false),
            Err(err) => {
                let err_str = err.to_string();
                // Check for timeout
                if err_str.contains("timeout") || err_str.contains("canceling statement") {
                    pgrx::warning!("sql_firewall: regex check timeout - possible ReDoS attack pattern");
                    return false;
                }
                // Tablo yoksa sessizce geç (bootstrap sırasında)
                if err_str.contains("does not exist") || err_str.contains("mevcut değil") {
                    return false;
                }
                pgrx::warning!("sql_firewall: regex check failed: {err}");
                false
            }
        };
        
        result
    });

    if matched {
        let reason = "Regex pattern match".to_string();
        log_activity(ctx, command, "BLOCKED", Some(&reason), query);
        Some("sql_firewall: Query blocked by security regex pattern.".to_string())
    } else {
        let normalized = query.to_ascii_lowercase();
        if matches_builtin_injection(&normalized) {
            let reason = "Built-in injection pattern match".to_string();
            log_activity(ctx, command, "BLOCKED", Some(&reason), query);
            Some("sql_firewall: Query matched default injection pattern.".to_string())
        } else {
            None
        }
    }
}

pub fn rate_limit_violation(ctx: &ExecutionContext, command: &str, query: &str) -> Option<String> {
    if !in_transaction() {
        return None;
    }

    // CRITICAL: More precise check - skip only actual firewall table access
    let lower = query.to_ascii_lowercase();
    if (lower.contains("from ") || lower.contains("into ") || lower.contains("update ")) &&
       (lower.contains("sql_firewall_activity_log") || 
        lower.contains("sql_firewall_command_approvals") ||
        lower.contains("sql_firewall_query_fingerprints") ||
        lower.contains("sql_firewall_regex_rules")) {
        return None;
    }

    let role_name = ctx.role.as_deref()?;
    let role_oid = ctx.role_oid?;

    if guc::rate_limit_enabled() {
        let limit = guc::rate_limit_count();
        let window_secs = guc::rate_limit_seconds();
        if let Some(decision) = rate_state::check_global(Some(role_oid), limit, window_secs) {
            let detail = format!(
                "Rate limit exceeded: {}/{} queries in {} seconds",
                decision.attempts, decision.limit, decision.window_secs
            );
            log_activity(ctx, command, "BLOCKED (RATE LIMIT)", Some(&detail), query);
            return Some(format!(
                "sql_firewall: Rate limit exceeded for role '{}'.",
                role_name
            ));
        }
    }

    let command_limit = guc::command_limit(command);
    let window_secs = guc::command_limit_seconds();
    if command_limit > 0 && window_secs > 0 {
        let command_code = rate_state::command_code(command);
        if let Some(decision) =
            rate_state::check_command(Some(role_oid), command_code, command_limit, window_secs)
        {
            let detail = format!(
                "{} limit exceeded: {}/{} in {} seconds",
                command, decision.attempts, decision.limit, decision.window_secs
            );
            log_activity(ctx, command, "BLOCKED (RATE LIMIT)", Some(&detail), query);
            return Some(format!(
                "sql_firewall: Rate limit for command '{}' exceeded for role '{}'",
                command, role_name
            ));
        }
    }

    None
}

pub fn approval_requirement(
    ctx: &ExecutionContext,
    command: &str,
    mode: FirewallMode,
    query: &str,
) -> Option<String> {
    if !in_transaction() {
        return None;
    }

    // CRITICAL: More precise check - skip only actual firewall table access
    let lower = query.to_ascii_lowercase();
    if (lower.contains("from ") || lower.contains("into ") || lower.contains("update ")) &&
       (lower.contains("sql_firewall_activity_log") || 
        lower.contains("sql_firewall_command_approvals") ||
        lower.contains("sql_firewall_query_fingerprints") ||
        lower.contains("sql_firewall_regex_rules")) {
        return None;
    }

    if command == "OTHER" {
        log_activity(
            ctx,
            command,
            "ALLOWED",
            Some("Command type is 'OTHER'"),
            query,
        );
        return None;
    }

    let role = match ctx.role.as_deref() {
        Some(r) => r,
        None => {
            let decision = Decision::Allow {
                action: Cow::Borrowed("ALLOWED"),
                reason: Some("Role unknown".to_string()),
                skip_fingerprint_check: true,  // No role, can't check fingerprints anyway
            };
            return finalize_decision(decision, ctx, command, mode, query);
        }
    };

    let approval = Spi::connect(|client| {
        match spi_select_one::<bool>(
            client,
            "SELECT is_approved FROM public.sql_firewall_command_approvals \
             WHERE role_name = $1 AND command_type = $2",
            &[name_arg(role), text_arg(command)],
        ) {
            Ok(result) => result,
            Err(err) => {
                if err.to_string().contains("does not exist")
                    || err.to_string().contains("mevcut değil")
                {
                    return None;
                }
                pgrx::warning!("sql_firewall: approval lookup failed: {err}");
                None
            }
        }
    });

    let record_pending = || {
        // CRITICAL: Multiple logging layers to survive transaction abort
        
        // 1. PostgreSQL WARNING (survives transaction abort)
        pgrx::warning!(
            "sql_firewall: PENDING APPROVAL REQUEST - role='{}' command='{}'", 
            role, command
        );
        
        // 2. PostgreSQL LOG (also survives abort)
        pgrx::log!(
            "sql_firewall_rs: APPROVAL_NEEDED role='{}' command='{}' database='{}'",
            role,
            command,
            ctx.database.as_deref().unwrap_or("unknown")
        );
        
        // 3. If syslog alerts enabled, use that too
        if guc::syslog_alerts_enabled() {
            use crate::alerts;
            alerts::emit_block_alert(
                ctx,
                command,
                "PENDING APPROVAL - awaiting admin action"
            );
        }
    };

    let decision = match approval {
        Some(true) => Decision::Allow {
            action: Cow::Borrowed("ALLOWED"),
            reason: Some("Approved command type".to_string()),
            skip_fingerprint_check: true,  // Command approved at command-type level, skip fingerprint
        },
        Some(false) => match mode {
            FirewallMode::Permissive => {
                pgrx::warning!(
                    "sql_firewall: role '{}' command '{}' allowed in permissive mode (pending approval)",
                    role,
                    command
                );
                Decision::Allow {
                    action: Cow::Borrowed("ALLOWED (PERMISSIVE - PENDING)"),
                    reason: Some("Command type approval pending".to_string()),
                    skip_fingerprint_check: false,  // Still check fingerprints in permissive mode
                }
            }
            FirewallMode::Learn => Decision::Block {
                action: Cow::Borrowed("BLOCKED (LEARN MODE)"),
                reason: Some("Command type approval pending".to_string()),
                error: format!(
                    "sql_firewall: BLOCKED - Approval for command '{}' is pending for role '{}'",
                    command, role
                ),
            },
            _ => Decision::Block {
                action: Cow::Borrowed("BLOCKED"),
                reason: Some("Command type approval pending".to_string()),
                error: format!(
                    "sql_firewall: BLOCKED - Approval for command '{}' is pending for role '{}'",
                    command, role
                ),
            },
        },
        None => match mode {
            FirewallMode::Learn => {
                record_pending();
                Decision::Block {
                    action: Cow::Borrowed("BLOCKED (LEARN MODE)"),
                    reason: Some("New command type detected".to_string()),
                    error: format!(
                        "sql_firewall: BLOCKED - Approval required for command '{}' for role '{}'",
                        command, role
                    ),
                }
            }
            FirewallMode::Permissive => {
                record_pending();
                pgrx::warning!(
                    "sql_firewall: role '{}' command '{}' auto-approved in permissive mode (no rule)",
                    role,
                    command
                );
                Decision::Allow {
                    action: Cow::Borrowed("ALLOWED (PERMISSIVE - AUTO)"),
                    reason: Some("No rule for command type".to_string()),
                    skip_fingerprint_check: false,  // Still check fingerprints
                }
            }
            FirewallMode::Enforce => Decision::Block {
                action: Cow::Borrowed("BLOCKED"),
                reason: Some("No rule for command type".to_string()),
                error: format!(
                    "sql_firewall: No rule found for command '{}' for role '{}'",
                    command, role
                ),
            },
        },
    };

    finalize_decision(decision, ctx, command, mode, query)
}

thread_local! {
    static LOG_GUARD: std::cell::Cell<bool> = std::cell::Cell::new(false);
}

const MICROS_PER_SEC: i64 = 1_000_000;
static LAST_PRUNE_EPOCH: AtomicI64 = AtomicI64::new(0);

pub fn log_activity(
    ctx: &ExecutionContext,
    command: &str,
    action: &str,
    reason: Option<&str>,
    query: &str,
) {
    if !in_transaction() {
        return;
    }

    let entered = LOG_GUARD.with(|flag| {
        if flag.get() {
            false
        } else {
            flag.set(true);
            true
        }
    });
    if !entered {
        return;
    }

    let role = ctx.role.as_deref().unwrap_or("unknown");
    let database = ctx.database.as_deref().unwrap_or("unknown");
    pgrx::log!(
        "sql_firewall_rs log_activity: role='{}' database='{}' action='{}' command='{}'",
        role,
        database,
        action,
        command
    );
    Spi::connect_mut(|client| {
        let reason_arg = reason
            .map(text_arg)
            .unwrap_or_else(|| DatumWithOid::null_oid(pg_sys::TEXTOID));
        let app_arg = ctx
            .application_name
            .as_deref()
            .map(text_arg)
            .unwrap_or_else(|| DatumWithOid::null_oid(pg_sys::TEXTOID));
        let client_arg = ctx
            .client_addr
            .as_deref()
            .map(text_arg)
            .unwrap_or_else(|| DatumWithOid::null_oid(pg_sys::TEXTOID));
        let args = [
            name_arg(role),
            name_arg(database),
            text_arg(action),
            reason_arg,
            text_arg(query),
            text_arg(command),
            app_arg,
            client_arg,
        ];
        if let Err(err) = spi_update(
            client,
            "INSERT INTO public.sql_firewall_activity_log \
             (role_name, database_name, action, reason, query_text, command_type, application_name, client_ip) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &args,
        ) {
            pgrx::warning!("sql_firewall: failed to log activity: {err}");
        }
    });

    maybe_prune_activity_log();

    if action.starts_with("BLOCKED") {
        let reason_text = reason.unwrap_or("unspecified");
        alerts::emit_block_alert(ctx, command, reason_text);
    }

    LOG_GUARD.with(|flag| flag.set(false));
}

fn in_transaction() -> bool {
    unsafe { pg_sys::IsTransactionState() }
}

enum Decision {
    Allow {
        action: Cow<'static, str>,
        reason: Option<String>,
        skip_fingerprint_check: bool,  // If true, skip fingerprint enforcement (command already approved)
    },
    Block {
        action: Cow<'static, str>,
        reason: Option<String>,
        error: String,
    },
}

fn finalize_decision(
    decision: Decision,
    ctx: &ExecutionContext,
    command: &str,
    mode: FirewallMode,
    query: &str,
) -> Option<String> {
    match decision {
        Decision::Allow { action, reason, skip_fingerprint_check } => {
            // Check fingerprints if needed (Learn mode always checks to track, others check to enforce)
            if !skip_fingerprint_check && guc::fingerprint_learning_enabled() {
                if let Some(reason_text) = fingerprints::enforce(ctx, command, mode, query) {
                    return Some(reason_text);
                }
            }
            log_activity(ctx, command, action.as_ref(), reason.as_deref(), query);
            None
        }
        Decision::Block {
            action,
            reason,
            error,
        } => {
            log_activity(ctx, command, action.as_ref(), reason.as_deref(), query);
            Some(error)
        }
    }
}

fn maybe_prune_activity_log() {
    // Only superuser should prune activity logs
    if !unsafe { pg_sys::superuser() } {
        return;
    }

    let retention_days = guc::activity_log_retention_days();
    let max_rows = guc::activity_log_max_rows();
    if retention_days <= 0 && max_rows <= 0 {
        return;
    }

    let interval = guc::activity_log_prune_interval_seconds().max(5) as i64;
    let now = unsafe { pg_sys::GetCurrentTimestamp() } / MICROS_PER_SEC;
    let last = LAST_PRUNE_EPOCH.load(Ordering::Relaxed);
    if now - last < interval {
        return;
    }
    if LAST_PRUNE_EPOCH
        .compare_exchange(last, now, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    Spi::connect_mut(|client| {
        if retention_days > 0 {
            let _ = spi_update(
                client,
                "DELETE FROM public.sql_firewall_activity_log \
                 WHERE log_time < now() - make_interval(days => $1::integer)",
                &[int4_arg(retention_days)],
            );
        }

        if max_rows > 0 {
            let capped = max_rows.min(i32::MAX as i64) as i32;
            let args = [int4_arg(capped)];
            let _ = spi_update(
                client,
                "WITH ranked AS (
                     SELECT log_id
                     FROM public.sql_firewall_activity_log
                     ORDER BY log_time DESC
                     OFFSET $1
                 )
                 DELETE FROM public.sql_firewall_activity_log
                 WHERE log_id IN (SELECT log_id FROM ranked)",
                &args,
            );
        }
    });
}

fn matches_builtin_injection(lower: &str) -> bool {
    lower.contains(" or '1'='1'")
        || lower.contains(" or 1=1")
        || lower.contains("' or '1'='1")
        || lower.contains("\" or \"1\"=\"1\"")
}
