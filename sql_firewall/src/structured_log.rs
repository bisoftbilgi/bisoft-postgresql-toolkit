/// Structured logging module for sql_firewall_rs
/// Provides standardized, parseable log format for production monitoring

use crate::context::ExecutionContext;
use crate::guc::FirewallMode;

/// Log a blocked query with structured format
/// Format: [SQL_FIREWALL][BLOCKED][mode][user=X][db=Y][cmd=Z] Reason: message
#[allow(dead_code)]
pub fn log_block(ctx: &ExecutionContext, command: &str, mode: FirewallMode, reason: &str) {
    let user = ctx.role.as_deref().unwrap_or("unknown");
    let db = ctx.database.as_deref().unwrap_or("unknown");
    let app = ctx.application_name.as_deref().unwrap_or("unknown");
    let ip = ctx.client_addr.as_deref().unwrap_or("unknown");
    
    pgrx::warning!(
        "[SQL_FIREWALL][BLOCKED][{:?}][user={}][db={}][app={}][ip={}][cmd={}] {}",
        mode, user, db, app, ip, command, reason
    );
}

/// Log an allowed query in learning mode
/// Format: [SQL_FIREWALL][LEARNED][user=X][db=Y][cmd=Z] Query learned
#[allow(dead_code)]
pub fn log_learn(ctx: &ExecutionContext, command: &str, fingerprint: &str) {
    let user = ctx.role.as_deref().unwrap_or("unknown");
    let db = ctx.database.as_deref().unwrap_or("unknown");
    
    pgrx::log!(
        "[SQL_FIREWALL][LEARNED][user={}][db={}][cmd={}] Fingerprint: {}",
        user, db, command, fingerprint
    );
}

/// Log an allowed query in permissive mode
/// Format: [SQL_FIREWALL][ALLOWED][user=X][db=Y][cmd=Z] Query permitted
#[allow(dead_code)]
pub fn log_allow(ctx: &ExecutionContext, command: &str, mode: FirewallMode) {
    let user = ctx.role.as_deref().unwrap_or("unknown");
    let db = ctx.database.as_deref().unwrap_or("unknown");
    
    pgrx::log!(
        "[SQL_FIREWALL][ALLOWED][{:?}][user={}][db={}][cmd={}] Query permitted",
        mode, user, db, command
    );
}

/// Log rate limit violation
/// Format: [SQL_FIREWALL][RATE_LIMIT][user=X][db=Y] count/limit in window
#[allow(dead_code)]
pub fn log_rate_limit(ctx: &ExecutionContext, count: i32, limit: i32, window_secs: i32) {
    let user = ctx.role.as_deref().unwrap_or("unknown");
    let db = ctx.database.as_deref().unwrap_or("unknown");
    
    pgrx::warning!(
        "[SQL_FIREWALL][RATE_LIMIT][user={}][db={}] {}/{} queries in {}s window",
        user, db, count, limit, window_secs
    );
}

/// Log quiet hours block
/// Format: [SQL_FIREWALL][QUIET_HOURS][user=X][db=Y][cmd=Z] window
pub fn log_quiet_hours(ctx: &ExecutionContext, command: &str, start: &str, end: &str) {
    let user = ctx.role.as_deref().unwrap_or("unknown");
    let db = ctx.database.as_deref().unwrap_or("unknown");
    
    pgrx::warning!(
        "[SQL_FIREWALL][QUIET_HOURS][user={}][db={}][cmd={}] Blocked during {}-{} window",
        user, db, command, start, end
    );
}

/// Log regex pattern match
/// Format: [SQL_FIREWALL][REGEX_BLOCK][user=X][db=Y][cmd=Z] Pattern: regex
#[allow(dead_code)]
pub fn log_regex_block(ctx: &ExecutionContext, command: &str, pattern: &str) {
    let user = ctx.role.as_deref().unwrap_or("unknown");
    let db = ctx.database.as_deref().unwrap_or("unknown");
    
    pgrx::warning!(
        "[SQL_FIREWALL][REGEX_BLOCK][user={}][db={}][cmd={}] Pattern: {}",
        user, db, command, pattern
    );
}

/// Log keyword block
/// Format: [SQL_FIREWALL][KEYWORD_BLOCK][user=X][db=Y][cmd=Z] Keyword: word
#[allow(dead_code)]
pub fn log_keyword_block(ctx: &ExecutionContext, command: &str, keyword: &str) {
    let user = ctx.role.as_deref().unwrap_or("unknown");
    let db = ctx.database.as_deref().unwrap_or("unknown");
    
    pgrx::warning!(
        "[SQL_FIREWALL][KEYWORD_BLOCK][user={}][db={}][cmd={}] Blacklisted keyword: {}",
        user, db, command, keyword
    );
}

/// Log approval requirement
/// Format: [SQL_FIREWALL][APPROVAL_NEEDED][user=X][db=Y][cmd=Z] Command requires approval
#[allow(dead_code)]
pub fn log_approval_needed(ctx: &ExecutionContext, command: &str, mode: FirewallMode) {
    let user = ctx.role.as_deref().unwrap_or("unknown");
    let db = ctx.database.as_deref().unwrap_or("unknown");
    
    pgrx::warning!(
        "[SQL_FIREWALL][APPROVAL_NEEDED][{:?}][user={}][db={}][cmd={}] Command requires explicit approval",
        mode, user, db, command
    );
}

/// Log fingerprint mismatch in enforce mode
/// Format: [SQL_FIREWALL][FINGERPRINT_MISMATCH][user=X][db=Y][cmd=Z] Unknown query pattern
#[allow(dead_code)]
pub fn log_fingerprint_mismatch(ctx: &ExecutionContext, command: &str, fingerprint: &str) {
    let user = ctx.role.as_deref().unwrap_or("unknown");
    let db = ctx.database.as_deref().unwrap_or("unknown");
    
    pgrx::warning!(
        "[SQL_FIREWALL][FINGERPRINT_MISMATCH][user={}][db={}][cmd={}] Unknown pattern: {}",
        user, db, command, fingerprint
    );
}

/// Log connection policy violation
/// Format: [SQL_FIREWALL][CONNECTION_BLOCK][user=X][ip=Y][app=Z] Reason: message
#[allow(dead_code)]
pub fn log_connection_block(ctx: &ExecutionContext, reason: &str) {
    let user = ctx.role.as_deref().unwrap_or("unknown");
    let ip = ctx.client_addr.as_deref().unwrap_or("unknown");
    let app = ctx.application_name.as_deref().unwrap_or("unknown");
    
    pgrx::warning!(
        "[SQL_FIREWALL][CONNECTION_BLOCK][user={}][ip={}][app={}] {}",
        user, ip, app, reason
    );
}

/// Log INFO level for statistics (less verbose)
/// Format: [SQL_FIREWALL][INFO] message
#[allow(dead_code)]
pub fn log_info(message: &str) {
    pgrx::log!("[SQL_FIREWALL][INFO] {}", message);
}

/// Log ERROR level for critical issues
/// Format: [SQL_FIREWALL][ERROR] message
#[allow(dead_code)]
pub fn log_error(message: &str) {
    pgrx::error!("[SQL_FIREWALL][ERROR] {}", message);
}
