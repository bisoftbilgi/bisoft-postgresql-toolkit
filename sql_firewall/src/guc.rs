use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};

use pgrx::{
    guc::{GucContext, GucFlags, GucRegistry, GucSetting, PostgresGucEnum},
    pg_sys::{self, errcodes::PgSqlErrorCode},
};

#[derive(Debug, Copy, Clone, Eq, PartialEq, PostgresGucEnum, Default)]
pub enum FirewallMode {
    #[default]
    Learn,
    Permissive,
    Enforce,
}

pub static FIREWALL_MODE: GucSetting<FirewallMode> =
    GucSetting::<FirewallMode>::new(FirewallMode::Learn);
pub static FIREWALL_ENABLED: GucSetting<bool> = GucSetting::<bool>::new(true);
// NOTE: ring_buffer_size removed - using fixed capacity (1024) in pending_approvals.rs
pub static RETENTION_DAYS: GucSetting<i32> = GucSetting::<i32>::new(30);
pub static ENABLE_KEYWORD_SCAN: GucSetting<bool> = GucSetting::<bool>::new(true);
pub static ENABLE_REGEX_SCAN: GucSetting<bool> = GucSetting::<bool>::new(true);
pub static ENABLE_QUIET_HOURS: GucSetting<bool> = GucSetting::<bool>::new(false);
pub static QUIET_HOURS_START: GucSetting<Option<CString>> =
    GucSetting::<Option<CString>>::new(None);
pub static QUIET_HOURS_END: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
pub static BLACKLISTED_KEYWORDS: GucSetting<Option<CString>> =
    GucSetting::<Option<CString>>::new(None);
pub static QUIET_HOURS_LOGGING: GucSetting<bool> = GucSetting::<bool>::new(true);
pub static ENABLE_RATE_LIMITING: GucSetting<bool> = GucSetting::<bool>::new(false);
pub static RATE_LIMIT_COUNT: GucSetting<i32> = GucSetting::<i32>::new(100);
pub static RATE_LIMIT_SECONDS: GucSetting<i32> = GucSetting::<i32>::new(60);
pub static COMMAND_LIMIT_SECONDS: GucSetting<i32> = GucSetting::<i32>::new(60);
pub static SELECT_LIMIT_COUNT: GucSetting<i32> = GucSetting::<i32>::new(0);
pub static INSERT_LIMIT_COUNT: GucSetting<i32> = GucSetting::<i32>::new(0);
pub static UPDATE_LIMIT_COUNT: GucSetting<i32> = GucSetting::<i32>::new(0);
pub static DELETE_LIMIT_COUNT: GucSetting<i32> = GucSetting::<i32>::new(0);
pub static ENABLE_APPLICATION_BLOCKING: GucSetting<bool> = GucSetting::<bool>::new(false);
pub static BLOCKED_APPLICATIONS: GucSetting<Option<CString>> =
    GucSetting::<Option<CString>>::new(None);
pub static ENABLE_IP_BLOCKING: GucSetting<bool> = GucSetting::<bool>::new(false);
pub static BLOCKED_IPS: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
pub static ENABLE_ROLE_IP_BINDING: GucSetting<bool> = GucSetting::<bool>::new(false);
pub static ROLE_IP_BINDINGS: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
pub static ALLOW_SUPERUSER_AUTH_BYPASS: GucSetting<bool> = GucSetting::<bool>::new(true);
pub static ENABLE_FINGERPRINT_LEARNING: GucSetting<bool> = GucSetting::<bool>::new(true);
pub static FINGERPRINT_LEARN_THRESHOLD: GucSetting<i32> = GucSetting::<i32>::new(5);
pub static ENABLE_ALERT_NOTIFICATIONS: GucSetting<bool> = GucSetting::<bool>::new(false);
pub static ALERT_CHANNEL: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
pub static SYSLOG_ALERTS: GucSetting<bool> = GucSetting::<bool>::new(false);
pub static ALERT_ONLY_ON_BLOCK: GucSetting<bool> = GucSetting::<bool>::new(true);
pub static ACTIVITY_LOG_RETENTION_DAYS: GucSetting<i32> = GucSetting::<i32>::new(30);
pub static APPROVAL_WORKER_DATABASE: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
pub static ACTIVITY_LOG_MAX_ROWS: GucSetting<i32> = GucSetting::<i32>::new(1_000_000);
pub static ACTIVITY_LOG_PRUNE_INTERVAL: GucSetting<i32> = GucSetting::<i32>::new(300);
pub static ENABLE_ACTIVITY_LOGGING: GucSetting<bool> = GucSetting::<bool>::new(true);

pub fn register() {
    GucRegistry::define_enum_guc(
        cstr(b"sql_firewall.mode\0"),
        cstr(b"Sets the firewall operation mode.\0"),
        cstr(b"Learn: Allow all + auto-approve (training), Permissive: Allow + warn + fingerprint check, Enforce: Block unapproved + log for admin review.\0"),
        &FIREWALL_MODE,
        GucContext::Suset,
        GucFlags::default(),
    );

    GucRegistry::define_bool_guc(
        cstr(b"sql_firewall.enabled\0"),
        cstr(b"Enable/disable SQL firewall globally (kill switch).\0"),
        cstr(b"When disabled, all hook processing is bypassed for emergency situations.\0"),
        &FIREWALL_ENABLED,
        GucContext::Suset,
        GucFlags::default(),
    );

    // NOTE: ring_buffer_size GUC removed - using fixed capacity (1024) for Phase 1
    // Will be made configurable in Phase 2 with proper shared memory reallocation

    GucRegistry::define_int_guc(
        cstr(b"sql_firewall.retention_days\0"),
        cstr(b"Number of days to retain audit logs.\0"),
        cstr(b"Logs older than this will be pruned by background worker. 0 = no retention limit.\0"),
        &RETENTION_DAYS,
        0,
        3650,
        GucContext::Suset,
        GucFlags::default(),
    );

    GucRegistry::define_bool_guc(
        cstr(b"sql_firewall.enable_keyword_scan\0"),
        cstr(b"Enable keyword scanning.\0"),
        cstr(b"Blocks statements that contain blacklisted keywords.\0"),
        &ENABLE_KEYWORD_SCAN,
        GucContext::Suset,
        GucFlags::default(),
    );

    GucRegistry::define_bool_guc(
        cstr(b"sql_firewall.enable_regex_scan\0"),
        cstr(b"Enable regex scanning.\0"),
        cstr(b"Evaluates statements against regex rules stored in the catalog.\0"),
        &ENABLE_REGEX_SCAN,
        GucContext::Suset,
        GucFlags::default(),
    );

    GucRegistry::define_bool_guc(
        cstr(b"sql_firewall.enable_quiet_hours\0"),
        cstr(b"Enable quiet hours.\0"),
        cstr(b"Blocks statements during configured quiet-hour windows.\0"),
        &ENABLE_QUIET_HOURS,
        GucContext::Suset,
        GucFlags::default(),
    );
    GucRegistry::define_bool_guc(
        cstr(b"sql_firewall.quiet_hours_log\0"),
        cstr(b"Log quiet-hours denials.\0"),
        cstr(b"If enabled, quiet-hours blocks emit WARNING entries to server log.\0"),
        &QUIET_HOURS_LOGGING,
        GucContext::Suset,
        GucFlags::default(),
    );
    GucRegistry::define_bool_guc(
        cstr(b"sql_firewall.enable_rate_limiting\0"),
        cstr(b"Enable global rate limiting.\0"),
        cstr(b"Limits number of queries per role over a rolling window.\0"),
        &ENABLE_RATE_LIMITING,
        GucContext::Suset,
        GucFlags::default(),
    );
    GucRegistry::define_int_guc(
        cstr(b"sql_firewall.rate_limit_count\0"),
        cstr(b"Max total queries allowed within the global window.\0"),
        cstr(b"Set to zero to disable.\0"),
        &RATE_LIMIT_COUNT,
        0,
        1000000,
        GucContext::Suset,
        GucFlags::default(),
    );
    GucRegistry::define_int_guc(
        cstr(b"sql_firewall.rate_limit_seconds\0"),
        cstr(b"Global rate limit window in seconds.\0"),
        cstr(b"Defines the size of the rolling window for global limits.\0"),
        &RATE_LIMIT_SECONDS,
        1,
        86400,
        GucContext::Suset,
        GucFlags::default(),
    );
    GucRegistry::define_int_guc(
        cstr(b"sql_firewall.command_limit_seconds\0"),
        cstr(b"Per-command rate-limit window in seconds.\0"),
        cstr(b"Applies to SELECT/INSERT/UPDATE/DELETE limits.\0"),
        &COMMAND_LIMIT_SECONDS,
        0,
        86400,
        GucContext::Suset,
        GucFlags::default(),
    );
    GucRegistry::define_int_guc(
        cstr(b"sql_firewall.select_limit_count\0"),
        cstr(b"Max SELECT commands allowed within the per-command window.\0"),
        cstr(b"Set to zero for no per-command limit.\0"),
        &SELECT_LIMIT_COUNT,
        0,
        1000000,
        GucContext::Suset,
        GucFlags::default(),
    );
    GucRegistry::define_int_guc(
        cstr(b"sql_firewall.insert_limit_count\0"),
        cstr(b"Max INSERT commands allowed within the per-command window.\0"),
        cstr(b"Set to zero for no per-command limit.\0"),
        &INSERT_LIMIT_COUNT,
        0,
        1000000,
        GucContext::Suset,
        GucFlags::default(),
    );
    GucRegistry::define_int_guc(
        cstr(b"sql_firewall.update_limit_count\0"),
        cstr(b"Max UPDATE commands allowed within the per-command window.\0"),
        cstr(b"Set to zero for no per-command limit.\0"),
        &UPDATE_LIMIT_COUNT,
        0,
        1000000,
        GucContext::Suset,
        GucFlags::default(),
    );
    GucRegistry::define_int_guc(
        cstr(b"sql_firewall.delete_limit_count\0"),
        cstr(b"Max DELETE commands allowed within the per-command window.\0"),
        cstr(b"Set to zero for no per-command limit.\0"),
        &DELETE_LIMIT_COUNT,
        0,
        1000000,
        GucContext::Suset,
        GucFlags::default(),
    );

    unsafe {
        GucRegistry::define_string_guc_with_hooks(
            cstr(b"sql_firewall.quiet_hours_start\0"),
            cstr(b"Quiet hours start (HH:MM).\0"),
            cstr(b"Defines when quiet hours begin.\0"),
            &QUIET_HOURS_START,
            GucContext::Suset,
            GucFlags::default(),
            Some(check_quiet_hours_start),
            None,
            None,
        );

        GucRegistry::define_string_guc_with_hooks(
            cstr(b"sql_firewall.quiet_hours_end\0"),
            cstr(b"Quiet hours end (HH:MM).\0"),
            cstr(b"Defines when quiet hours end.\0"),
            &QUIET_HOURS_END,
            GucContext::Suset,
            GucFlags::default(),
            Some(check_quiet_hours_end),
            None,
            None,
        );

        GucRegistry::define_string_guc_with_hooks(
            cstr(b"sql_firewall.blacklisted_keywords\0"),
            cstr(b"Comma-separated keywords to block.\0"),
            cstr(b"Queries containing these keywords (case-insensitive) are blocked.\0"),
            &BLACKLISTED_KEYWORDS,
            GucContext::Suset,
            GucFlags::default(),
            Some(check_keyword_list),
            None,
            None,
        );

        GucRegistry::define_bool_guc(
            cstr(b"sql_firewall.enable_application_blocking\0"),
            cstr(b"Enable blocking connections based on application_name.\0"),
            cstr(b"Rejects sessions whose application_name is listed in sql_firewall.blocked_applications.\0"),
            &ENABLE_APPLICATION_BLOCKING,
            GucContext::Suset,
            GucFlags::default(),
        );
        GucRegistry::define_string_guc_with_hooks(
            cstr(b"sql_firewall.blocked_applications\0"),
            cstr(b"Comma-separated list of application_name values to block.\0"),
            cstr(b"Exact matches will be rejected at authentication time.\0"),
            &BLOCKED_APPLICATIONS,
            GucContext::Suset,
            GucFlags::default(),
            None,
            None,
            None,
        );
        GucRegistry::define_bool_guc(
            cstr(b"sql_firewall.enable_ip_blocking\0"),
            cstr(b"Enable blocking connections based on client IP.\0"),
            cstr(b"Rejects sessions whose client IP appears in sql_firewall.blocked_ips.\0"),
            &ENABLE_IP_BLOCKING,
            GucContext::Suset,
            GucFlags::default(),
        );
        GucRegistry::define_string_guc_with_hooks(
            cstr(b"sql_firewall.blocked_ips\0"),
            cstr(b"Comma-separated list of IP addresses (text form) to block.\0"),
            cstr(b"Matches exact textual address as reported by libpq/auth.\0"),
            &BLOCKED_IPS,
            GucContext::Suset,
            GucFlags::default(),
            None,
            None,
            None,
        );
        GucRegistry::define_bool_guc(
            cstr(b"sql_firewall.enable_role_ip_binding\0"),
            cstr(b"Enable role-to-IP binding enforcement.\0"),
            cstr(b"Each entry in sql_firewall.role_ip_bindings constrains a role to specific IP addresses.\0"),
            &ENABLE_ROLE_IP_BINDING,
            GucContext::Suset,
            GucFlags::default(),
        );
        GucRegistry::define_string_guc_with_hooks(
            cstr(b"sql_firewall.role_ip_bindings\0"),
            cstr(b"Comma-separated list of role@ip entries (e.g., analyst@10.0.0.5).\0"),
            cstr(b"Only the listed IPs may be used by the specified roles when binding is enabled.\0"),
            &ROLE_IP_BINDINGS,
            GucContext::Suset,
            GucFlags::default(),
            None,
            None,
            None,
        );
        GucRegistry::define_bool_guc(
            cstr(b"sql_firewall.allow_superuser_auth_bypass\0"),
            cstr(b"Allow postgres superuser to bypass authentication guard.\0"),
            cstr(b"Set to false to enforce IP/application restrictions even for superusers.\0"),
            &ALLOW_SUPERUSER_AUTH_BYPASS,
            GucContext::Suset,
            GucFlags::default(),
        );
        GucRegistry::define_bool_guc(
            cstr(b"sql_firewall.enable_fingerprint_learning\0"),
            cstr(b"Enable adaptive learning for query fingerprints.\0"),
            cstr(b"Automatically approve frequently seen normalized queries when threshold met.\0"),
            &ENABLE_FINGERPRINT_LEARNING,
            GucContext::Suset,
            GucFlags::default(),
        );
        GucRegistry::define_int_guc(
            cstr(b"sql_firewall.fingerprint_learn_threshold\0"),
            cstr(b"Number of identical fingerprints required before auto-approval.\0"),
            cstr(b"Used only when learning mode is enabled and fingerprint learning is active.\0"),
            &FINGERPRINT_LEARN_THRESHOLD,
            1,
            1000,
            GucContext::Suset,
            GucFlags::default(),
        );
        GucRegistry::define_bool_guc(
            cstr(b"sql_firewall.enable_alert_notifications\0"),
            cstr(b"Emit NOTIFY alerts for firewall events.\0"),
            cstr(b"Requires sql_firewall.alert_channel to specify the channel name.\0"),
            &ENABLE_ALERT_NOTIFICATIONS,
            GucContext::Suset,
            GucFlags::default(),
        );
        GucRegistry::define_string_guc_with_hooks(
            cstr(b"sql_firewall.alert_channel\0"),
            cstr(b"LISTEN/NOTIFY channel used for firewall alerts.\0"),
            cstr(b"Defaults to 'sql_firewall_alerts' when set to NULL.\0"),
            &ALERT_CHANNEL,
            GucContext::Suset,
            GucFlags::default(),
            None,
            None,
            None,
        );
        GucRegistry::define_bool_guc(
            cstr(b"sql_firewall.syslog_alerts\0"),
            cstr(b"Mirror firewall alerts via syslog().\0"),
            cstr(b"Useful for forwarding to external SIEM/SOAR platforms.\0"),
            &SYSLOG_ALERTS,
            GucContext::Suset,
            GucFlags::default(),
        );
        GucRegistry::define_bool_guc(
            cstr(b"sql_firewall.alert_only_on_block\0"),
            cstr(b"Only emit alerts when a query is blocked.\0"),
            cstr(b"Set to false to alert on all firewall decisions.\0"),
            &ALERT_ONLY_ON_BLOCK,
            GucContext::Suset,
            GucFlags::default(),
        );
        GucRegistry::define_int_guc(
            cstr(b"sql_firewall.activity_log_retention_days\0"),
            cstr(b"Number of days to retain records in sql_firewall_activity_log.\0"),
            cstr(b"Older records will be purged automatically when rotation is enabled.\0"),
            &ACTIVITY_LOG_RETENTION_DAYS,
            1,
            3650,
            GucContext::Suset,
            GucFlags::default(),
        );
        GucRegistry::define_string_guc(
            cstr(b"sql_firewall.approval_worker_database\0"),
            cstr(b"Database for approval worker to connect to.\0"),
            cstr(b"Background worker will record pending approvals in this database. If not set, uses 'postgres'.\0"),
            &APPROVAL_WORKER_DATABASE,
            GucContext::Postmaster,
            GucFlags::default(),
        );
        GucRegistry::define_int_guc(
            cstr(b"sql_firewall.activity_log_max_rows\0"),
            cstr(b"Target maximum row count for sql_firewall_activity_log.\0"),
            cstr(b"Purge will delete oldest rows beyond this threshold.\0"),
            &ACTIVITY_LOG_MAX_ROWS,
            1000,
            100_000_000,
            GucContext::Suset,
            GucFlags::default(),
        );
        GucRegistry::define_int_guc(
            cstr(b"sql_firewall.activity_log_prune_interval_seconds\0"),
            cstr(b"Minimum seconds between background pruning attempts.\0"),
            cstr(b"Prevents excessive churn when logging heavily.\0"),
            &ACTIVITY_LOG_PRUNE_INTERVAL,
            5,
            86400,
            GucContext::Suset,
            GucFlags::default(),
        );
        GucRegistry::define_bool_guc(
            cstr(b"sql_firewall.enable_activity_logging\0"),
            cstr(b"Enable logging of firewall activity to activity_log table.\0"),
            cstr(b"Set to false to disable activity logging (blocked queries are always logged). Default: true.\0"),
            &ENABLE_ACTIVITY_LOGGING,
            GucContext::Suset,
            GucFlags::default(),
        );
    }
}

pub fn mode() -> FirewallMode {
    FIREWALL_MODE.get()
}

pub fn firewall_enabled() -> bool {
    FIREWALL_ENABLED.get()
}

// NOTE: ring_buffer_size() removed - using RING_CAPACITY constant in pending_approvals.rs

#[allow(dead_code)]
pub fn retention_days() -> i32 {
    RETENTION_DAYS.get()
}

pub fn keyword_scan_enabled() -> bool {
    ENABLE_KEYWORD_SCAN.get()
}

pub fn regex_scan_enabled() -> bool {
    ENABLE_REGEX_SCAN.get()
}

pub fn quiet_hours_enabled() -> bool {
    ENABLE_QUIET_HOURS.get()
}

pub fn quiet_hours_logging_enabled() -> bool {
    QUIET_HOURS_LOGGING.get()
}

pub fn quiet_hours_window() -> Option<(String, String)> {
    let start = QUIET_HOURS_START.get();
    let end = QUIET_HOURS_END.get();
    match (start, end) {
        (Some(s), Some(e)) => {
            let start = s.to_string_lossy().into_owned();
            let end = e.to_string_lossy().into_owned();
            Some((start, end))
        }
        _ => None,
    }
}

pub fn blacklisted_keywords() -> Vec<String> {
    BLACKLISTED_KEYWORDS
        .get()
        .as_deref()
        .map(|raw| {
            raw.to_string_lossy()
                .split(',')
                .map(|token| token.trim())
                .filter(|token| !token.is_empty())
                .map(|token| token.to_ascii_lowercase())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

pub fn rate_limit_enabled() -> bool {
    ENABLE_RATE_LIMITING.get()
}

pub fn rate_limit_count() -> i32 {
    RATE_LIMIT_COUNT.get()
}

pub fn rate_limit_seconds() -> i32 {
    RATE_LIMIT_SECONDS.get()
}

pub fn command_limit_seconds() -> i32 {
    COMMAND_LIMIT_SECONDS.get()
}

pub fn command_limit(command: &str) -> i32 {
    match command {
        "SELECT" => SELECT_LIMIT_COUNT.get(),
        "INSERT" => INSERT_LIMIT_COUNT.get(),
        "UPDATE" => UPDATE_LIMIT_COUNT.get(),
        "DELETE" => DELETE_LIMIT_COUNT.get(),
        _ => 0,
    }
}

pub fn application_blocking_enabled() -> bool {
    ENABLE_APPLICATION_BLOCKING.get()
}

pub fn blocked_applications() -> Vec<String> {
    BLOCKED_APPLICATIONS
        .get()
        .as_deref()
        .map(parse_csv)
        .unwrap_or_default()
}

pub fn ip_blocking_enabled() -> bool {
    ENABLE_IP_BLOCKING.get()
}

pub fn blocked_ips() -> Vec<String> {
    BLOCKED_IPS
        .get()
        .as_deref()
        .map(parse_csv)
        .unwrap_or_default()
}

pub fn role_ip_binding_enabled() -> bool {
    ENABLE_ROLE_IP_BINDING.get()
}

pub fn role_ip_bindings() -> Vec<(String, String)> {
    ROLE_IP_BINDINGS
        .get()
        .as_deref()
        .map(|raw| {
            parse_csv(raw)
                .into_iter()
                .filter_map(|entry| {
                    let (role, ip) = entry.split_once('@')?;
                    let role = role.trim();
                    let ip = ip.trim();
                    if role.is_empty() || ip.is_empty() {
                        return None;
                    }
                    Some((role.to_string(), ip.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn allow_superuser_auth_bypass() -> bool {
    ALLOW_SUPERUSER_AUTH_BYPASS.get()
}

pub fn fingerprint_learning_enabled() -> bool {
    ENABLE_FINGERPRINT_LEARNING.get()
}

#[allow(dead_code)]
pub fn fingerprint_learn_threshold() -> i32 {
    FINGERPRINT_LEARN_THRESHOLD.get()
}

pub fn alert_notifications_enabled() -> bool {
    ENABLE_ALERT_NOTIFICATIONS.get()
}

pub fn alert_channel() -> String {
    ALERT_CHANNEL
        .get()
        .map(|raw| raw.to_string_lossy().into_owned())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "sql_firewall_alerts".to_string())
}

pub fn syslog_alerts_enabled() -> bool {
    SYSLOG_ALERTS.get()
}

#[allow(dead_code)]
pub fn alert_only_on_block() -> bool {
    ALERT_ONLY_ON_BLOCK.get()
}

pub fn activity_log_retention_days() -> i32 {
    ACTIVITY_LOG_RETENTION_DAYS.get()
}

pub fn activity_log_max_rows() -> i64 {
    ACTIVITY_LOG_MAX_ROWS.get() as i64
}

pub fn activity_log_prune_interval_seconds() -> i32 {
    ACTIVITY_LOG_PRUNE_INTERVAL.get()
}

pub fn enable_activity_logging() -> bool {
    ENABLE_ACTIVITY_LOGGING.get()
}

fn cstr(bytes: &'static [u8]) -> &'static CStr {
    unsafe { CStr::from_bytes_with_nul_unchecked(bytes) }
}

#[pgrx::pg_guard]
unsafe extern "C-unwind" fn check_quiet_hours_start(
    newval: *mut *mut c_char,
    _extra: *mut *mut c_void,
    _source: pg_sys::GucSource::Type,
) -> bool {
    validate_hhmm_guc("sql_firewall.quiet_hours_start", newval)
}

#[pgrx::pg_guard]
unsafe extern "C-unwind" fn check_quiet_hours_end(
    newval: *mut *mut c_char,
    _extra: *mut *mut c_void,
    _source: pg_sys::GucSource::Type,
) -> bool {
    validate_hhmm_guc("sql_firewall.quiet_hours_end", newval)
}

#[pgrx::pg_guard]
unsafe extern "C-unwind" fn check_keyword_list(
    newval: *mut *mut c_char,
    _extra: *mut *mut c_void,
    _source: pg_sys::GucSource::Type,
) -> bool {
    if let Some(value) = cstring_to_option(newval) {
        if value.len() > 2048 {
            pgrx::ereport!(
                ERROR,
                PgSqlErrorCode::ERRCODE_INVALID_PARAMETER_VALUE,
                &format!(
                    "sql_firewall.blacklisted_keywords is too long ({} bytes, max 2048)",
                    value.len()
                )
            );
        }
    }
    true
}

unsafe fn validate_hhmm_guc(name: &str, newval: *mut *mut c_char) -> bool {
    if let Some(value) = cstring_to_option(newval) {
        if !is_valid_hhmm(&value) {
            pgrx::ereport!(
                ERROR,
                PgSqlErrorCode::ERRCODE_INVALID_PARAMETER_VALUE,
                &format!("{name} must be in HH:MM form, got '{value}'")
            );
        }
    }
    true
}

fn is_valid_hhmm(value: &str) -> bool {
    let mut parts = value.split(':');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(hour), Some(minute), None) => {
            if let (Ok(h), Ok(m)) = (hour.trim().parse::<i32>(), minute.trim().parse::<i32>()) {
                return (0..24).contains(&h) && (0..60).contains(&m);
            }
            false
        }
        _ => false,
    }
}

unsafe fn cstring_to_option(newval: *mut *mut c_char) -> Option<String> {
    if newval.is_null() {
        return None;
    }
    let ptr = *newval;
    if ptr.is_null() {
        None
    } else {
        Some(CStr::from_ptr(ptr).to_string_lossy().into_owned())
    }
}

fn parse_csv(raw: &CStr) -> Vec<String> {
    raw.to_string_lossy()
        .split(',')
        .map(|token| token.trim())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_string())
        .collect()
}

#[allow(dead_code)]
pub fn approval_worker_database() -> String {
    match APPROVAL_WORKER_DATABASE.get() {
        Some(db) => db.to_string_lossy().to_string(),
        None => "postgres".to_string(),
    }
}
