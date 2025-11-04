use bcrypt::{hash, verify, DEFAULT_COST};
use pgrx::bgworkers::{BackgroundWorker, BackgroundWorkerBuilder, SignalWakeFlags};
use pgrx::pg_sys;
use pgrx::pg_sys::ffi::pg_guard_ffi_boundary;
use pgrx::prelude::*;
use rand::Rng;
use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::os::raw::c_int;
use std::ptr;
use std::sync::{Mutex, Once};
use std::time::{Duration, Instant};

::pgrx::pg_module_magic!();

static BLACKLIST_INIT: Once = Once::new();
static BLACKLIST_CACHE: Mutex<Option<HashSet<String>>> = Mutex::new(None);

// Authentication event cache to prevent duplicate processing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthEventKind {
    Failed,
    Success,
}

#[derive(Debug, Clone)]
struct AuthEvent {
    username: String,
    kind: AuthEventKind,
    timestamp: Instant,
}

static AUTH_EVENT_CACHE: Mutex<Vec<AuthEvent>> = Mutex::new(Vec::new());

const LOCK_CACHE_SIZE: usize = 2048;
const LOCK_USERNAME_BYTES: usize = 64;
const MICROS_PER_SEC: i64 = 1_000_000;

#[repr(C)]
struct LockEntry {
    username: [u8; LOCK_USERNAME_BYTES],
    expires_at: pg_sys::TimestampTz,
}

impl LockEntry {
    const fn new() -> Self {
        LockEntry {
            username: [0; LOCK_USERNAME_BYTES],
            expires_at: 0,
        }
    }
}

#[repr(C)]
struct LockCache {
    lock: pg_sys::slock_t,
    entries: [LockEntry; LOCK_CACHE_SIZE],
}

static mut LOCK_CACHE: *mut LockCache = ptr::null_mut();

// Hook registration - ensures hooks are registered exactly once
static HOOK_INIT: Once = Once::new();
static CLIENT_AUTH_HOOK_INIT: Once = Once::new();

type ClientAuthHookRaw = unsafe extern "C" fn(port: *mut pg_sys::Port, status: c_int);
static mut PREV_CLIENT_AUTH_HOOK: Option<ClientAuthHookRaw> = None;

// Password complexity GUCs
static PASSWORD_MIN_LENGTH: pgrx::GucSetting<i32> = pgrx::GucSetting::<i32>::new(8);
static REQUIRE_UPPERCASE: pgrx::GucSetting<bool> = pgrx::GucSetting::<bool>::new(false);
static REQUIRE_LOWERCASE: pgrx::GucSetting<bool> = pgrx::GucSetting::<bool>::new(false);
static REQUIRE_DIGIT: pgrx::GucSetting<bool> = pgrx::GucSetting::<bool>::new(false);
static REQUIRE_SPECIAL: pgrx::GucSetting<bool> = pgrx::GucSetting::<bool>::new(false);
static PREVENT_USERNAME: pgrx::GucSetting<bool> = pgrx::GucSetting::<bool>::new(true);

// Password history GUCs
static PASSWORD_HISTORY_COUNT: pgrx::GucSetting<i32> = pgrx::GucSetting::<i32>::new(5);
static PASSWORD_REUSE_DAYS: pgrx::GucSetting<i32> = pgrx::GucSetting::<i32>::new(90);

// Password expiration GUCs
static PASSWORD_EXPIRY_DAYS: pgrx::GucSetting<i32> = pgrx::GucSetting::<i32>::new(90);
static PASSWORD_GRACE_LOGINS: pgrx::GucSetting<i32> = pgrx::GucSetting::<i32>::new(3);

// Failed login GUCs
static FAILED_LOGIN_MAX: pgrx::GucSetting<i32> = pgrx::GucSetting::<i32>::new(3);
static LOCKOUT_MINUTES: pgrx::GucSetting<i32> = pgrx::GucSetting::<i32>::new(2);

// Log monitoring GUCs for background worker
static LOG_DIRECTORY: pgrx::GucSetting<Option<CString>> =
    pgrx::GucSetting::<Option<CString>>::new(None);
static LOG_MONITOR_ENABLED: pgrx::GucSetting<bool> = pgrx::GucSetting::<bool>::new(true);

// ============================================================================
// Background Worker Safe SPI Execution
// ============================================================================

/// Background worker içinde güvenli SPI çağrısı (raw C SPI)
/// Bu fonksiyon PostgreSQL'in native C API'sini kullanarak
/// background worker context'inde güvenli SQL execution sağlar  
unsafe fn bg_execute_sql(sql: &str) {
    let c_sql = match CString::new(sql) {
        Ok(s) => s,
        Err(_) => {
            pgrx::warning!("Failed to create CString for SQL");
            return;
        }
    };

    // Transaction başlat
    pg_sys::SetCurrentStatementStartTimestamp();
    pg_sys::StartTransactionCommand();
    pg_sys::SPI_connect();
    pg_sys::PushActiveSnapshot(pg_sys::GetTransactionSnapshot());

    // SQL'i çalıştır
    let result = pg_sys::SPI_execute(c_sql.as_ptr(), false, 0);

    // SPI'den çık ve transaction'ı tamamla
    pg_sys::SPI_finish();
    pg_sys::PopActiveSnapshot();

    if result >= 0 {
        pg_sys::CommitTransactionCommand();
    } else {
        pgrx::warning!("SPI_execute failed with code: {}", result);
        pg_sys::AbortCurrentTransaction();
    }

    pg_sys::pgstat_report_stat(false);
}

// ============================================================================
// PostgreSQL Hook Integration
// ============================================================================

/// Register the check_password_hook to automatically validate passwords
/// This hook is called whenever a user password is set via CREATE USER, ALTER USER, or \password
unsafe fn register_password_check_hook() {
    static mut PREV_CHECK_PASSWORD_HOOK: pg_sys::check_password_hook_type = None;

    #[pg_guard]
    unsafe extern "C-unwind" fn password_check_hook(
        username: *const std::os::raw::c_char,
        shadow_pass: *const std::os::raw::c_char,
        password_type: pg_sys::PasswordType::Type,
        validuntil_time: pg_sys::Datum,
        validuntil_null: bool,
    ) {
        // Convert C strings to Rust
        let username_str = if username.is_null() {
            "unknown"
        } else {
            CStr::from_ptr(username).to_str().unwrap_or("unknown")
        };

        let password_str = if shadow_pass.is_null() {
            ""
        } else {
            CStr::from_ptr(shadow_pass).to_str().unwrap_or("")
        };

        // Only validate plaintext passwords (PASSWORD_TYPE_PLAINTEXT)
        // Skip already hashed passwords (PASSWORD_TYPE_MD5, PASSWORD_TYPE_SCRAM_SHA_256)
        if password_type == pg_sys::PasswordType::PASSWORD_TYPE_PLAINTEXT
            && !password_str.is_empty()
        {
            // Call our validation function
            match check_password(username_str, password_str) {
                Ok(_) => {
                    pgrx::log!("Password validation passed for user: {}", username_str);
                }
                Err(e) => {
                    // Password validation failed - report error to PostgreSQL
                    pgrx::error!("Password validation failed: {}", e);
                }
            }
        }

        // Call the previous hook if it exists
        if let Some(prev_hook) = PREV_CHECK_PASSWORD_HOOK {
            pg_guard_ffi_boundary(|| {
                prev_hook(
                    username,
                    shadow_pass,
                    password_type,
                    validuntil_time,
                    validuntil_null,
                )
            });
        }
    }

    // Save previous hook and install ours
    PREV_CHECK_PASSWORD_HOOK = pg_sys::check_password_hook;
    pg_sys::check_password_hook = Some(password_check_hook);
}

// ============================================================================
// Client Authentication Hook Integration
// ============================================================================

extern "C" {
    fn password_profile_port_username(port: *mut pg_sys::Port) -> *const std::os::raw::c_char;
    fn password_profile_register_client_auth_hook(
        hook: Option<ClientAuthHookRaw>,
    ) -> Option<ClientAuthHookRaw>;
}

#[inline]
fn encode_username(username: &str) -> [u8; LOCK_USERNAME_BYTES] {
    let mut buf = [0u8; LOCK_USERNAME_BYTES];
    let bytes = username.as_bytes();
    let len = bytes.len().min(LOCK_USERNAME_BYTES.saturating_sub(1));
    buf[..len].copy_from_slice(&bytes[..len]);
    buf
}

unsafe fn lock_cache_init() {
    if !LOCK_CACHE.is_null() {
        return;
    }

    let size = std::mem::size_of::<LockCache>();
    let mut found = false;
    let cache_ptr = pg_sys::ShmemInitStruct(
        c"password_profile_lock_cache".as_ptr(),
        size,
        &mut found as *mut bool,
    ) as *mut LockCache;

    if cache_ptr.is_null() {
        pgrx::error!("password_profile: failed to initialize shared lock cache");
    }

    if !found {
        (*cache_ptr).lock = 0;
        pg_sys::SpinLockInit(&mut (*cache_ptr).lock);
        for entry in (*cache_ptr).entries.iter_mut() {
            entry.username = [0; LOCK_USERNAME_BYTES];
            entry.expires_at = 0;
        }
        pgrx::log!(
            "password_profile: lock cache allocated ({} bytes)",
            std::mem::size_of::<LockCache>()
        );
    } else {
        pgrx::log!("password_profile: lock cache attached to existing segment");
    }

    LOCK_CACHE = cache_ptr;
}

unsafe fn lock_cache_set(username: &str, expires_at: pg_sys::TimestampTz) {
    if LOCK_CACHE.is_null() {
        pgrx::log!(
            "password_profile: lock_cache_set skipped (cache not initialized) for {}",
            username
        );
        return;
    }
    if expires_at <= pg_sys::GetCurrentTimestamp() {
        return;
    }

    let encoded = encode_username(username);
    let cache = &mut *LOCK_CACHE;
    let now = pg_sys::GetCurrentTimestamp();

    pg_sys::SpinLockAcquire(&mut cache.lock);

    if let Some(entry) = cache
        .entries
        .iter_mut()
        .find(|e| e.username[0] != 0 && e.username == encoded)
    {
        entry.expires_at = expires_at;
        pgrx::log!(
            "password_profile: lock cache update existing user={} expires_at={}",
            username,
            expires_at
        );
        pg_sys::SpinLockRelease(&mut cache.lock);
        return;
    }

    if let Some(entry) = cache
        .entries
        .iter_mut()
        .find(|e| e.username[0] == 0 || e.expires_at <= now)
    {
        entry.username = encoded;
        entry.expires_at = expires_at;
        pgrx::log!(
            "password_profile: lock cache set user={} expires_at={}",
            username,
            expires_at
        );
        pg_sys::SpinLockRelease(&mut cache.lock);
        return;
    }

    // No free slots - evict oldest entry (LRU)
    if let Some(oldest_entry) = cache
        .entries
        .iter_mut()
        .min_by_key(|e| e.expires_at)
    {
        let old_username = std::str::from_utf8(&oldest_entry.username)
            .unwrap_or("(invalid)")
            .trim_end_matches('\0');
        pgrx::warning!(
            "password_profile: LockCache full (2048 entries), evicting oldest entry: {}",
            old_username
        );
        oldest_entry.username = encoded;
        oldest_entry.expires_at = expires_at;
        pgrx::log!(
            "password_profile: lock cache evicted and set user={} expires_at={}",
            username,
            expires_at
        );
    } else {
        // Fallback: overwrite slot 0 (should never happen)
        cache.entries[0].username = encoded;
        cache.entries[0].expires_at = expires_at;
        pgrx::log!(
            "password_profile: lock cache overwrite slot0 user={} expires_at={}",
            username,
            expires_at
        );
    }

    pg_sys::SpinLockRelease(&mut cache.lock);
}

unsafe fn lock_cache_clear(username: &str) {
    if LOCK_CACHE.is_null() {
        return;
    }
    let encoded = encode_username(username);
    let cache = &mut *LOCK_CACHE;

    pg_sys::SpinLockAcquire(&mut cache.lock);
    for entry in cache.entries.iter_mut() {
        if entry.username[0] != 0 && entry.username == encoded {
            entry.username = [0; LOCK_USERNAME_BYTES];
            entry.expires_at = 0;
            pgrx::log!("password_profile: lock cache cleared user={}", username);
            break;
        }
    }
    pg_sys::SpinLockRelease(&mut cache.lock);
}

unsafe fn lock_cache_remaining_seconds(username: &str) -> Option<i64> {
    if LOCK_CACHE.is_null() {
        return None;
    }

    let encoded = encode_username(username);
    let cache = &mut *LOCK_CACHE;
    let now = pg_sys::GetCurrentTimestamp();
    let mut remaining = None;

    pg_sys::SpinLockAcquire(&mut cache.lock);
    for entry in cache.entries.iter() {
        if entry.username[0] == 0 {
            continue;
        }
        if entry.username == encoded && entry.expires_at > now {
            remaining = Some(((entry.expires_at - now) / MICROS_PER_SEC) as i64);
            break;
        }
    }
    pg_sys::SpinLockRelease(&mut cache.lock);

    let filtered = remaining.filter(|secs| *secs > 0);
    if filtered.is_none() {
        pgrx::log!(
            "password_profile: lock cache miss for {} (entry expired or not present)",
            username
        );
    }
    filtered
}

unsafe extern "C" fn client_auth_hook(port: *mut pg_sys::Port, status: c_int) {
    let username_ptr = password_profile_port_username(port);
    if !username_ptr.is_null() {
        if let Ok(username_str) = CStr::from_ptr(username_ptr).to_str() {
            // Check lockout BEFORE authentication - reject early
            if let Some(seconds) = lock_cache_remaining_seconds(username_str) {
                if seconds > 0 {
                    pgrx::log!(
                        "password_profile: LOCKOUT ENFORCED for {} (remaining {}s) - CONNECTION REJECTED",
                        username_str,
                        seconds
                    );

                    let minutes = seconds / 60;
                    let secs = seconds % 60;
                    pgrx::log!(
                        "password_profile: Account locked for user '{}'. Please wait {} minute(s) and {} second(s) before retrying.",
                        username_str,
                        minutes,
                        secs
                    );

                    add_timing_jitter();

                    // Call previous hook with failed status to reject connection
                    // Note: Cannot send custom error message to client from auth hook
                    // Client will see generic "password authentication failed"
                    // but lockout is ENFORCED and logged
                    if let Some(prev_hook) = PREV_CLIENT_AUTH_HOOK {
                        pg_guard_ffi_boundary(|| prev_hook(port, pg_sys::STATUS_EOF as c_int));
                    }
                    return; // Early exit - connection rejected
                }
            }

            // Log auth result for non-locked users
            if status == pg_sys::STATUS_OK as c_int {
                pgrx::log!("password_profile: auth_success user={}", username_str);
            } else {
                pgrx::log!("password_profile: auth_failure user={}", username_str);
            }
        }
    }

    // Preserve existing hook chain for normal auth flow
    if let Some(prev_hook) = PREV_CLIENT_AUTH_HOOK {
        pg_guard_ffi_boundary(|| prev_hook(port, status));
    }
}

fn register_client_auth_hook() {
    CLIENT_AUTH_HOOK_INIT.call_once(|| {
        unsafe {
            PREV_CLIENT_AUTH_HOOK =
                password_profile_register_client_auth_hook(Some(client_auth_hook));
            // Note: lock_cache_init() is called from shmem_startup_hook, not here
        }
        pgrx::log!("ClientAuthentication_hook registered");
    });
}

// ============================================================================
// Hook Initialization - Ensures hooks are registered exactly once
// ============================================================================

/// Ensures all hooks are registered. Safe to call multiple times.
/// This is called from SQL functions since _PG_init doesn't work with pgrx + CREATE EXTENSION
pub fn ensure_hooks_registered() {
    HOOK_INIT.call_once(|| {
        unsafe {
            register_log_hook();
            pgrx::log!("Hooks registered via ensure_hooks_registered()");
        }
        register_client_auth_hook();
    });
}

// ============================================================================
// Log Hook - Track Failed Logins via PostgreSQL Logs
// ============================================================================

extern "C" {
    #[link_name = "emit_log_hook"]
    static mut emit_log_hook: Option<unsafe extern "C" fn(edata: *mut pg_sys::ErrorData)>;
}

/// Register emit_log_hook to intercept PostgreSQL logs and detect failed logins
unsafe fn register_log_hook() {
    pgrx::log!("🔍 register_log_hook: Starting registration...");

    static mut PREV_LOG_HOOK: Option<unsafe extern "C" fn(edata: *mut pg_sys::ErrorData)> = None;

    unsafe extern "C" fn log_hook_impl(edata: *mut pg_sys::ErrorData) {
        // Call previous hook first (if exists)
        if let Some(prev_hook) = PREV_LOG_HOOK {
            prev_hook(edata);
        }

        if edata.is_null() {
            return;
        }

        let error_data = &*edata;

        // Check if this is an authentication error (elevel = ERROR or FATAL)
        // FATAL = 22 in PostgreSQL, ERROR = 21
        if error_data.elevel < 21 {
            return; // Skip non-error logs
        }

        // Get the error message
        let message = if error_data.message.is_null() {
            return;
        } else {
            match std::ffi::CStr::from_ptr(error_data.message).to_str() {
                Ok(s) => s,
                Err(_) => return,
            }
        };

        // Turkish: "password authentication failed for user"
        // English: "password authentication failed for user"
        // Both contain these keywords
        if !message.contains("password authentication failed")
            && !message.contains("parola doğrulaması başarısız")
        {
            return; // Not a failed login
        }

        // Extract username from message
        // English: "password authentication failed for user \"username\""
        // Turkish: "kullanıcısı için parola doğrulaması başarısız: \"username\""
        let username = if let Some(start_idx) = message.find("user \"") {
            let start = start_idx + 6; // After "user \""
            if let Some(end_idx) = message[start..].find('"') {
                &message[start..start + end_idx]
            } else {
                return;
            }
        } else if let Some(start_idx) = message.find("kullanıcısı için") {
            // Turkish format - username is before "kullanıcısı için"
            // Find it by searching backwards for quote
            if let Some(end_idx) = message[..start_idx].rfind('"') {
                if let Some(start_idx) = message[..end_idx].rfind('"') {
                    &message[start_idx + 1..end_idx]
                } else {
                    return;
                }
            } else {
                return;
            }
        } else {
            return; // Can't extract username
        };

        pgrx::log!("🚨 Failed login detected for user: {}", username);

        // Record the failed login attempt
        // Use direct SPI call - we're in a log hook context where SPI should be available
        // We use catch_unwind to prevent panics from crashing PostgreSQL
        let _ = std::panic::catch_unwind(|| {
            // Try to record using SPI if available
            // SPI might not be initialized in all contexts, so we gracefully handle errors
            if let Ok(_) = pgrx::Spi::run(&format!(
                "SELECT record_failed_login('{}')",
                username.replace("'", "''") // SQL injection protection
            )) {
                pgrx::log!("Recorded failed login for user: {}", username);
            }
        });
    }

    // Save previous hook and install ours
    PREV_LOG_HOOK = emit_log_hook;
    emit_log_hook = Some(log_hook_impl);

    pgrx::log!("Log hook registration complete");
}

#[no_mangle]
pub unsafe extern "C" fn _PG_init() {
    // CRITICAL TEST: Is _PG_init being called at all?
    pgrx::warning!(" _PG_init ÇAĞRILDI - BAŞLADI ");

    // Register shmem_request_hook to request shared memory space
    static mut PREV_SHMEM_REQUEST_HOOK: Option<unsafe extern "C-unwind" fn()> = None;

    unsafe extern "C-unwind" fn shmem_request_hook_impl() {
        if let Some(prev) = PREV_SHMEM_REQUEST_HOOK {
            prev();
        }
        pg_sys::RequestAddinShmemSpace(std::mem::size_of::<LockCache>());
    }

    PREV_SHMEM_REQUEST_HOOK = pg_sys::shmem_request_hook;
    pg_sys::shmem_request_hook = Some(shmem_request_hook_impl);

    // Register shmem_startup_hook to initialize the cache
    static mut PREV_SHMEM_STARTUP_HOOK: Option<unsafe extern "C-unwind" fn()> = None;

    unsafe extern "C-unwind" fn shmem_startup_hook_impl() {
        if let Some(prev) = PREV_SHMEM_STARTUP_HOOK {
            prev();
        }
        lock_cache_init();
    }

    PREV_SHMEM_STARTUP_HOOK = pg_sys::shmem_startup_hook;
    pg_sys::shmem_startup_hook = Some(shmem_startup_hook_impl);

    // Password complexity
    pgrx::GucRegistry::define_int_guc(
        c"password_profile.min_length",
        c"Minimum password length",
        c"Minimum characters required",
        &PASSWORD_MIN_LENGTH,
        1,
        128,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_bool_guc(
        c"password_profile.require_uppercase",
        c"Require at least one uppercase letter",
        c"Password must contain A-Z",
        &REQUIRE_UPPERCASE,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_bool_guc(
        c"password_profile.require_lowercase",
        c"Require at least one lowercase letter",
        c"Password must contain a-z",
        &REQUIRE_LOWERCASE,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_bool_guc(
        c"password_profile.require_digit",
        c"Require at least one digit",
        c"Password must contain 0-9",
        &REQUIRE_DIGIT,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_bool_guc(
        c"password_profile.require_special",
        c"Require at least one special character",
        c"Password must contain special chars",
        &REQUIRE_SPECIAL,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_bool_guc(
        c"password_profile.prevent_username",
        c"Prevent password from containing username",
        c"Username cannot be part of password",
        &PREVENT_USERNAME,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    // Password history
    pgrx::GucRegistry::define_int_guc(
        c"password_profile.password_history_count",
        c"Number of previous passwords to check",
        c"Prevent reuse of last N passwords",
        &PASSWORD_HISTORY_COUNT,
        0,
        24,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_int_guc(
        c"password_profile.password_reuse_days",
        c"Days before password can be reused",
        c"Prevent reuse within time window",
        &PASSWORD_REUSE_DAYS,
        0,
        3650,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    // Password expiration
    pgrx::GucRegistry::define_int_guc(
        c"password_profile.password_expiry_days",
        c"Days before password expires",
        c"Force password change after N days (0=disabled)",
        &PASSWORD_EXPIRY_DAYS,
        0,
        3650,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_int_guc(
        c"password_profile.password_grace_logins",
        c"Grace logins after expiry",
        c"Number of logins allowed after expiry",
        &PASSWORD_GRACE_LOGINS,
        0,
        10,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    // Failed login lockout
    pgrx::GucRegistry::define_int_guc(
        c"password_profile.failed_login_max",
        c"Maximum failed login attempts",
        c"Lock account after this many failures",
        &FAILED_LOGIN_MAX,
        1,
        100,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_int_guc(
        c"password_profile.lockout_minutes",
        c"Account lockout duration",
        c"Minutes to lock account after max failures",
        &LOCKOUT_MINUTES,
        1,
        1440,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    // Log monitoring GUCs
    pgrx::GucRegistry::define_string_guc(
        c"password_profile.log_directory",
        c"PostgreSQL log directory path",
        c"If not set, uses PostgreSQL's log_directory setting",
        &LOG_DIRECTORY,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_bool_guc(
        c"password_profile.log_monitor_enabled",
        c"Enable automatic failed login tracking via log monitoring",
        c"Requires shared_preload_libraries",
        &LOG_MONITOR_ENABLED,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    // Background worker for log monitoring
    if LOG_MONITOR_ENABLED.get() {
        BackgroundWorkerBuilder::new("password_profile_log_monitor")
            .set_function("log_monitor_main")
            .set_library("password_profile_pure") // MUST match Cargo.toml [package] name
            .set_argument(None::<i32>.into_datum())
            .enable_spi_access()
            .load();
        pgrx::info!("password_profile: log monitor background worker registered");
    }

    // Register check_password_hook
    pgrx::log!("password_profile: Registering hooks...");
    unsafe {
        register_password_check_hook();
        pgrx::log!("password_profile: Password check hook registered");
    }
    register_client_auth_hook();

    pgrx::log!("password_profile initialized with all features");
}

// Safe SQL escaping helper - uses PostgreSQL's quote_literal for proper escaping
fn quote_literal(s: &str) -> Result<String, Box<dyn std::error::Error>> {
    let query = format!(
        "SELECT quote_literal({})",
        // First escape for Rust string, then PostgreSQL will properly escape
        format!("'{}'", s.replace("'", "''"))
    );
    Spi::get_one::<String>(&query)?.ok_or_else(|| "Failed to quote string".into())
}

// Timing attack prevention: Add small random delay on auth failures
// This prevents attackers from measuring timing differences to gain info
#[inline(never)] // Prevent optimization from removing this
fn add_timing_jitter() {
    let mut rng = rand::thread_rng();
    // Random delay between 10-50ms to mask timing variations
    let delay_ms = rng.gen_range(10..50);
    pgrx::log!("⏰ Adding {}ms timing jitter", delay_ms);
    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
}

fn init_blacklist() {
    BLACKLIST_INIT.call_once(|| {
        let content = include_str!("../blacklist.txt");
        let set: HashSet<String> = content
            .lines()
            .map(|l| l.trim().to_lowercase())
            .filter(|l| !l.is_empty())
            .collect();
        pgrx::info!("Loaded {} passwords", set.len());
        if let Ok(mut cache) = BLACKLIST_CACHE.lock() {
            *cache = Some(set);
        }
    });
}

fn is_blacklisted(password: &str) -> bool {
    init_blacklist();
    BLACKLIST_CACHE
        .lock()
        .ok()
        .and_then(|c| c.as_ref().map(|s| s.contains(&password.to_lowercase())))
        .unwrap_or(false)
}

#[pg_extern]
fn check_password(username: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
    // 1. Length check
    if password.len() < PASSWORD_MIN_LENGTH.get() as usize {
        add_timing_jitter(); // Prevent timing attacks
        return Err("Password too short".into());
    }

    // 2. Complexity checks
    if REQUIRE_UPPERCASE.get() && !password.chars().any(|c| c.is_uppercase()) {
        add_timing_jitter();
        return Err("Password must contain at least one uppercase letter".into());
    }

    if REQUIRE_LOWERCASE.get() && !password.chars().any(|c| c.is_lowercase()) {
        add_timing_jitter();
        return Err("Password must contain at least one lowercase letter".into());
    }

    if REQUIRE_DIGIT.get() && !password.chars().any(|c| c.is_ascii_digit()) {
        add_timing_jitter();
        return Err("Password must contain at least one digit".into());
    }

    if REQUIRE_SPECIAL.get() && !password.chars().any(|c| !c.is_alphanumeric()) {
        add_timing_jitter();
        return Err("Password must contain at least one special character".into());
    }

    // 3. Username prevention
    if PREVENT_USERNAME.get() && !username.is_empty() {
        let pwd_lower = password.to_lowercase();
        let user_lower = username.to_lowercase();
        if pwd_lower.contains(&user_lower) {
            add_timing_jitter();
            return Err("Password cannot contain username".into());
        }
    }

    // 4. Blacklist check
    if is_blacklisted(password) {
        add_timing_jitter();
        return Err("Password is in blacklist (too common)".into());
    }

    // 5. Password history check (if enabled)
    if PASSWORD_HISTORY_COUNT.get() > 0 {
        let username_quoted = quote_literal(username)?;
        let history_count = PASSWORD_HISTORY_COUNT.get();

        // Get recent password hashes using array aggregation - SAFE: username is properly quoted
        let query = format!(
            "SELECT COALESCE(array_agg(password_hash), ARRAY[]::text[]) 
             FROM (
                 SELECT password_hash FROM password_profile.password_history 
                 WHERE username = {} 
                 ORDER BY changed_at DESC LIMIT {}
             ) t",
            username_quoted, history_count
        );

        if let Ok(Some(hashes)) = Spi::get_one::<Vec<String>>(&query) {
            for stored_hash in hashes {
                // Try bcrypt verification (new format)
                if verify(password, &stored_hash).unwrap_or(false) {
                    add_timing_jitter();
                    return Err(format!(
                        "Password was used recently. Cannot reuse last {} passwords.",
                        history_count
                    )
                    .into());
                }

                // Legacy: also check MD5 for backward compatibility (32 hex chars = MD5)
                if stored_hash.len() == 32 && stored_hash.chars().all(|c| c.is_ascii_hexdigit()) {
                    let pwd_hash_md5 = format!("{:x}", md5::compute(password.as_bytes()));
                    if stored_hash == pwd_hash_md5 {
                        add_timing_jitter();
                        return Err(format!(
                            "Password was used recently. Cannot reuse last {} passwords.",
                            history_count
                        )
                        .into());
                    }
                }
            }
        }
    }

    // 6. Time-based reuse check
    if PASSWORD_REUSE_DAYS.get() > 0 {
        let username_quoted = quote_literal(username)?;
        let reuse_days = PASSWORD_REUSE_DAYS.get();

        let query = format!(
            "SELECT COALESCE(array_agg(password_hash), ARRAY[]::text[]) 
             FROM password_profile.password_history 
             WHERE username = {} 
             AND changed_at > now() - interval '{} days'",
            username_quoted, reuse_days
        );

        if let Ok(Some(hashes)) = Spi::get_one::<Vec<String>>(&query) {
            for stored_hash in hashes {
                // Try bcrypt verification (new format)
                if verify(password, &stored_hash).unwrap_or(false) {
                    add_timing_jitter();
                    return Err(format!("Password was used within last {} days", reuse_days).into());
                }

                // Legacy: also check MD5 for backward compatibility (32 hex chars = MD5)
                if stored_hash.len() == 32 && stored_hash.chars().all(|c| c.is_ascii_hexdigit()) {
                    let pwd_hash_md5 = format!("{:x}", md5::compute(password.as_bytes()));
                    if stored_hash == pwd_hash_md5 {
                        add_timing_jitter();
                        return Err(
                            format!("Password was used within last {} days", reuse_days).into()
                        );
                    }
                }
            }
        }
    }

    // 7. Custom validation hook (if function exists) - silently skip if not exists
    let hook_check = format!(
        "SELECT EXISTS(
            SELECT 1 FROM pg_proc p
            JOIN pg_namespace n ON p.pronamespace = n.oid
            WHERE n.nspname = 'password_profile' AND p.proname = 'custom_password_check'
        )"
    );

    if let Ok(Some(true)) = Spi::get_one::<bool>(&hook_check) {
        let username_quoted = quote_literal(username)?;
        let password_quoted = quote_literal(password)?;

        let hook_query = format!(
            "SELECT password_profile.custom_password_check({}, {})",
            username_quoted, password_quoted
        );

        if let Ok(Some(msg)) = Spi::get_one::<String>(&hook_query) {
            if !msg.is_empty() && msg != "OK" {
                add_timing_jitter();
                return Err(msg.into());
            }
        }
    }

    Ok("Password accepted".to_string())
}

#[pg_extern]
fn init_login_attempts_table() -> Result<String, Box<dyn std::error::Error>> {
    Spi::run("CREATE SCHEMA IF NOT EXISTS password_profile")?;

    // Login attempts table
    Spi::run(
        "CREATE TABLE IF NOT EXISTS password_profile.login_attempts (
            username TEXT PRIMARY KEY,
            fail_count INT DEFAULT 0,
            last_fail TIMESTAMPTZ DEFAULT now(),
            lockout_until TIMESTAMPTZ
        )",
    )?;

    // Password history table
    Spi::run(
        "CREATE TABLE IF NOT EXISTS password_profile.password_history (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            changed_at TIMESTAMPTZ DEFAULT now()
        )",
    )?;

    Spi::run(
        "CREATE INDEX IF NOT EXISTS idx_pwd_history_user 
         ON password_profile.password_history (username, changed_at DESC)",
    )?;

    // Password expiry table
    Spi::run(
        "CREATE TABLE IF NOT EXISTS password_profile.password_expiry (
            username TEXT PRIMARY KEY,
            last_changed TIMESTAMPTZ DEFAULT now(),
            must_change_by TIMESTAMPTZ,
            grace_logins_remaining INT DEFAULT 0
        )",
    )?;

    // Blacklist table (optional, overrides file)
    Spi::run(
        "CREATE TABLE IF NOT EXISTS password_profile.blacklist (
            password TEXT PRIMARY KEY,
            added_at TIMESTAMPTZ DEFAULT now(),
            reason TEXT
        )",
    )?;

    Ok("All tables created successfully".to_string())
}

#[pg_extern]
fn record_failed_login(username: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Ensure hooks are registered on first call
    ensure_hooks_registered();

    let username_quoted = quote_literal(username)?;
    
    // Get user-specific lockout_minutes from pg_user.useconfig or use global default
    let lockout_min = Spi::get_one::<i32>(&format!(
        "SELECT COALESCE(
            (SELECT substring(cfg FROM 'password_profile\\.lockout_minutes=([0-9]+)')::int
             FROM unnest((SELECT useconfig FROM pg_user WHERE usename = {})) AS cfg
             WHERE cfg LIKE 'password_profile.lockout_minutes=%'),
            {}
        )",
        username_quoted, LOCKOUT_MINUTES.get()
    ))?.unwrap_or(LOCKOUT_MINUTES.get());
    
    // Get user-specific failed_login_max from pg_user.useconfig or use global default
    let max_fails = Spi::get_one::<i32>(&format!(
        "SELECT COALESCE(
            (SELECT substring(cfg FROM 'password_profile\\.failed_login_max=([0-9]+)')::int
             FROM unnest((SELECT useconfig FROM pg_user WHERE usename = {})) AS cfg
             WHERE cfg LIKE 'password_profile.failed_login_max=%'),
            {}
        )",
        username_quoted, FAILED_LOGIN_MAX.get()
    ))?.unwrap_or(FAILED_LOGIN_MAX.get());

    pgrx::log!(
        "password_profile: User {} - lockout_minutes={}, max_fails={}",
        username, lockout_min, max_fails
    );

    // First, clean up ONLY truly expired lockouts (not NULL, and past expiration)
    let cleanup_query = format!(
        "UPDATE password_profile.login_attempts 
         SET fail_count = 0, lockout_until = NULL
         WHERE username = {} AND lockout_until IS NOT NULL AND lockout_until <= now()",
        username_quoted
    );
    pgrx::log!("password_profile: Running cleanup query: {}", cleanup_query);
    Spi::run(&cleanup_query)?;

    let query = format!(
        "INSERT INTO password_profile.login_attempts (username, fail_count, last_fail, lockout_until)
         VALUES ({}, 1, now(), NULL)
         ON CONFLICT (username) DO UPDATE SET
             fail_count = password_profile.login_attempts.fail_count + 1,
             last_fail = now(),
             lockout_until = CASE
                 WHEN password_profile.login_attempts.fail_count + 1 >= {}
                 THEN now() + interval '{} minutes'
                 ELSE NULL
             END",
        username_quoted, max_fails, lockout_min
    );

    pgrx::log!("password_profile: Running insert/update query: {}", query);
    Spi::run(&query)?;
    pgrx::log!("password_profile: Query completed successfully");
    pgrx::log!(
        "password_profile: record_failed_login calling sync_lock_cache for {}",
        username
    );
    sync_lock_cache(username, max_fails)?;
    Ok("Failed login recorded".to_string())
}

#[pg_extern]
fn clear_login_attempts(username: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Security check: Only superuser or the same user can clear attempts
    let current_user = Spi::get_one::<String>("SELECT current_user::text")?
        .ok_or("Failed to get current user")?;
    
    let current_user_quoted = quote_literal(&current_user)?;
    let is_superuser = Spi::get_one::<bool>(&format!(
        "SELECT usesuper FROM pg_user WHERE usename = {}",
        current_user_quoted
    ))?
    .unwrap_or(false);
    
    if !is_superuser && current_user != username {
        return Err(format!(
            "Permission denied: Only superuser or user '{}' can clear their login attempts",
            username
        ).into());
    }
    
    let username_quoted = quote_literal(username)?;
    let query = format!(
        "DELETE FROM password_profile.login_attempts WHERE username = {}",
        username_quoted
    );
    Spi::run(&query)?;
    unsafe {
        lock_cache_clear(username);
    }
    Ok("Login attempts cleared".to_string())
}

#[pg_extern]
fn is_user_locked(username: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let username_quoted = quote_literal(username)?;
    let query = format!(
        "SELECT 1 FROM password_profile.login_attempts 
         WHERE username = {} AND lockout_until > now() LIMIT 1",
        username_quoted
    );

    match Spi::get_one::<i32>(&query) {
        Ok(Some(_)) => Ok(true),
        Ok(None) => Ok(false),
        Err(_) => Ok(false), // Table doesn't exist or other error
    }
}

#[pg_extern]
fn check_user_access(username: &str) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(seconds) = unsafe { lock_cache_remaining_seconds(username) } {
        if seconds > 0 {
            let minutes = seconds / 60;
            let secs = seconds % 60;
            return Err(format!(
                "Account locked! Please wait {} minute(s) and {} second(s). Too many failed login attempts.",
                minutes, secs
            )
            .into());
        }
    }

    let username_quoted = quote_literal(username)?;

    // Check if locked and get remaining time
    let query = format!(
        "SELECT EXTRACT(EPOCH FROM (lockout_until - now()))::int AS seconds_left
         FROM password_profile.login_attempts 
         WHERE username = {} AND lockout_until > now()",
        username_quoted
    );

    match Spi::get_one::<i32>(&query) {
        Ok(Some(seconds)) if seconds > 0 => {
            let minutes = seconds / 60;
            let secs = seconds % 60;
            Err(format!(
                "Account locked! Please wait {} minute(s) and {} second(s). Too many failed login attempts.",
                minutes, secs
            ).into())
        }
        _ => Ok("Access granted".to_string()),
    }
}

// Password history functions
#[pg_extern]
fn record_password_change(
    username: &str,
    new_password: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let username_quoted = quote_literal(username)?;

    // Hash password with bcrypt (secure) - returns a string like "$2b$12$..."
    let pwd_hash =
        hash(new_password, DEFAULT_COST).map_err(|e| format!("Failed to hash password: {}", e))?;
    let hash_quoted = quote_literal(&pwd_hash)?;

    // Insert into history
    let query = format!(
        "INSERT INTO password_profile.password_history (username, password_hash, changed_at) 
         VALUES ({}, {}, now())",
        username_quoted, hash_quoted
    );
    Spi::run(&query)?;

    // Update expiry
    let expiry_days = PASSWORD_EXPIRY_DAYS.get();
    if expiry_days > 0 {
        let expiry_query = format!(
            "INSERT INTO password_profile.password_expiry (username, last_changed, must_change_by, grace_logins_remaining)
             VALUES ({}, now(), now() + interval '{} days', {})
             ON CONFLICT (username) DO UPDATE SET
                 last_changed = now(),
                 must_change_by = now() + interval '{} days',
                 grace_logins_remaining = {}",
            username_quoted, expiry_days, PASSWORD_GRACE_LOGINS.get(), expiry_days, PASSWORD_GRACE_LOGINS.get()
        );
        Spi::run(&expiry_query)?;
    }

    Ok("Password change recorded".to_string())
}

#[pg_extern]
fn check_password_expiry(username: &str) -> Result<String, Box<dyn std::error::Error>> {
    if PASSWORD_EXPIRY_DAYS.get() == 0 {
        return Ok("Password expiry disabled".to_string());
    }

    let username_quoted = quote_literal(username)?;

    // Check if expired
    let query = format!(
        "SELECT grace_logins_remaining
         FROM password_profile.password_expiry 
         WHERE username = {} AND must_change_by < now()",
        username_quoted
    );

    match Spi::get_one::<i32>(&query) {
        Ok(Some(grace)) if grace > 0 => {
            Err(format!("Password expired! {} grace login(s) remaining.", grace).into())
        }
        Ok(Some(_)) => Err("Password expired! No grace logins remaining.".into()),
        _ => Ok("Password valid".to_string()),
    }
}

#[pg_extern]
fn add_to_blacklist(
    password: &str,
    reason: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let password_quoted = quote_literal(password)?;
    let reason_quoted = quote_literal(reason.unwrap_or("Admin added"))?;

    let query = format!(
        "INSERT INTO password_profile.blacklist (password, added_at, reason)
         VALUES ({}, now(), {})
         ON CONFLICT (password) DO NOTHING",
        password_quoted, reason_quoted
    );

    Spi::run(&query)?;
    Ok("Added to blacklist".to_string())
}

#[pg_extern]
fn remove_from_blacklist(password: &str) -> Result<String, Box<dyn std::error::Error>> {
    let password_quoted = quote_literal(password)?;
    let query = format!(
        "DELETE FROM password_profile.blacklist WHERE password = {}",
        password_quoted
    );

    Spi::run(&query)?;
    Ok("Removed from blacklist".to_string())
}

#[pg_extern]
fn get_password_stats(username: &str) -> Result<String, Box<dyn std::error::Error>> {
    let username_quoted = quote_literal(username)?;

    // Get various stats
    let history_query = format!(
        "SELECT COUNT(*) FROM password_profile.password_history WHERE username = {}",
        username_quoted
    );
    let history_count = Spi::get_one::<i64>(&history_query)
        .unwrap_or(Some(0))
        .unwrap_or(0);

    let expiry_query = format!(
        "SELECT EXTRACT(EPOCH FROM (must_change_by - now()))::int / 86400
         FROM password_profile.password_expiry WHERE username = {}",
        username_quoted
    );
    let days_until_expiry = Spi::get_one::<i32>(&expiry_query).unwrap_or(None);

    let failed_query = format!(
        "SELECT fail_count FROM password_profile.login_attempts WHERE username = {}",
        username_quoted
    );
    let failed_attempts = Spi::get_one::<i32>(&failed_query)
        .unwrap_or(Some(0))
        .unwrap_or(0);

    let stats = format!(
        "Password History: {} changes | Days until expiry: {} | Failed attempts: {}",
        history_count,
        days_until_expiry.map_or("N/A".to_string(), |d| d.to_string()),
        failed_attempts
    );

    Ok(stats)
}

/// Check if an authentication event should be processed or skipped (duplicate)
/// Returns true if the event should be processed, false if it's a recent duplicate
fn should_process_auth_event(username: &str, kind: AuthEventKind) -> bool {
    let mut cache = match AUTH_EVENT_CACHE.lock() {
        Ok(c) => c,
        Err(poisoned) => {
            pgrx::warning!("AUTH_EVENT_CACHE mutex poisoned, recovering");
            poisoned.into_inner()
        }
    };
    let now = Instant::now();

    // Clean up old events (older than 2 seconds)
    cache.retain(|event| now.duration_since(event.timestamp) < Duration::from_millis(2000));

    // Check if we've seen this event recently (within 1.5 seconds)
    let is_duplicate = cache.iter().any(|event| {
        event.username == username
            && event.kind == kind
            && now.duration_since(event.timestamp) < Duration::from_millis(1500)
    });

    if is_duplicate {
        return false; // Skip duplicate
    }

    // Add to cache
    cache.push(AuthEvent {
        username: username.to_string(),
        kind,
        timestamp: now,
    });

    true // Process this event
}

fn sync_lock_cache(username: &str, max_fails: i32) -> Result<(), Box<dyn std::error::Error>> {
    pgrx::log!(
        "password_profile: sync_lock_cache called for username={}, max_fails={}",
        username,
        max_fails
    );

    let username_quoted = quote_literal(username)?;
    let status_query = format!(
        "SELECT fail_count::bigint,
                GREATEST(
                    COALESCE(ROUND(EXTRACT(EPOCH FROM (lockout_until - now())))::bigint, 0),
                    0
                )
         FROM password_profile.login_attempts
         WHERE username = {}",
        username_quoted
    );

    match Spi::get_two::<i64, i64>(&status_query) {
        Ok((Some(fails), Some(remaining_secs))) => {
            pgrx::log!(
                "password_profile: sync_lock_cache query result: fails={}, remaining_secs={}, max_fails={}",
                fails, remaining_secs, max_fails
            );
            unsafe {
                if fails >= max_fails as i64 && remaining_secs > 0 {
                    // Active lockout - add to cache
                    let now = pg_sys::GetCurrentTimestamp();
                    let delta = remaining_secs.saturating_mul(MICROS_PER_SEC);
                    let expires_at = now.saturating_add(delta);
                    pgrx::log!(
                        "password_profile: Calling lock_cache_set with expires_at={}",
                        expires_at
                    );
                    lock_cache_set(username, expires_at);
                } else if fails >= max_fails as i64 && remaining_secs <= 0 {
                    // Lockout expired - clear cache and delete DB record
                    pgrx::log!("password_profile: Lockout EXPIRED (fails={} >= max={} BUT remaining={} <= 0), clearing cache and DB", fails, max_fails, remaining_secs);
                    lock_cache_clear(username);
                    let clear_query = format!(
                        "DELETE FROM password_profile.login_attempts WHERE username = {}",
                        username_quoted
                    );
                    let _ = Spi::run(&clear_query);
                    pgrx::log!(
                        "password_profile: Cleared expired lockout record for {}",
                        username
                    );
                } else {
                    // Not locked yet (fails < max) - just clear cache
                    pgrx::log!("password_profile: Not locked yet (fails={} < max={}), clearing cache only", fails, max_fails);
                    lock_cache_clear(username);
                }
            }
        }
        Ok(_) => {
            pgrx::log!("password_profile: sync_lock_cache query returned None, clearing cache");
            unsafe {
                lock_cache_clear(username);
            }
        }
        Err(e) => {
            pgrx::log!(
                "password_profile: sync_lock_cache query error: {}, clearing cache",
                e
            );
            unsafe {
                lock_cache_clear(username);
            }
        }
    }

    Ok(())
}

/// Background worker main function for log monitoring
/// Monitors PostgreSQL log files for failed/successful authentication events
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn log_monitor_main(_arg: pg_sys::Datum) {
    use std::fs::File;
    use std::io::{BufRead, BufReader, Seek, SeekFrom};
    use std::path::{Path, PathBuf};
    use std::thread;
    use std::time::Duration;

    BackgroundWorker::attach_signal_handlers(SignalWakeFlags::SIGHUP | SignalWakeFlags::SIGTERM);

    // Connect to database (required for SPI operations)
    BackgroundWorker::connect_worker_to_spi(Some("postgres"), None);

    pgrx::log!("password_profile: Log monitor background worker started");

    // Helper: resolve log directory considering extension GUC + PostgreSQL config
    fn resolve_log_directory() -> PathBuf {
        if let Some(dir) = LOG_DIRECTORY.get().as_ref().and_then(|c| c.to_str().ok()) {
            return PathBuf::from(dir);
        }

        // Fallback to PostgreSQL's own log_directory setting
        let fallback = Spi::get_one::<String>("SHOW log_directory")
            .ok()
            .flatten()
            .unwrap_or_else(|| "log".to_string());

        let mut path = PathBuf::from(fallback);

        // When relative, it's relative to data_directory
        if path.is_relative() {
            if let Ok(Some(data_dir)) = Spi::get_one::<String>("SHOW data_directory") {
                path = Path::new(&data_dir).join(path);
            }
        }

        path
    }

    let mut log_dir = resolve_log_directory();
    pgrx::log!(
        "password_profile: Using log directory: {}",
        log_dir.display()
    );

    let mut last_position: u64 = 0;
    let mut current_log_file: Option<String> = None;

    // Main monitoring loop
    loop {
        if BackgroundWorker::sighup_received() {
            pgrx::log!("password_profile: Log monitor received SIGHUP, reloading config");
            log_dir = resolve_log_directory();
            pgrx::log!(
                "password_profile: Using log directory: {}",
                log_dir.display()
            );
        }

        if BackgroundWorker::sigterm_received() {
            pgrx::log!("password_profile: Log monitor shutting down");
            break;
        }

        // Ensure log directory exists before scanning
        if !log_dir.exists() {
            pgrx::warning!(
                "password_profile: Log directory '{}' not found; sleeping",
                log_dir.display()
            );
            thread::sleep(Duration::from_secs(5));
            continue;
        }

        // Find the latest log file
        if let Ok(entries) = std::fs::read_dir(&log_dir) {
            let mut latest_file: Option<(String, std::time::SystemTime)> = None;

            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata() {
                    if let Some(path_str) = entry.path().to_str().map(String::from) {
                        if path_str.ends_with(".log") || path_str.contains("postgresql-") {
                            if let Ok(modified) = metadata.modified() {
                                if latest_file.is_none()
                                    || Some(modified) > latest_file.as_ref().map(|(_, t)| *t)
                                {
                                    latest_file = Some((path_str, modified));
                                }
                            }
                        }
                    }
                }
            }

            if let Some((log_file_path, _)) = latest_file {
                // Check if we switched to a new log file
                if current_log_file.as_ref() != Some(&log_file_path) {
                    pgrx::log!(
                        "password_profile: Monitoring new log file: {}",
                        log_file_path
                    );
                    current_log_file = Some(log_file_path.clone());
                    last_position = 0;
                }

                // Read new lines from the log file
                if let Ok(mut file) = File::open(&log_file_path) {
                    if file.seek(SeekFrom::Start(last_position)).is_ok() {
                        let reader = BufReader::new(file);

                        for line in reader.lines().flatten() {
                            last_position += line.len() as u64 + 1; // +1 for newline

                            // Parse authentication events:
                            // Priority 1: Hook-based logs (clean, reliable)
                            // Priority 2: Legacy FATAL logs (fallback for compatibility)
                            let hook_failed = line.contains("password_profile: auth_failure");
                            let hook_success = line.contains("password_profile: auth_success");

                            // Legacy FATAL patterns (English and Turkish)
                            let legacy_failed = !hook_failed
                                && ((line.contains("FATAL") || line.contains("ÖLÜMCÜL"))
                                    && (line.contains("password authentication failed")
                                        || line.contains("şifre doğrulaması başarısız")));
                            let legacy_success =
                                !hook_success && line.contains("connection authorized");

                            if hook_failed || legacy_failed {
                                if let Some(username) = extract_username_from_log(&line) {
                                    // Check for duplicate event
                                    if !should_process_auth_event(&username, AuthEventKind::Failed)
                                    {
                                        continue; // Skip duplicate
                                    }

                                    pgrx::log!("Failed login detected for user: {}", username);

                                    unsafe {
                                        bg_execute_sql(&format!(
                                            "SELECT password_profile.record_failed_login('{}')",
                                            username.replace("'", "''")
                                        ));
                                    }
                                    pgrx::log!("Recorded failed login for: {}", username);
                                }
                            } else if hook_success || legacy_success {
                                if let Some(username) = extract_username_from_log(&line) {
                                    if !should_process_auth_event(&username, AuthEventKind::Success)
                                    {
                                        continue;
                                    }

                                    pgrx::log!(
                                        "Successful login detected for user: {}",
                                        username
                                    );

                                    unsafe {
                                        bg_execute_sql(&format!(
                                            "SELECT password_profile.clear_login_attempts('{}')",
                                            username.replace("'", "''")
                                        ));
                                    }
                                    pgrx::log!("Cleared login attempts for: {}", username);
                                }
                            }
                        }
                    }
                } else {
                    // Log file disappeared (rotation/deletion)
                    pgrx::warning!(
                        "password_profile: Log file disappeared: {}, re-detecting...",
                        log_file_path
                    );
                    current_log_file = None; // Force re-detection
                    last_position = 0;
                }
            } else {
                // No log file found in directory
                pgrx::warning!(
                    "password_profile: No log files found in directory: {}",
                    log_dir.display()
                );
            }
        } else {
            // Cannot read log directory
            pgrx::warning!(
                "password_profile: Cannot read log directory: {}",
                log_dir.display()
            );
        }

        // Sleep for a short interval before checking again
        thread::sleep(Duration::from_secs(1));
    }

    pgrx::log!("password_profile: Log monitor background worker stopped");
}

/// Extract username from PostgreSQL log line
fn extract_username_from_log(line: &str) -> Option<String> {
    // Try to match patterns like:
    // English: "password authentication failed for user \"username\""
    // English: "connection authorized: user=username"
    // Turkish: "\"username\" kullanıcısı için şifre doğrulaması başarısız oldu"
    // Custom hook log: "password_profile: auth_failure user=username"

    if let Some(pos) = line.find("password_profile: auth_") {
        if let Some(user_pos) = line[pos..].find("user=") {
            let after_user = &line[pos + user_pos + 5..];
            let username: String = after_user
                .chars()
                .take_while(|c| !c.is_whitespace() && *c != ',' && *c != ';')
                .collect();
            if !username.is_empty() {
                return Some(username);
            }
        }
    }

    // Pattern 1: user="username" or user=\"username\"
    if let Some(pos) = line.find("user=\"") {
        let after_user = &line[pos + 6..];
        if let Some(end_pos) = after_user.find('"') {
            return Some(after_user[..end_pos].to_string());
        }
    }

    // Pattern 2: user=username (no quotes)
    if let Some(pos) = line.find("user=") {
        let after_user = &line[pos + 5..];
        let username: String = after_user
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
            .collect();
        if !username.is_empty() {
            return Some(username);
        }
    }

    // Pattern 3: for user "username" (English)
    if let Some(pos) = line.find("for user ") {
        let after_user = &line[pos + 9..];
        if after_user.starts_with('"') {
            let username: String = after_user[1..].chars().take_while(|c| *c != '"').collect();
            if !username.is_empty() {
                return Some(username);
            }
        } else {
            let username: String = after_user
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            if !username.is_empty() {
                return Some(username);
            }
        }
    }

    // Pattern 4: "username" kullanıcısı için (Turkish)
    // Example: "test_auto_login" kullanıcısı için şifre doğrulaması başarısız oldu
    if line.contains("kullanıcısı") {
        // Find all quoted strings in the line
        let mut in_quotes = false;
        let mut username = String::new();
        let mut chars = line.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '"' {
                if in_quotes {
                    // End of quoted string - check if followed by " kullanıcısı"
                    let remaining: String = chars.clone().collect();
                    if remaining.trim_start().starts_with("kullanıcısı") {
                        if !username.is_empty() {
                            return Some(username);
                        }
                    }
                    username.clear();
                    in_quotes = false;
                } else {
                    in_quotes = true;
                    username.clear();
                }
            } else if in_quotes {
                username.push(c);
            }
        }
    }

    None
}
