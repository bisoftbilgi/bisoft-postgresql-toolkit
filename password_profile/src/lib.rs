use bcrypt::{hash, verify};
use pgrx::bgworkers::BackgroundWorkerBuilder;
use pgrx::pg_sys;
use pgrx::pg_sys::errcodes::PgSqlErrorCode;
use pgrx::pg_sys::ffi::pg_guard_ffi_boundary;
use pgrx::prelude::*;
use rand::Rng;
use std::ffi::{CStr, CString};
use std::os::raw::c_int;
use std::sync::Once;
use std::time::Duration;

mod auth_event;
mod blacklist;
mod lock_cache;
mod sql;
mod structured_log;
mod worker;
use crate::sql::{int4_arg, spi_select_one, spi_update, text_arg};
pub use worker::auth_event_consumer_main;

::pgrx::pg_module_magic!();
pgrx::extension_sql_file!("../sql/password_profile_schema.sql");

const LOCK_CACHE_SIZE: usize = 2048;
const LOCK_USERNAME_BYTES: usize = 64;
const MICROS_PER_SEC: i64 = 1_000_000;
const AUTH_EVENT_RING_SIZE: usize = 1024;

/// Shared memory blacklist cache using sorted hash array for O(log n) lookup
/// Memory: ~80KB shared vs ~80MB (1000 processes × 80KB each) with Mutex<HashSet>
///
/// CRITICAL: Uses fixed SipHash keys (k0, k1) stored in shared memory to ensure
/// consistent hashing across all processes. Without fixed keys, each process
/// would hash passwords differently, breaking lookups entirely.
/// RAII guard for PostgreSQL SpinLock - automatically releases lock on drop (panic-safe)
struct SpinLockGuard {
    lock_ptr: *mut pg_sys::slock_t,
}

impl SpinLockGuard {
    /// Acquires SpinLock and returns RAII guard
    /// SAFETY: Caller must ensure lock_ptr is valid for entire lifetime
    unsafe fn new(lock_ptr: *mut pg_sys::slock_t) -> Self {
        pg_sys::SpinLockAcquire(lock_ptr);
        Self { lock_ptr }
    }
}

impl Drop for SpinLockGuard {
    fn drop(&mut self) {
        // CRITICAL: Always release lock even if panic occurs
        unsafe { pg_sys::SpinLockRelease(self.lock_ptr) }
    }
}

// Hook registration - ensures hooks are registered exactly once
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

// bcrypt hashing cost (4-31, default 10)
// Higher = more secure but slower. Adjust based on hardware and security requirements.
// Cost 10 = ~70ms, Cost 12 = ~300ms, Cost 8 = ~20ms
static BCRYPT_COST: pgrx::GucSetting<i32> = pgrx::GucSetting::<i32>::new(10);

// Bypass parameter for special users (superusers, service accounts)
static BYPASS_PASSWORD_PROFILE: pgrx::GucSetting<bool> = pgrx::GucSetting::<bool>::new(false);

// ====================================================================================
// PostgreSQL Hook Integration
// ====================================================================================

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

        // CRITICAL SECURITY: Check for hash-like input BEFORE password_type check
        // PostgreSQL auto-detects "md5..." as PASSWORD_TYPE_MD5, bypassing our PLAINTEXT check
        // We must reject hash-formatted strings even if PostgreSQL thinks they're already hashed
        if !password_str.is_empty() && is_hash_like(password_str) {
            pgrx::error!(
                "Security violation: Password looks like a precomputed hash. \
                 Direct hash input is not allowed. Use plain text passwords only."
            );
        }

        // Only validate plaintext passwords (PASSWORD_TYPE_PLAINTEXT)
        // Skip already hashed passwords (PASSWORD_TYPE_MD5, PASSWORD_TYPE_SCRAM_SHA_256)
        if password_type == pg_sys::PasswordType::PASSWORD_TYPE_PLAINTEXT
            && !password_str.is_empty()
        {
            // Call our validation function
            match check_password(username_str, password_str) {
                Ok(_) => {
                    structured_log::log_password_validated(username_str);
                }
                Err(e) => {
                    // Password validation failed - log and report error
                    structured_log::log_password_rejected(username_str, &e.to_string());
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

// ====================================================================================
// Client Authentication Hook Integration
// ====================================================================================

extern "C" {
    fn password_profile_port_username(port: *mut pg_sys::Port) -> *const std::os::raw::c_char;
    fn password_profile_register_client_auth_hook(
        hook: Option<ClientAuthHookRaw>,
    ) -> Option<ClientAuthHookRaw>;
    fn password_profile_raise_lockout_error(
        username: *const std::os::raw::c_char,
        remaining_seconds: c_int,
    );
    fn password_profile_user_exists(username: *const std::os::raw::c_char) -> c_int;
    fn password_profile_get_last_sqlstate(port: *mut pg_sys::Port, status: c_int) -> c_int;
}

#[inline]
fn encode_username(username: &str) -> [u8; LOCK_USERNAME_BYTES] {
    let mut buf = [0u8; LOCK_USERNAME_BYTES];
    let bytes = username.as_bytes();
    let len = bytes.len().min(LOCK_USERNAME_BYTES.saturating_sub(1));
    buf[..len].copy_from_slice(&bytes[..len]);
    buf
}

/// Check database for lockout status when cache miss occurs
fn check_lockout_from_db(username: &str) -> Option<i64> {
    use pgrx::spi::Spi;
    use crate::sql::text_arg;
    
    // Check if we can connect to database
    let my_db_id = unsafe { std::ptr::addr_of!(pg_sys::MyDatabaseId).read() };
    if my_db_id == pg_sys::InvalidOid {
        return None;
    }
    
    let result = Spi::connect(|client| -> pgrx::spi::Result<Option<i64>> {
        let args = [text_arg(username)];
        let table = client.select(
            "SELECT GREATEST(
                COALESCE(ROUND(EXTRACT(EPOCH FROM (lockout_until - now())))::bigint, 0),
                0
             ) as remaining_seconds
             FROM password_profile.login_attempts
             WHERE username = $1 AND fail_count >= 3",
            Some(1),
            &args,
        )?;
        
        Ok(table.first().get_one::<i64>()?)
    });
    
    match result {
        Ok(Some(secs)) if secs > 0 => Some(secs),
        _ => None,
    }
}

unsafe extern "C" fn client_auth_hook(port: *mut pg_sys::Port, status: c_int) {
    let username_ptr = password_profile_port_username(port);
    if !username_ptr.is_null() {
        if let Ok(username_str) = CStr::from_ptr(username_ptr).to_str() {
            // First check cache, if not found then check database
            let remaining_secs = unsafe { lock_cache::remaining_seconds(username_str) }
                .or_else(|| check_lockout_from_db(username_str));
            
            if let Some(seconds) = remaining_secs {
                if seconds > 0 {
                    // SECURITY: Do not log usernames
                    add_timing_jitter();

                    static FALLBACK_USERNAME: &[u8] = b"locked_user\0";
                    let c_username = CString::new(username_str).unwrap_or_else(|_| unsafe {
                        CStr::from_bytes_with_nul_unchecked(FALLBACK_USERNAME).to_owned()
                    });
                    unsafe {
                        password_profile_raise_lockout_error(c_username.as_ptr(), seconds as c_int);
                    }
                }
            }

            let is_failure = status != pg_sys::STATUS_OK as c_int;

            if is_failure {
                let sqlstate = password_profile_get_last_sqlstate(port, status) as u32;
                let is_invalid_password =
                    sqlstate == PgSqlErrorCode::ERRCODE_INVALID_PASSWORD as u32;

                if is_invalid_password {
                    // Check if user exists in pg_authid before tracking
                    let user_exists = password_profile_user_exists(username_ptr);

                    if user_exists == 1 {
                        auth_event::enqueue(username_str, true);
                        // SECURITY: Do not log usernames
                    } else if user_exists == 0 {
                        // Non-existent user - do not track fake usernames
                    } else {
                        pgrx::warning!(
                            "password_profile: failed to verify user existence during auth failure"
                        );
                    }
                } else {
                    // Non-password failures (pg_hba reject, SSL, etc.) shouldn't affect lockouts
                }
            } else {
                // Success - clear failure count
                auth_event::enqueue(username_str, false);
                // SECURITY: Do not log usernames
            }
        }
    }

    // Call previous hook
    if let Some(prev_hook) = PREV_CLIENT_AUTH_HOOK {
        pg_guard_ffi_boundary(|| prev_hook(port, status));
    }
}

fn register_client_auth_hook() {
    CLIENT_AUTH_HOOK_INIT.call_once(|| {
        unsafe {
            PREV_CLIENT_AUTH_HOOK =
                password_profile_register_client_auth_hook(Some(client_auth_hook));
            // Note: lock_cache::init() is called from shmem_startup_hook, not here
        }
        pgrx::log!("ClientAuthentication_hook registered");
    });
}

#[no_mangle]
pub unsafe extern "C" fn _PG_init() {
    // CRITICAL: Verify that _PG_init is being called during library load
    pgrx::warning!("password_profile_pure: _PG_init called - extension loading");

    // Register shmem_request_hook to request shared memory space
    static mut PREV_SHMEM_REQUEST_HOOK: Option<unsafe extern "C-unwind" fn()> = None;

    unsafe extern "C-unwind" fn shmem_request_hook_impl() {
        if let Some(prev) = PREV_SHMEM_REQUEST_HOOK {
            prev();
        }
        pg_sys::RequestAddinShmemSpace(lock_cache::shared_memory_bytes());
        pg_sys::RequestAddinShmemSpace(blacklist::shared_memory_bytes());
        pg_sys::RequestAddinShmemSpace(auth_event::shared_memory_bytes());
    }

    PREV_SHMEM_REQUEST_HOOK = pg_sys::shmem_request_hook;
    pg_sys::shmem_request_hook = Some(shmem_request_hook_impl);

    // Register shmem_startup_hook to initialize the cache
    static mut PREV_SHMEM_STARTUP_HOOK: Option<unsafe extern "C-unwind" fn()> = None;

    unsafe extern "C-unwind" fn shmem_startup_hook_impl() {
        if let Some(prev) = PREV_SHMEM_STARTUP_HOOK {
            prev();
        }
        lock_cache::init();
        blacklist::init(); // Initialize blacklist in shared memory
        auth_event::init(); // Initialize auth event queue
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
        c"Number of previous passwords to check (0=disabled)",
        c"Prevent reuse of last N passwords. Set to 0 to disable history checking.",
        &PASSWORD_HISTORY_COUNT,
        0,
        24,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_int_guc(
        c"password_profile.password_reuse_days",
        c"Days before password can be reused (0=disabled)",
        c"Prevent reuse within time window. Set to 0 to disable time-based checking.",
        &PASSWORD_REUSE_DAYS,
        0,
        3650,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    // Password expiration
    pgrx::GucRegistry::define_int_guc(
        c"password_profile.password_expiry_days",
        c"Days before password expires (0=disabled)",
        c"Force password change after N days. Set to 0 to disable expiration.",
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
        c"Account lockout duration (minutes)",
        c"Minutes to lock account after max failures. Must be at least 1 minute.",
        &LOCKOUT_MINUTES,
        1,
        1440,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_int_guc(
        c"password_profile.bcrypt_cost",
        c"bcrypt hashing cost factor (4-31, default 10)",
        c"Higher = more secure but slower. Cost 10 = ~70ms, Cost 12 = ~300ms, Cost 8 = ~20ms. Adjust based on hardware capabilities.",
        &BCRYPT_COST,
        4,
        31,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    // Bypass parameter for exempting users from password profile checks
    pgrx::GucRegistry::define_bool_guc(
        c"password_profile.bypass_password_profile",
        c"Bypass all password profile checks for this user",
        c"Set to true to exempt a user from password validation, history, expiry, and lockout checks. Use with ALTER USER username SET password_profile.bypass_password_profile = true;",
        &BYPASS_PASSWORD_PROFILE,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    // Background worker: consume auth events from shared memory
    BackgroundWorkerBuilder::new("password_profile_auth_event_consumer")
        .set_function("auth_event_consumer_main")
        .set_library("password_profile") // MUST match Cargo.toml [package] name AND .so filename
        .set_argument(None::<i32>.into_datum())
        .set_restart_time(Some(Duration::from_secs(1)))
        .enable_spi_access()
        .load();
    pgrx::info!("password_profile: auth event consumer background worker registered");

    // Register check_password_hook
    pgrx::log!("password_profile: Registering hooks...");
    unsafe {
        register_password_check_hook();
        pgrx::log!("password_profile: Password check hook registered");
    }
    register_client_auth_hook();
    // Note: log_hook removed - using SQLSTATE check in client_auth_hook instead

    // CRITICAL FIX: CANNOT call SPI functions (Spi::run) during _PG_init!
    // _PG_init runs in the postmaster process during shared library load,
    // and SPI is not available/initialized at this phase. Calling SPI here
    // causes FATAL errors: "SPI_connect() can only be called from a normal backend"
    // or crashes the entire PostgreSQL server.
    //
    // Table creation has been moved to sql/password_profile--0.0.0.sql
    // which is automatically executed during CREATE EXTENSION.
    // Removed init_login_attempts_table() call from here.

    pgrx::log!("password_profile initialized with all features");
}

// Timing attack prevention: Add small random delay on auth failures
// This prevents attackers from measuring timing differences to gain info
#[inline(never)] // Prevent optimization from removing this
fn add_timing_jitter() {
    let mut rng = rand::thread_rng();
    // Random delay between 10-50ms to mask timing variations
    let delay_ms = rng.gen_range(10..50);
    // SECURITY: Do NOT log timing delay - prevents information leakage
    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
}

/// SECURITY: Detect if a password string looks like a precomputed hash
/// This prevents attackers from bypassing validation by entering hash strings directly
///
/// Detects:
/// 1. PostgreSQL MD5: md5 + 32 hex chars (e.g., md5c4ca4238a0b923820dcc509a6f75849b)
/// 2. bcrypt: $2a$, $2b$, $2x$, $2y$ formats (typically 60 chars)
/// 3. argon2: $argon2i$, $argon2id$, $argon2d$ formats
/// 4. SCRAM-SHA-256: SCRAM-SHA-256$ prefix
/// 5. PBKDF2: $pbkdf2-sha256$ and similar
/// 6. Raw MD5: exactly 32 hex chars (OPTIONAL - may cause false positives)
/// 7. SHA-1: exactly 40 hex chars (OPTIONAL)
/// 8. SHA-256: exactly 64 hex chars (OPTIONAL)
/// 9. SHA-512: exactly 128 hex chars (OPTIONAL)
/// 10. Generic hash pattern: long strings with $ delimiters
fn is_hash_like(password: &str) -> bool {
    if password.is_empty() {
        return false;
    }

    let len = password.len();
    let lower = password.to_lowercase();

    // 1. PostgreSQL MD5 format: "md5" + 32 hex = 35 chars total
    // Example: md5c4ca4238a0b923820dcc509a6f75849b
    if len == 35 && lower.starts_with("md5") {
        let hex_part = &password[3..];
        if hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return true;
        }
    }

    // 2. bcrypt formats: $2a$, $2b$, $2x$, $2y$
    // Typical format: $2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW
    // Length usually ~60 chars, but can be shorter in some implementations
    // Format: $2[abxy]$<cost>$<salt+hash>
    if (lower.starts_with("$2a$")
        || lower.starts_with("$2b$")
        || lower.starts_with("$2x$")
        || lower.starts_with("$2y$"))
        && len >= 20
    // Minimum reasonable bcrypt length (relaxed from 59)
    {
        return true;
    }

    // 3. argon2 formats: $argon2i$, $argon2id$, $argon2d$
    // Example: $argon2id$v=19$m=65536,t=2,p=1$...
    if lower.starts_with("$argon2i$")
        || lower.starts_with("$argon2id$")
        || lower.starts_with("$argon2d$")
    {
        return true;
    }

    // 4. SCRAM-SHA-256 format
    // Example: SCRAM-SHA-256$4096:salt$hash:proof
    if lower.starts_with("scram-sha-256$") || lower.starts_with("scram-sha-1$") {
        return true;
    }

    // 5. PBKDF2 formats
    // Example: $pbkdf2-sha256$29000$...
    if lower.starts_with("$pbkdf2") {
        return true;
    }

    // 6. Django/Werkzeug formats
    // Example: pbkdf2:sha256:... or sha1$salt$hash
    if lower.starts_with("pbkdf2:") || lower.starts_with("sha1$") || lower.starts_with("sha256$") {
        return true;
    }

    // 7. Raw MD5: exactly 32 hex chars (OPTIONAL - may reject valid hex passwords)
    // Disabled by default to avoid false positives
    // Uncomment if you want to strictly reject all 32-char hex strings
    // if len == 32 && password.chars().all(|c| c.is_ascii_hexdigit()) {
    //     return true;
    // }

    // 8. Common hash lengths (OPTIONAL - commented out to avoid false positives)
    // SHA-1: 40 hex, SHA-256: 64 hex, SHA-512: 128 hex
    // These might be legitimate passwords, so we're conservative here
    if (len == 40 || len == 64 || len == 128) && password.chars().all(|c| c.is_ascii_hexdigit()) {
        // Only reject if it looks TOO much like a hash (all lowercase/uppercase hex)
        // Real passwords with these lengths are unlikely to be pure hex
        return true;
    }

    // 9. Generic hash pattern: starts with $, has multiple $ delimiters, and is long
    // This catches many other hash formats we might have missed
    if password.starts_with('$') && len > 50 && password.matches('$').count() >= 3 {
        return true;
    }

    // 10. crypt(3) formats: $1$ (MD5), $5$ (SHA-256), $6$ (SHA-512)
    if (lower.starts_with("$1$") || lower.starts_with("$5$") || lower.starts_with("$6$"))
        && len > 20
    {
        return true;
    }

    false
}

#[pg_extern]
fn check_password(username: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Check if user has bypass enabled (per-user setting)
    let bypass_args = [text_arg(username)];
    let bypass_enabled = Spi::get_one_with_args::<bool>(
        "SELECT COALESCE(
            (SELECT (unnest(useconfig) LIKE 'password_profile.bypass_password_profile=true')
             FROM pg_user WHERE usename = $1
             LIMIT 1),
            false
        )",
        &bypass_args,
    )?
    .unwrap_or(false);

    if bypass_enabled {
        // SECURITY: Do not log usernames
        return Ok("Password accepted (bypassed)".to_string());
    }

    // SECURITY LAYER 1: Defense-in-depth - reject hash-formatted input
    // This is a second layer of protection (first is in the hook)
    // Prevents attackers from bypassing validation by entering precomputed hashes
    if is_hash_like(password) {
        add_timing_jitter();
        // SECURITY: Do not log usernames or password details
        return Err(
            "Security violation: Password looks like a precomputed hash. \
             Plain text passwords cannot be in hash format (bcrypt, MD5, SCRAM, etc.)"
                .into(),
        );
    }

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
    if blacklist::contains(password) {
        add_timing_jitter();
        return Err("Password is in blacklist (too common)".into());
    }

    // 5. Password history check (if enabled)
    if PASSWORD_HISTORY_COUNT.get() > 0 {
        let history_count = PASSWORD_HISTORY_COUNT.get();

        let args = [text_arg(username), int4_arg(history_count)];
        const HISTORY_QUERY: &str = "
            SELECT COALESCE(array_agg(password_hash), ARRAY[]::text[])
            FROM (
                SELECT password_hash
                FROM password_profile.password_history
                WHERE username = $1
                ORDER BY changed_at DESC
                LIMIT $2
            ) t
        ";

        if let Some(hashes) = Spi::get_one_with_args::<Vec<String>>(HISTORY_QUERY, &args)? {
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
        let reuse_days = PASSWORD_REUSE_DAYS.get();

        let args = [text_arg(username), int4_arg(reuse_days)];
        const REUSE_QUERY: &str = "
            SELECT COALESCE(array_agg(password_hash), ARRAY[]::text[])
            FROM password_profile.password_history
            WHERE username = $1
              AND changed_at > now() - ($2 || ' days')::interval
        ";

        if let Some(hashes) = Spi::get_one_with_args::<Vec<String>>(REUSE_QUERY, &args)? {
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
    const HOOK_EXISTS_QUERY: &str = "
        SELECT EXISTS(
            SELECT 1 FROM pg_proc p
            JOIN pg_namespace n ON p.pronamespace = n.oid
            WHERE n.nspname = 'password_profile'
              AND p.proname = 'custom_password_check'
        )
    ";

    if Spi::get_one::<bool>(HOOK_EXISTS_QUERY)?.unwrap_or(false) {
        let hook_args = [text_arg(username), text_arg(password)];
        let hook_query = "SELECT password_profile.custom_password_check($1, $2)";

        if let Some(msg) = Spi::get_one_with_args::<String>(hook_query, &hook_args)? {
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
    let my_db_id = unsafe { std::ptr::addr_of!(pg_sys::MyDatabaseId).read() };
    if my_db_id == pg_sys::InvalidOid {
        return Ok("Skipped - no database context".to_string());
    }

    let (is_superuser, bypass_check, _lockout_min, max_fails) = Spi::connect_mut(
        |client| -> pgrx::spi::Result<(bool, bool, i32, i32)> {
            let username_arg = [text_arg(username)];

            let is_super = spi_select_one::<bool>(
                client,
                "SELECT COALESCE((SELECT usesuper FROM pg_user WHERE usename = $1), false)",
                &username_arg,
            )?
            .unwrap_or(false);
            if is_super {
                return Ok((true, false, 0, 0));
            }

            let bypass = spi_select_one::<bool>(
                client,
                "SELECT COALESCE(
                    (SELECT (unnest(useconfig) LIKE 'password_profile.bypass_password_profile=true')
                     FROM pg_user WHERE usename = $1
                     LIMIT 1),
                    false
                )",
                &username_arg,
            )?
            .unwrap_or(false);
            if bypass {
                return Ok((false, true, 0, 0));
            }

            let lockout = spi_select_one::<i32>(
                client,
                "SELECT COALESCE(
                    (
                        SELECT substring(cfg FROM 'password_profile\\.lockout_minutes=([0-9]+)')::int
                        FROM unnest((SELECT useconfig FROM pg_user WHERE usename = $1)) AS cfg
                        WHERE cfg LIKE 'password_profile.lockout_minutes=%'
                    ),
                    $2
                )",
                &[text_arg(username), int4_arg(LOCKOUT_MINUTES.get())],
            )?
            .unwrap_or(LOCKOUT_MINUTES.get());

            let max_fails_val = spi_select_one::<i32>(
                client,
                "SELECT COALESCE(
                    (
                        SELECT substring(cfg FROM 'password_profile\\.failed_login_max=([0-9]+)')::int
                        FROM unnest((SELECT useconfig FROM pg_user WHERE usename = $1)) AS cfg
                        WHERE cfg LIKE 'password_profile.failed_login_max=%'
                    ),
                    $2
                )",
                &[text_arg(username), int4_arg(FAILED_LOGIN_MAX.get())],
            )?
            .unwrap_or(FAILED_LOGIN_MAX.get());

            spi_update(
                client,
                "UPDATE password_profile.login_attempts 
                 SET fail_count = 0, lockout_until = NULL
                 WHERE username = $1 AND lockout_until IS NOT NULL AND lockout_until <= now()",
                &username_arg,
            )?;

            spi_update(
                client,
                "INSERT INTO password_profile.login_attempts (username, fail_count, last_fail, lockout_until)
                 VALUES ($1, 1, now(), NULL)
                 ON CONFLICT (username) DO UPDATE SET
                     fail_count = password_profile.login_attempts.fail_count + 1,
                     last_fail = now(),
                     lockout_until = CASE
                         WHEN password_profile.login_attempts.fail_count + 1 >= $2
                         THEN now() + ($3 || ' minutes')::interval
                         ELSE NULL
                     END",
                &[text_arg(username), int4_arg(max_fails_val), int4_arg(lockout)],
            )?;

            Ok((false, false, lockout, max_fails_val))
        },
    )?;

    if is_superuser {
        return Ok("Superuser bypassed".to_string());
    }

    if bypass_check {
        return Ok("Bypassed failed login tracking".to_string());
    }

    lock_cache::sync(username, max_fails)?;
    Ok("Failed login recorded".to_string())
}
#[pg_extern]
fn clear_login_attempts(username: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Security check: Only superuser or the same user can clear attempts
    // Use single Spi::connect() to avoid nested SPI
    let current_user =
        Spi::get_one::<String>("SELECT current_user::text")?.ok_or("Failed to get current user")?;
    let is_superuser = Spi::get_one_with_args::<bool>(
        "SELECT usesuper FROM pg_user WHERE usename = $1",
        &[text_arg(&current_user)],
    )?
    .unwrap_or(false);

    if !is_superuser && current_user != username {
        return Err(format!(
            "Permission denied: Only superuser or user '{}' can clear their login attempts",
            username
        )
        .into());
    }

    clear_login_attempts_internal(username)?;
    Ok("Login attempts cleared".to_string())
}

fn clear_login_attempts_internal(username: &str) -> Result<(), Box<dyn std::error::Error>> {
    Spi::run_with_args(
        "DELETE FROM password_profile.login_attempts WHERE username = $1",
        &[text_arg(username)],
    )?;

    unsafe {
        lock_cache::clear(username);
    }
    Ok(())
}

#[pg_extern]
fn is_user_locked(username: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let query = "
        SELECT 1 FROM password_profile.login_attempts 
        WHERE username = $1 AND lockout_until > now() LIMIT 1
    ";

    match Spi::get_one_with_args::<i32>(query, &[text_arg(username)]) {
        Ok(Some(_)) => Ok(true),
        Ok(None) => Ok(false),
        Err(_) => Ok(false), // Table doesn't exist or other error
    }
}

#[pg_extern]
fn check_user_access(username: &str) -> Result<String, Box<dyn std::error::Error>> {
    // CRITICAL: Check database context before SPI operations
    let my_db_id = unsafe { std::ptr::addr_of!(pg_sys::MyDatabaseId).read() };
    if my_db_id == pg_sys::InvalidOid {
        pgrx::log!("password_profile: check_user_access skipped - no database context");
        return Ok("Access check skipped - no database context".to_string());
    }

    // First check lock cache (fast, no DB access needed)
    if let Some(seconds) = unsafe { lock_cache::remaining_seconds(username) } {
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

    // Check if locked and get remaining time
    let query = "
        SELECT EXTRACT(EPOCH FROM (lockout_until - now()))::int AS seconds_left
        FROM password_profile.login_attempts 
        WHERE username = $1 AND lockout_until > now()
    ";

    match Spi::get_one_with_args::<i32>(query, &[text_arg(username)]) {
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
    // Hash password with bcrypt (cost from GUC parameter)
    let cost = BCRYPT_COST.get().clamp(4, 31) as u32; // Ensure valid range
    let pwd_hash =
        hash(new_password, cost).map_err(|e| format!("Failed to hash password: {}", e))?;
    Spi::run_with_args(
        "INSERT INTO password_profile.password_history (username, password_hash, changed_at) 
         VALUES ($1, $2, now())",
        &[text_arg(username), text_arg(&pwd_hash)],
    )?;

    // Update expiry
    let expiry_days = PASSWORD_EXPIRY_DAYS.get();
    if expiry_days > 0 {
        let grace_logins = PASSWORD_GRACE_LOGINS.get();
        Spi::run_with_args(
            "INSERT INTO password_profile.password_expiry (username, last_changed, must_change_by, grace_logins_remaining)
             VALUES ($1, now(), now() + ($2 || ' days')::interval, $3)
             ON CONFLICT (username) DO UPDATE SET
                 last_changed = now(),
                 must_change_by = now() + ($2 || ' days')::interval,
                 grace_logins_remaining = $3",
            &[text_arg(username), int4_arg(expiry_days), int4_arg(grace_logins)],
        )?;
    }

    Ok("Password change recorded".to_string())
}

#[pg_extern]
fn check_password_expiry(username: &str) -> Result<String, Box<dyn std::error::Error>> {
    if PASSWORD_EXPIRY_DAYS.get() == 0 {
        return Ok("Password expiry disabled".to_string());
    }

    // Check if expired
    let query = "
        SELECT grace_logins_remaining
        FROM password_profile.password_expiry 
        WHERE username = $1 AND must_change_by < now()
    ";

    match Spi::get_one_with_args::<i32>(query, &[text_arg(username)]) {
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
    Spi::run_with_args(
        "INSERT INTO password_profile.blacklist (password, added_at, reason)
         VALUES ($1, now(), $2)
         ON CONFLICT (password) DO NOTHING",
        &[
            text_arg(password),
            text_arg(reason.unwrap_or("Admin added")),
        ],
    )?;
    Ok("Added to blacklist".to_string())
}

#[pg_extern]
fn remove_from_blacklist(password: &str) -> Result<String, Box<dyn std::error::Error>> {
    Spi::run_with_args(
        "DELETE FROM password_profile.blacklist WHERE password = $1",
        &[text_arg(password)],
    )?;
    Ok("Removed from blacklist".to_string())
}

#[pg_extern]
fn load_blacklist_from_file(
    file_path: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    // Default path: $PGDATA/../share/extension/password_profile_blacklist.txt
    let path = if let Some(p) = file_path {
        p.to_string()
    } else {
        // Try to get PGDATA
        let pgdata = std::env::var("PGDATA").unwrap_or_else(|_| "/var/lib/pgsql/16/data".to_string());
        format!("{}/password_profile_blacklist.txt", pgdata)
    };

    let file = File::open(&path).map_err(|e| {
        format!("Failed to open blacklist file '{}': {}", path, e)
    })?;

    let reader = BufReader::new(file);
    let mut count = 0;
    let mut errors = 0;

    for line in reader.lines() {
        if let Ok(password) = line {
            let password = password.trim();
            if password.is_empty() || password.starts_with('#') {
                continue;
            }

            match Spi::run_with_args(
                "INSERT INTO password_profile.blacklist (password, reason)
                 VALUES ($1, 'Loaded from file')
                 ON CONFLICT (password) DO NOTHING",
                &[text_arg(password)],
            ) {
                Ok(_) => count += 1,
                Err(_) => errors += 1,
            }
        }
    }

    Ok(format!(
        "Loaded {} passwords from '{}' ({} errors)",
        count, path, errors
    ))
}

#[pg_extern]
fn get_password_stats(username: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Get various stats
    let history_query = "
        SELECT COUNT(*) FROM password_profile.password_history WHERE username = $1
    ";
    let history_count =
        Spi::get_one_with_args::<i64>(history_query, &[text_arg(username)])?.unwrap_or(0);

    let expiry_query = "
        SELECT EXTRACT(EPOCH FROM (must_change_by - now()))::int / 86400
        FROM password_profile.password_expiry WHERE username = $1
    ";
    let days_until_expiry = Spi::get_one_with_args::<i32>(expiry_query, &[text_arg(username)])?;

    let failed_query = "
        SELECT fail_count FROM password_profile.login_attempts WHERE username = $1
    ";
    let failed_attempts =
        Spi::get_one_with_args::<i32>(failed_query, &[text_arg(username)])?.unwrap_or(0);

    let stats = format!(
        "Password History: {} changes | Days until expiry: {} | Failed attempts: {}",
        history_count,
        days_until_expiry.map_or("N/A".to_string(), |d| d.to_string()),
        failed_attempts
    );

    Ok(stats)
}

// ====================================================================================
// Instrumentation & Monitoring Functions
// ====================================================================================

/// Returns runtime statistics about lock cache and authentication failures
/// Useful for ops monitoring and capacity planning
#[pg_extern]
fn get_lock_cache_stats() -> Result<
    TableIterator<
        'static,
        (
            name!(metric, String),
            name!(value, i64),
            name!(description, String),
        ),
    >,
    Box<dyn std::error::Error>,
> {
    let stats = lock_cache::collect_stats()?;
    Ok(TableIterator::new(stats.into_iter()))
}

#[cfg(test)]
mod tests {
    use pgrx::prelude::*;

    #[test]
    fn test_user_exists_real_user() {
        Spi::run("CREATE USER test_exists_user WITH PASSWORD 'test123'").ok();
        let username = std::ffi::CString::new("test_exists_user").unwrap();
        let result = unsafe { crate::password_profile_user_exists(username.as_ptr()) };
        assert_eq!(result, 1);
        Spi::run("DROP USER test_exists_user").ok();
    }

    #[test]
    fn test_user_exists_fake_user() {
        let username = std::ffi::CString::new("definitely_not_exists_99999").unwrap();
        let result = unsafe { crate::password_profile_user_exists(username.as_ptr()) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_user_exists_null() {
        let result = unsafe { crate::password_profile_user_exists(std::ptr::null()) };
        assert_eq!(result, -1);
    }

    #[test]
    fn test_record_failed_login_basic() {
        Spi::run("CREATE SCHEMA IF NOT EXISTS password_profile").ok();
        Spi::run(
            "CREATE TABLE IF NOT EXISTS password_profile.login_attempts (
                username TEXT PRIMARY KEY,
                fail_count INT DEFAULT 0,
                last_fail TIMESTAMPTZ,
                lockout_until TIMESTAMPTZ
            )",
        )
        .ok();

        Spi::run("CREATE USER test_fail_user WITH PASSWORD 'test123'").ok();
        crate::record_failed_login("test_fail_user").unwrap();
        let count: Option<i32> = Spi::get_one(
            "SELECT fail_count FROM password_profile.login_attempts WHERE username = 'test_fail_user'",
        )
        .unwrap();
        assert!(count.unwrap_or(0) > 0);
        Spi::run("DELETE FROM password_profile.login_attempts WHERE username = 'test_fail_user'")
            .ok();
        Spi::run("DROP USER test_fail_user").ok();
    }

    #[test]
    fn test_clear_login_attempts() {
        Spi::run("CREATE SCHEMA IF NOT EXISTS password_profile").ok();
        Spi::run(
            "CREATE TABLE IF NOT EXISTS password_profile.login_attempts (
                username TEXT PRIMARY KEY,
                fail_count INT DEFAULT 0,
                last_fail TIMESTAMPTZ,
                lockout_until TIMESTAMPTZ
            )",
        )
        .ok();

        Spi::run("CREATE USER test_clear_user WITH PASSWORD 'test123'").ok();
        Spi::run(
            "INSERT INTO password_profile.login_attempts (username, fail_count, last_fail) 
                    VALUES ('test_clear_user', 5, NOW())",
        )
        .ok();

        crate::clear_login_attempts("test_clear_user").unwrap();
        let count: Option<i32> = Spi::get_one(
            "SELECT COUNT(*) FROM password_profile.login_attempts WHERE username = 'test_clear_user'",
        )
        .unwrap();
        assert_eq!(count.unwrap(), 0);
        Spi::run("DROP USER test_clear_user").ok();
    }

    #[test]
    fn test_password_validation_weak() {
        Spi::run("SET password_profile.password_min_length = 8").ok();
        let result = Spi::run("CREATE USER test_weak WITH PASSWORD 'weak'");
        assert!(result.is_err());
    }

    #[test]
    fn test_detect_hash_password() {
        let hash_attempts = vec![
            "md5c4ca4238a0b923820dcc509a6f75849b",
            "SCRAM-SHA-256$",
            "$2a$10$abcdefghijklmnopqrstuv",
        ];

        for attempt in hash_attempts {
            assert!(crate::is_hash_like(attempt));
        }
        assert!(!crate::is_hash_like("MyPassword123!"));
    }

    #[test]
    fn test_blacklist_contains_common_password() {
        unsafe { crate::blacklist::init() };
        assert!(crate::blacklist::contains("123456"));
        assert!(!crate::blacklist::contains("TrulyUniquePass!2024"));
    }

    #[test]
    fn test_lock_cache_sync_populates_cache() {
        unsafe { crate::lock_cache::init() };
        Spi::run("CREATE SCHEMA IF NOT EXISTS password_profile").ok();
        Spi::run(
            "CREATE TABLE IF NOT EXISTS password_profile.login_attempts (
                username TEXT PRIMARY KEY,
                fail_count INT DEFAULT 0,
                last_fail TIMESTAMPTZ,
                lockout_until TIMESTAMPTZ
            )",
        )
        .ok();

        Spi::run("DELETE FROM password_profile.login_attempts WHERE username = 'lock_user_stats'")
            .ok();
        Spi::run(
            "INSERT INTO password_profile.login_attempts (username, fail_count, lockout_until)
                 VALUES ('lock_user_stats', 5, now() + interval '2 minutes')",
        )
        .ok();

        crate::lock_cache::sync("lock_user_stats", 3).unwrap();
        let remaining = unsafe { crate::lock_cache::remaining_seconds("lock_user_stats") };
        assert!(remaining.unwrap_or(0) > 0);

        Spi::run("DELETE FROM password_profile.login_attempts WHERE username = 'lock_user_stats'")
            .ok();
        unsafe { crate::lock_cache::clear("lock_user_stats") };
    }

    #[test]
    fn test_record_failed_login_triggers_lockout() {
        Spi::run("SET password_profile.failed_login_max = 2").ok();
        Spi::run("SET password_profile.lockout_minutes = 1").ok();

        Spi::run("CREATE SCHEMA IF NOT EXISTS password_profile").ok();
        Spi::run(
            "CREATE TABLE IF NOT EXISTS password_profile.login_attempts (
                username TEXT PRIMARY KEY,
                fail_count INT DEFAULT 0,
                last_fail TIMESTAMPTZ,
                lockout_until TIMESTAMPTZ
            )",
        )
        .ok();

        Spi::run("CREATE USER test_lockout_user WITH PASSWORD 'test123'").ok();
        crate::record_failed_login("test_lockout_user").unwrap();
        crate::record_failed_login("test_lockout_user").unwrap();

        let locked: Option<bool> = Spi::get_one(
            "SELECT lockout_until > now() FROM password_profile.login_attempts
                 WHERE username = 'test_lockout_user'",
        )
        .unwrap();
        assert!(locked.unwrap_or(false));

        Spi::run(
            "DELETE FROM password_profile.login_attempts WHERE username = 'test_lockout_user'",
        )
        .ok();
        Spi::run("DROP USER test_lockout_user").ok();
        Spi::run("RESET password_profile.failed_login_max").ok();
        Spi::run("RESET password_profile.lockout_minutes").ok();
    }
}
