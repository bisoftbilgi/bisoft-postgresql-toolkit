use bcrypt::{hash, verify};
use pgrx::bgworkers::{BackgroundWorker, BackgroundWorkerBuilder, SignalWakeFlags};
use pgrx::pg_sys;
use pgrx::pg_sys::ffi::pg_guard_ffi_boundary;
use pgrx::prelude::*;
// SpiClient removed - using direct Spi calls instead of parameterized queries
use rand::Rng;
use siphasher::sip::SipHasher13;
use std::ffi::{CStr, CString};
use std::hash::{Hash, Hasher};
use std::os::raw::c_int;
use std::ptr;
use std::sync::Once;
use std::time::Duration;

::pgrx::pg_module_magic!();

const LOCK_CACHE_SIZE: usize = 2048;
const LOCK_USERNAME_BYTES: usize = 64;
const MICROS_PER_SEC: i64 = 1_000_000;
const BLACKLIST_HASH_SIZE: usize = 10000; // Match blacklist.txt size
const AUTH_EVENT_RING_SIZE: usize = 1024;

#[repr(C)]
struct LockEntry {
    username: [u8; LOCK_USERNAME_BYTES],
    expires_at: pg_sys::TimestampTz,
}

impl LockEntry {
    #[allow(dead_code)]
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

/// Shared memory blacklist cache using sorted hash array for O(log n) lookup
/// Memory: ~80KB shared vs ~80MB (1000 processes × 80KB each) with Mutex<HashSet>
/// 
/// CRITICAL: Uses fixed SipHash keys (k0, k1) stored in shared memory to ensure
/// consistent hashing across all processes. Without fixed keys, each process
/// would hash passwords differently, breaking lookups entirely.
#[repr(C)]
struct BlacklistCache {
    lock: pg_sys::slock_t,
    count: u32,                              // Number of hashes in array
    sip_k0: u64,                             // SipHash key 0 (fixed per cluster)
    sip_k1: u64,                             // SipHash key 1 (fixed per cluster)
    hashes: [u64; BLACKLIST_HASH_SIZE],      // Sorted SipHash-13 values
}

#[repr(C)]
#[derive(Copy, Clone)]
struct SharedAuthEvent {
    username: [u8; LOCK_USERNAME_BYTES],
    timestamp: pg_sys::TimestampTz,
    is_failure: bool,
}

#[repr(C)]
struct AuthEventRing {
    lock: pg_sys::slock_t,
    head: u32,
    tail: u32,
    dropped: u64,
    events: [SharedAuthEvent; AUTH_EVENT_RING_SIZE],
}

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

static mut LOCK_CACHE: *mut LockCache = ptr::null_mut();
static mut BLACKLIST_CACHE_SHM: *mut BlacklistCache = ptr::null_mut();
static mut AUTH_EVENT_RING: *mut AuthEventRing = ptr::null_mut();

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
                    // SECURITY: Do not log usernames
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

// ====================================================================================
// Client Authentication Hook Integration
// ====================================================================================

extern "C" {
    fn password_profile_port_username(port: *mut pg_sys::Port) -> *const std::os::raw::c_char;
    fn password_profile_register_client_auth_hook(
        hook: Option<ClientAuthHookRaw>,
    ) -> Option<ClientAuthHookRaw>;
    fn password_profile_raise_lockout_error(username: *const std::os::raw::c_char, remaining_seconds: c_int);
    fn password_profile_user_exists(username: *const std::os::raw::c_char) -> c_int;
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

    // Track operation result for logging AFTER lock release
    enum CacheOp {
        Updated,
        Inserted,
        Evicted(String),
        OverwriteSlot0,
    }
    let operation: CacheOp;

    // SAFETY: SpinLockGuard ensures lock release even if panic occurs
    // CRITICAL: NO LOGGING INSIDE SPINLOCK! Log after guard drops.
    {
        let _guard = SpinLockGuard::new(&mut cache.lock);

        if let Some(entry) = cache
            .entries
            .iter_mut()
            .find(|e| e.username[0] != 0 && e.username == encoded)
        {
            entry.expires_at = expires_at;
            operation = CacheOp::Updated;
        } else if let Some(entry) = cache
            .entries
            .iter_mut()
            .find(|e| e.username[0] == 0 || e.expires_at <= now)
        {
            entry.username = encoded;
            entry.expires_at = expires_at;
            operation = CacheOp::Inserted;
        } else if let Some(oldest_entry) = cache.entries.iter_mut().min_by_key(|e| e.expires_at) {
            // No free slots - evict oldest entry (LRU)
            let old_username = std::str::from_utf8(&oldest_entry.username)
                .unwrap_or("(invalid)")
                .trim_end_matches('\0')
                .to_string();
            oldest_entry.username = encoded;
            oldest_entry.expires_at = expires_at;
            operation = CacheOp::Evicted(old_username);
        } else {
            // Fallback: overwrite slot 0 (should never happen)
            cache.entries[0].username = encoded;
            cache.entries[0].expires_at = expires_at;
            operation = CacheOp::OverwriteSlot0;
        }
    } // Guard drops here, lock released

    // Log AFTER releasing spinlock to avoid deadlock
    match operation {
        CacheOp::Updated => pgrx::log!(
            "password_profile: lock cache update existing user={} expires_at={}",
            username, expires_at
        ),
        CacheOp::Inserted => pgrx::log!(
            "password_profile: lock cache set user={} expires_at={}",
            username, expires_at
        ),
        CacheOp::Evicted(old_user) => {
            pgrx::warning!(
                "password_profile: LockCache full (2048 entries), evicting oldest entry: {}",
                old_user
            );
            pgrx::log!(
                "password_profile: lock cache evicted and set user={} expires_at={}",
                username, expires_at
            );
        }
        CacheOp::OverwriteSlot0 => pgrx::log!(
            "password_profile: lock cache overwrite slot0 user={} expires_at={}",
            username, expires_at
        ),
    }
}

unsafe fn lock_cache_clear(username: &str) {
    if LOCK_CACHE.is_null() {
        return;
    }
    let encoded = encode_username(username);
    let cache = &mut *LOCK_CACHE;

    // SAFETY: SpinLockGuard ensures lock release even if panic occurs
    // CRITICAL: NO LOGGING INSIDE SPINLOCK!
    {
        let _guard = SpinLockGuard::new(&mut cache.lock);
        
        for entry in cache.entries.iter_mut() {
            if entry.username[0] != 0 && entry.username == encoded {
                entry.username = [0; LOCK_USERNAME_BYTES];
                entry.expires_at = 0;
                break;
            }
        }
    } // Guard drops here, lock released

    // SECURITY: Do not log usernames
}

unsafe fn lock_cache_remaining_seconds(username: &str) -> Option<i64> {
    if LOCK_CACHE.is_null() {
        return None;
    }

    let encoded = encode_username(username);
    let cache = &mut *LOCK_CACHE;
    let now = pg_sys::GetCurrentTimestamp();
    let mut remaining = None;

    // SAFETY: SpinLockGuard ensures lock release even if panic occurs
    {
        let _guard = SpinLockGuard::new(&mut cache.lock);
        
        for entry in cache.entries.iter() {
            if entry.username[0] == 0 {
                continue;
            }
            if entry.username == encoded && entry.expires_at > now {
                remaining = Some(((entry.expires_at - now) / MICROS_PER_SEC) as i64);
                break;
            }
        }
        // Guard drops here, releases lock
    }

    let filtered = remaining.filter(|secs| *secs > 0);
    if filtered.is_none() {
        pgrx::log!(
            "password_profile: lock cache miss for {} (entry expired or not present)",
            username
        );
    }
    filtered
}

unsafe fn auth_event_ring_init() {
    if !AUTH_EVENT_RING.is_null() {
        return;
    }

    let size = std::mem::size_of::<AuthEventRing>();
    let mut found = false;
    let ring_ptr = pg_sys::ShmemInitStruct(
        c"password_profile_auth_event_ring".as_ptr(),
        size,
        &mut found as *mut bool,
    ) as *mut AuthEventRing;

    if ring_ptr.is_null() {
        pgrx::error!("password_profile: failed to initialize auth event ring");
    }

    if !found {
        (*ring_ptr).lock = 0;
        pg_sys::SpinLockInit(&mut (*ring_ptr).lock);
        (*ring_ptr).head = 0;
        (*ring_ptr).tail = 0;
        (*ring_ptr).dropped = 0;
        (*ring_ptr).events.iter_mut().for_each(|event| {
            event.username = [0; LOCK_USERNAME_BYTES];
            event.timestamp = 0;
            event.is_failure = false;
        });
        pgrx::log!(
            "password_profile: auth event ring allocated ({} bytes)",
            size
        );
    } else {
        pgrx::log!("password_profile: auth event ring attached to existing segment");
    }

    AUTH_EVENT_RING = ring_ptr;
}

fn enqueue_auth_event(username: &str, is_failure: bool) {
    unsafe {
        if AUTH_EVENT_RING.is_null() {
            pgrx::warning!("password_profile: auth event ring not initialized");
            return;
        }

        let encoded = encode_username(username);
        let ring = &mut *AUTH_EVENT_RING;

        let mut dropped_event = false;

        {
            let _guard = SpinLockGuard::new(&mut ring.lock);
            let next_head = (ring.head + 1) % AUTH_EVENT_RING_SIZE as u32;
            if next_head == ring.tail {
                // Ring full - drop oldest
                ring.tail = (ring.tail + 1) % AUTH_EVENT_RING_SIZE as u32;
                ring.dropped = ring.dropped.saturating_add(1);
                dropped_event = true;
            }

            ring.events[ring.head as usize] = SharedAuthEvent {
                username: encoded,
                timestamp: pg_sys::GetCurrentTimestamp(),
                is_failure,
            };
            ring.head = next_head;
        }

        if dropped_event {
            pgrx::warning!("password_profile: auth event ring full, dropping oldest event");
        }
    }
}

fn dequeue_auth_event() -> Option<SharedAuthEvent> {
    unsafe {
        if AUTH_EVENT_RING.is_null() {
            return None;
        }
        let ring = &mut *AUTH_EVENT_RING;
        let mut event = None;
        {
            let _guard = SpinLockGuard::new(&mut ring.lock);
            if ring.tail != ring.head {
                event = Some(ring.events[ring.tail as usize]);
                ring.tail = (ring.tail + 1) % AUTH_EVENT_RING_SIZE as u32;
            }
        }
        event
    }
}

fn username_from_bytes(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if end == 0 {
        return None;
    }
    std::str::from_utf8(&bytes[..end]).ok().map(|s| s.to_string())
}

unsafe extern "C" fn client_auth_hook(port: *mut pg_sys::Port, status: c_int) {
    let username_ptr = password_profile_port_username(port);
    if !username_ptr.is_null() {
        if let Ok(username_str) = CStr::from_ptr(username_ptr).to_str() {
            if let Some(seconds) = lock_cache_remaining_seconds(username_str) {
                if seconds > 0 {
                    // SECURITY: Do not log usernames
                    add_timing_jitter();

                    static FALLBACK_USERNAME: &[u8] = b"locked_user\0";
                    let c_username = CString::new(username_str)
                        .unwrap_or_else(|_| unsafe {
                            CStr::from_bytes_with_nul_unchecked(FALLBACK_USERNAME).to_owned()
                        });
                    unsafe {
                        password_profile_raise_lockout_error(c_username.as_ptr(), seconds as c_int);
                    }
                }
            }

            let is_failure = status != pg_sys::STATUS_OK as c_int;
            
            if is_failure {
                // Check if user exists in pg_authid before tracking
                let user_exists = password_profile_user_exists(username_ptr);
                
                if user_exists == 1 {
                    // User exists but password wrong - track it
                    enqueue_auth_event(username_str, true);
                    // SECURITY: Do not log usernames
                } else if user_exists == 0 {
                    // User does not exist - don't track
                    // SECURITY: Do not log usernames
                } else {
                    // Error checking user existence - track to be safe
                    enqueue_auth_event(username_str, true);
                    // SECURITY: Do not log usernames
                }
            } else {
                // Success - clear failure count
                enqueue_auth_event(username_str, false);
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
            // Note: lock_cache_init() is called from shmem_startup_hook, not here
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
        pg_sys::RequestAddinShmemSpace(std::mem::size_of::<LockCache>());
        pg_sys::RequestAddinShmemSpace(std::mem::size_of::<BlacklistCache>());
        pg_sys::RequestAddinShmemSpace(std::mem::size_of::<AuthEventRing>());
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
        blacklist_cache_init(); // Initialize blacklist in shared memory
        auth_event_ring_init(); // Initialize auth event queue
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

// Safe SQL escaping helper - uses PostgreSQL's quote_literal for proper escaping
fn quote_literal(s: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Use PostgreSQL's native quote_literal_cstr for proper SQL escaping
    // This is faster and more reliable than manual string replacement
    use std::ffi::CString;
    
    let c_str = CString::new(s)?;
    unsafe {
        let quoted = pg_sys::quote_literal_cstr(c_str.as_ptr());
        if quoted.is_null() {
            return Err("quote_literal_cstr returned NULL".into());
        }
        let result = std::ffi::CStr::from_ptr(quoted)
            .to_str()?
            .to_string();
        pg_sys::pfree(quoted as *mut std::ffi::c_void);
        Ok(result)
    }
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
        && len >= 20  // Minimum reasonable bcrypt length (relaxed from 59)
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
    if lower.starts_with("scram-sha-256$") 
        || lower.starts_with("scram-sha-1$") 
    {
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
    if (len == 40 || len == 64 || len == 128) 
        && password.chars().all(|c| c.is_ascii_hexdigit()) 
    {
        // Only reject if it looks TOO much like a hash (all lowercase/uppercase hex)
        // Real passwords with these lengths are unlikely to be pure hex
        return true;
    }

    // 9. Generic hash pattern: starts with $, has multiple $ delimiters, and is long
    // This catches many other hash formats we might have missed
    if password.starts_with('$') 
        && len > 50 
        && password.matches('$').count() >= 3 
    {
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

/// Initialize blacklist cache in shared memory (called once at extension load)
unsafe fn blacklist_cache_init() {
    if !BLACKLIST_CACHE_SHM.is_null() {
        return; // Already initialized
    }

    let size = std::mem::size_of::<BlacklistCache>();
    let mut found = false;
    let cache_ptr = pg_sys::ShmemInitStruct(
        c"password_profile_blacklist_cache".as_ptr(),
        size,
        &mut found as *mut bool,
    ) as *mut BlacklistCache;

    if cache_ptr.is_null() {
        pgrx::error!("password_profile: failed to initialize blacklist cache");
    }

    if !found {
        // First process to attach - initialize cache
        (*cache_ptr).lock = 0;
        pg_sys::SpinLockInit(&mut (*cache_ptr).lock);
        (*cache_ptr).count = 0;
        
        // CRITICAL FIX: Use fixed SipHash keys so all processes hash consistently
        // Without fixed keys, each process would use RandomState::new() which generates
        // different keys per process, making lookups fail 100% of the time.
        // These keys are arbitrary but must be consistent across the cluster.
        (*cache_ptr).sip_k0 = 0x0706050403020100u64; // Fixed key 0
        (*cache_ptr).sip_k1 = 0x0f0e0d0c0b0a0908u64; // Fixed key 1
        
        // Load blacklist.txt and hash all entries with FIXED keys
        let content = include_str!("../blacklist.txt");
        let mut hashes: Vec<u64> = content
            .lines()
            .map(|l| l.trim().to_lowercase())
            .filter(|l| !l.is_empty())
            .map(|password| {
                // Use SipHasher13 with FIXED keys from shared memory
                let mut hasher = SipHasher13::new_with_keys(
                    (*cache_ptr).sip_k0,
                    (*cache_ptr).sip_k1
                );
                password.hash(&mut hasher);
                hasher.finish()
            })
            .collect();

        // Sort for binary search
        hashes.sort_unstable();
        
        let count = hashes.len().min(BLACKLIST_HASH_SIZE);
        (*cache_ptr).count = count as u32;
        
        // Copy to shared memory
        for (i, hash) in hashes.iter().take(count).enumerate() {
            (*cache_ptr).hashes[i] = *hash;
        }
        
        pgrx::log!(
            "password_profile: blacklist cache initialized with {} passwords ({} bytes, keys: 0x{:x}, 0x{:x})",
            count,
            size,
            (*cache_ptr).sip_k0,
            (*cache_ptr).sip_k1
        );
    } else {
        pgrx::log!("password_profile: blacklist cache attached to existing segment");
    }

    BLACKLIST_CACHE_SHM = cache_ptr;
}

/// Check if password is blacklisted using binary search on sorted hash array
/// Time: O(log n) = O(log 10000) = ~13 comparisons max
/// 
/// CRITICAL: Must use the SAME fixed SipHash keys as blacklist_cache_init()
fn is_blacklisted(password: &str) -> bool {
    // Check database blacklist table first (dynamic entries)
    // Only if we're in a proper backend context (not during _PG_init or early auth)
    if unsafe { pg_sys::IsUnderPostmaster } {
        // Try database check, but silently fail if database context not ready
        let pwd_escaped = password.replace("'", "''");
        let db_check = Spi::get_one::<bool>(&format!(
            "SELECT EXISTS(SELECT 1 FROM password_profile.blacklist WHERE password = '{}')",
            pwd_escaped
        ));
        
        // If query succeeds and found in DB, reject immediately
        if let Ok(Some(true)) = db_check {
            return true;
        }
        // If query fails (table doesn't exist, no DB selected, etc.), fall through to static cache
    }
    
    // Check compile-time blacklist cache (static entries)
    unsafe {
        if BLACKLIST_CACHE_SHM.is_null() {
            pgrx::warning!("Blacklist cache not initialized");
            return false;
        }

        let cache = &*BLACKLIST_CACHE_SHM;
        
        // Hash the input password using THE SAME fixed keys from shared memory
        // CRITICAL: Must use the exact same SipHasher13 keys as init, otherwise
        // hashes won't match and blacklist lookups will always fail.
        let mut hasher = SipHasher13::new_with_keys(cache.sip_k0, cache.sip_k1);
        password.to_lowercase().hash(&mut hasher);
        let password_hash = hasher.finish();

        let found: bool;
        let count: usize;

        // Binary search in sorted hash array (SpinLock for read)
        // CRITICAL: NO LOGGING INSIDE SPINLOCK!
        {
            let _guard = SpinLockGuard::new(&mut (*BLACKLIST_CACHE_SHM).lock);
            
            count = cache.count as usize;
            let hashes = &cache.hashes[0..count];
            
            // Binary search
            found = hashes.binary_search(&password_hash).is_ok();
        } // Guard drops, lock released

        // SECURITY: Do NOT log passwords or hashes in production
        // Removed debug logging to prevent information leakage
        found
    }
}

#[pg_extern]
fn check_password(username: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Check if user has bypass enabled (per-user setting)
    let username_quoted = quote_literal(username)?;
    let bypass_check = Spi::get_one::<bool>(&format!(
        "SELECT COALESCE(
            (SELECT (unnest(useconfig) LIKE 'password_profile.bypass_password_profile=true')
             FROM pg_user WHERE usename = {}
             LIMIT 1),
            false
        )",
        username_quoted
    ));
    
    if let Ok(Some(true)) = bypass_check {
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
    let my_db_id = unsafe { std::ptr::addr_of!(pg_sys::MyDatabaseId).read() };
    if my_db_id == pg_sys::InvalidOid {
        return Ok("Skipped - no database context".to_string());
    }

    // CRITICAL: Use single Spi::connect() to avoid nested SPI calls
    // This prevents SIGSEGV when called from background worker transaction
    let username_quoted = quote_literal(username)?;
    let (is_superuser, bypass_check, _lockout_min, max_fails) = Spi::connect(|_client| -> Result<(bool, bool, i32, i32), Box<dyn std::error::Error>> {
        // Check if user is superuser (never lock superusers)
        let is_super = Spi::get_one::<bool>(&format!(
            "SELECT COALESCE((SELECT usesuper FROM pg_user WHERE usename = {}), false)",
            username_quoted
        ))?.unwrap_or(false);
        
        if is_super {
            return Ok((true, false, 0, 0));
        }

        // Check bypass setting
        let bypass = Spi::get_one::<bool>(&format!(
            "SELECT COALESCE(
                (SELECT (unnest(useconfig) LIKE 'password_profile.bypass_password_profile=true')
                 FROM pg_user WHERE usename = {}
                 LIMIT 1),
                false
            )",
            username_quoted
        ))?.unwrap_or(false);
        
        if bypass {
            return Ok((false, true, 0, 0));
        }

        // Get user-specific settings
        let lockout = Spi::get_one::<i32>(&format!(
            "SELECT COALESCE(
                (SELECT substring(cfg FROM 'password_profile\\.lockout_minutes=([0-9]+)')::int
                 FROM unnest((SELECT useconfig FROM pg_user WHERE usename = {})) AS cfg
                 WHERE cfg LIKE 'password_profile.lockout_minutes=%'),
                {}
            )",
            username_quoted, LOCKOUT_MINUTES.get()
        ))?.unwrap_or(LOCKOUT_MINUTES.get());
        
        let max_fails_val = Spi::get_one::<i32>(&format!(
            "SELECT COALESCE(
                (SELECT substring(cfg FROM 'password_profile\\.failed_login_max=([0-9]+)')::int
                 FROM unnest((SELECT useconfig FROM pg_user WHERE usename = {})) AS cfg
                 WHERE cfg LIKE 'password_profile.failed_login_max=%'),
                {}
            )",
            username_quoted, FAILED_LOGIN_MAX.get()
        ))?.unwrap_or(FAILED_LOGIN_MAX.get());

        // Cleanup expired lockouts
        Spi::run(&format!(
            "UPDATE password_profile.login_attempts 
             SET fail_count = 0, lockout_until = NULL
             WHERE username = {} AND lockout_until IS NOT NULL AND lockout_until <= now()",
            username_quoted
        ))?;

        // Insert or update failed attempt
        Spi::run(&format!(
            "INSERT INTO password_profile.login_attempts (username, fail_count, last_fail, lockout_until)
             VALUES ({}, 1, now(), NULL)
             ON CONFLICT (username) DO UPDATE SET
                 fail_count = password_profile.login_attempts.fail_count + 1,
                 last_fail = now(),
                 lockout_until = CASE
                     WHEN password_profile.login_attempts.fail_count + 1 >= {}
                     THEN now() + make_interval(mins => {})
                     ELSE NULL
                 END",
            username_quoted, max_fails_val, lockout
        ))?;

        Ok((false, false, lockout, max_fails_val))
    })?;
    
    if is_superuser {
        return Ok("Superuser bypassed".to_string());
    }
    
    if bypass_check {
        return Ok("Bypassed failed login tracking".to_string());
    }

    sync_lock_cache(username, max_fails)?;
    Ok("Failed login recorded".to_string())
}
#[pg_extern]
fn clear_login_attempts(username: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Security check: Only superuser or the same user can clear attempts
    // Use single Spi::connect() to avoid nested SPI
    let (current_user, is_superuser) = Spi::connect(|_client| {
        let user = Spi::get_one::<String>("SELECT current_user::text")?
            .ok_or("Failed to get current user")?;
        
        let user_quoted = quote_literal(&user)?;
        let is_super = Spi::get_one::<bool>(&format!(
            "SELECT usesuper FROM pg_user WHERE usename = {}", 
            user_quoted
        ))?.unwrap_or(false);
        
        Ok::<(String, bool), Box<dyn std::error::Error>>((user, is_super))
    })?;
    
    if !is_superuser && current_user != username {
        return Err(format!(
            "Permission denied: Only superuser or user '{}' can clear their login attempts",
            username
        ).into());
    }
    
    clear_login_attempts_internal(username)?;
    Ok("Login attempts cleared".to_string())
}

fn clear_login_attempts_internal(username: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Use single Spi::connect() to avoid nested SPI
    Spi::connect(|_client| {
        let username_quoted = quote_literal(username)?;
        Spi::run(&format!(
            "DELETE FROM password_profile.login_attempts WHERE username = {}", 
            username_quoted
        ))?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    
    unsafe {
        lock_cache_clear(username);
    }
    Ok(())
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
    // CRITICAL: Check database context before SPI operations
    let my_db_id = unsafe { std::ptr::addr_of!(pg_sys::MyDatabaseId).read() };
    if my_db_id == pg_sys::InvalidOid {
        pgrx::log!(
            "password_profile: check_user_access skipped - no database context"
        );
        return Ok("Access check skipped - no database context".to_string());
    }

    // First check lock cache (fast, no DB access needed)
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

    // Hash password with bcrypt (cost from GUC parameter)
    let cost = BCRYPT_COST.get().clamp(4, 31) as u32; // Ensure valid range
    let pwd_hash =
        hash(new_password, cost).map_err(|e| format!("Failed to hash password: {}", e))?;
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

fn sync_lock_cache(username: &str, max_fails: i32) -> Result<(), Box<dyn std::error::Error>> {
    // CRITICAL: Check if we're in a backend process with database connection
    let my_db_id = unsafe { std::ptr::addr_of!(pg_sys::MyDatabaseId).read() };
    if my_db_id == pg_sys::InvalidOid {
        return Ok(());
    }

    // Use single Spi::connect() to avoid nested SPI calls from worker
    let username_quoted = quote_literal(username)?;
    let result: Option<(i64, i64)> = Spi::connect(|_client| {
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

        let row_result = Spi::get_two::<i64, i64>(&status_query)?;
            
        if let (Some(fails), Some(remaining_secs)) = row_result {
            if fails >= max_fails as i64 && remaining_secs <= 0 {
                // Lockout expired - delete DB record
                Spi::run(&format!(
                    "DELETE FROM password_profile.login_attempts WHERE username = {}",
                    username_quoted
                ))?;
            }
            Ok::<Option<(i64, i64)>, Box<dyn std::error::Error>>(Some((fails, remaining_secs)))
        } else {
            Ok(None)
        }
    })?;

    unsafe {
        match result {
            Some((fails, remaining_secs)) => {
                if fails >= max_fails as i64 && remaining_secs > 0 {
                    // Active lockout - add to cache
                    let now = pg_sys::GetCurrentTimestamp();
                    let delta = remaining_secs.saturating_mul(MICROS_PER_SEC);
                    let expires_at = now.saturating_add(delta);
                    lock_cache_set(username, expires_at);
                } else {
                    // Not locked or expired - clear cache
                    lock_cache_clear(username);
                }
            }
            None => {
                lock_cache_clear(username);
            }
        }
    }

    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn auth_event_consumer_main(_arg: pg_sys::Datum) {
    use std::thread;
    use std::time::Duration;

    BackgroundWorker::attach_signal_handlers(SignalWakeFlags::SIGHUP | SignalWakeFlags::SIGTERM);
    BackgroundWorker::connect_worker_to_spi(Some("postgres"), None);

    pgrx::log!("password_profile: auth event consumer worker started");

    loop {
        if BackgroundWorker::sigterm_received() {
            pgrx::log!("password_profile: auth event consumer shutting down");
            break;
        }

        let mut processed = false;
        while let Some(event) = dequeue_auth_event() {
            processed = true;
            if let Some(username) = username_from_bytes(&event.username) {
                // SECURITY: Do not log usernames

                // CRITICAL: Each SPI operation must be in its own transaction block
                let result = BackgroundWorker::transaction(|| {
                    if event.is_failure {
                        match record_failed_login(&username) {
                            Ok(_) => {
                                // SECURITY: Do not log usernames
                                Ok(())
                            }
                            Err(e) => {
                                pgrx::warning!(
                                    "password_profile: worker failed to record login: {}",
                                    e
                                );
                                Err(e)
                            }
                        }
                    } else {
                        match clear_login_attempts_internal(&username) {
                            Ok(_) => {
                                // SECURITY: Do not log usernames
                                Ok(())
                            }
                            Err(e) => {
                                pgrx::warning!(
                                    "password_profile: worker failed to clear login attempts: {}",
                                    e
                                );
                                Err(e)
                            }
                        }
                    }
                });

                if let Err(e) = result {
                    pgrx::warning!("password_profile: worker transaction failed: {:?}", e);
                }
            }
        }

        if !processed {
            thread::sleep(Duration::from_millis(25));
        }
    }

    pgrx::log!("password_profile: auth event consumer worker stopped");
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
    let mut stats = Vec::new();

    unsafe {
        if !LOCK_CACHE.is_null() {
            let cache = &*LOCK_CACHE;
            let now = pg_sys::GetCurrentTimestamp();
            
            // SAFETY: Read-only access to cache for statistics
            let _guard = SpinLockGuard::new(&mut (*LOCK_CACHE).lock);
            
            // Count active (non-expired) entries
            let active_count = cache
                .entries
                .iter()
                .filter(|e| e.username[0] != 0 && e.expires_at > now)
                .count() as i64;

            // Count total used slots (including expired)
            let used_count = cache
                .entries
                .iter()
                .filter(|e| e.username[0] != 0)
                .count() as i64;

            stats.push((
                "lock_cache_total_size".to_string(),
                LOCK_CACHE_SIZE as i64,
                "Maximum number of lockout entries".to_string(),
            ));

            stats.push((
                "lock_cache_active_lockouts".to_string(),
                active_count,
                "Currently locked accounts (non-expired)".to_string(),
            ));

            stats.push((
                "lock_cache_used_slots".to_string(),
                used_count,
                "Total used cache slots (including expired)".to_string(),
            ));

            stats.push((
                "lock_cache_free_slots".to_string(),
                (LOCK_CACHE_SIZE as i64) - used_count,
                "Available cache slots for new lockouts".to_string(),
            ));

            stats.push((
                "lock_cache_utilization_pct".to_string(),
                (used_count * 100) / (LOCK_CACHE_SIZE as i64),
                "Cache utilization percentage".to_string(),
            ));
        } else {
            stats.push((
                "lock_cache_status".to_string(),
                0,
                "Lock cache not initialized".to_string(),
            ));
        }
    }

    // Add database-based stats (failed login attempts count)
    if let Ok(Some(total_attempts)) = Spi::get_one::<i64>(
        "SELECT COUNT(*) FROM password_profile.login_attempts WHERE fail_count > 0",
    ) {
        stats.push((
            "db_users_with_failures".to_string(),
            total_attempts,
            "Users with recorded failed attempts".to_string(),
        ));
    }

    if let Ok(Some(active_lockouts)) = Spi::get_one::<i64>(
        "SELECT COUNT(*) FROM password_profile.login_attempts WHERE lockout_until > NOW()",
    ) {
        stats.push((
            "db_active_lockouts".to_string(),
            active_lockouts,
            "Users currently locked in database".to_string(),
        ));
    }

    Ok(TableIterator::new(stats))
}

#[cfg(test)]
mod tests {
    use pgrx::prelude::*;

    #[test]
    fn test_quote_literal_basic() {
        let result = crate::quote_literal("test").unwrap();
        assert_eq!(result, "'test'");
    }

    #[test]
    fn test_quote_literal_with_quotes() {
        let result = crate::quote_literal("test'with'quotes").unwrap();
        // PostgreSQL quote_literal_cstr doubles single quotes
        assert!(result.contains("''"));
    }

    #[test]
    fn test_quote_literal_sql_injection() {
        let malicious = "'; DROP TABLE users; --";
        let result = crate::quote_literal(malicious).unwrap();
        // Should be safely quoted
        assert!(result.starts_with("'"));
        assert!(result.ends_with("'"));
    }

    #[test]
    fn test_user_exists_real_user() {
        // Create a test user
        Spi::run("CREATE USER test_exists_user WITH PASSWORD 'test123'").ok();
        
        let username = std::ffi::CString::new("test_exists_user").unwrap();
        let result = unsafe { crate::password_profile_user_exists(username.as_ptr()) };
        
        assert_eq!(result, 1, "Real user should return 1");
        
        // Cleanup
        Spi::run("DROP USER test_exists_user").ok();
    }

    #[test]
    fn test_user_exists_fake_user() {
        let username = std::ffi::CString::new("definitely_not_exists_99999").unwrap();
        let result = unsafe { crate::password_profile_user_exists(username.as_ptr()) };
        
        assert_eq!(result, 0, "Fake user should return 0");
    }

    #[test]
    fn test_user_exists_null() {
        let result = unsafe { crate::password_profile_user_exists(std::ptr::null()) };
        assert_eq!(result, -1, "NULL username should return -1");
    }

    #[test]
    fn test_record_failed_login_basic() {
        // Ensure schema and table exist
        Spi::run("CREATE SCHEMA IF NOT EXISTS password_profile").ok();
        Spi::run("CREATE TABLE IF NOT EXISTS password_profile.login_attempts (
            username TEXT PRIMARY KEY,
            fail_count INT DEFAULT 0,
            last_fail TIMESTAMPTZ,
            lockout_until TIMESTAMPTZ
        )").ok();

        // Create a test user
        Spi::run("CREATE USER test_fail_user WITH PASSWORD 'test123'").ok();
        
        // Record a failed login
        let result = crate::record_failed_login("test_fail_user");
        assert!(result.is_ok(), "record_failed_login should succeed");

        // Check that fail_count was incremented
        let count: Option<i32> = Spi::get_one(
            "SELECT fail_count FROM password_profile.login_attempts WHERE username = 'test_fail_user'"
        ).unwrap();
        
        assert!(count.is_some(), "Should have a record");
        assert!(count.unwrap() > 0, "Fail count should be greater than 0");

        // Cleanup
        Spi::run("DELETE FROM password_profile.login_attempts WHERE username = 'test_fail_user'").ok();
        Spi::run("DROP USER test_fail_user").ok();
    }

    #[test]
    fn test_clear_login_attempts() {
        // Setup
        Spi::run("CREATE SCHEMA IF NOT EXISTS password_profile").ok();
        Spi::run("CREATE TABLE IF NOT EXISTS password_profile.login_attempts (
            username TEXT PRIMARY KEY,
            fail_count INT DEFAULT 0,
            last_fail TIMESTAMPTZ,
            lockout_until TIMESTAMPTZ
        )").ok();

        Spi::run("CREATE USER test_clear_user WITH PASSWORD 'test123'").ok();
        
        // Insert a failed attempt
        Spi::run("INSERT INTO password_profile.login_attempts (username, fail_count, last_fail) 
                  VALUES ('test_clear_user', 5, NOW())").ok();

        // Clear as superuser (current user in tests)
        let result = crate::clear_login_attempts("test_clear_user");
        assert!(result.is_ok(), "clear_login_attempts should succeed");

        // Verify cleared
        let count: Option<i32> = Spi::get_one(
            "SELECT COUNT(*) FROM password_profile.login_attempts WHERE username = 'test_clear_user'"
        ).unwrap();
        
        assert_eq!(count.unwrap(), 0, "Record should be deleted");

        // Cleanup
        Spi::run("DROP USER test_clear_user").ok();
    }

    #[test]
    fn test_password_validation_weak() {
        // Test weak password rejection
        let result = Spi::run("SET password_profile.password_min_length = 8");
        assert!(result.is_ok());

        // This should fail validation (too short)
        let result = Spi::run("CREATE USER test_weak WITH PASSWORD 'weak'");
        assert!(result.is_err(), "Weak password should be rejected");
    }

    #[test]
    fn test_detect_hash_password() {
        // Test hash detection to prevent bypass
        let hash_attempts = vec![
            "md5c4ca4238a0b923820dcc509a6f75849b",  // MD5 hash
            "SCRAM-SHA-256$",                        // SCRAM prefix
            "$2a$10$abcdefghijklmnopqrstuv",          // Bcrypt
        ];
        
        for attempt in hash_attempts {
            let is_hash = crate::is_hash_like(attempt);
            assert!(is_hash, "Should detect '{}' as hash", attempt);
        }
        
        // Normal passwords should not be detected as hashes
        assert!(!crate::is_hash_like("MyPassword123!"));
        assert!(!crate::is_hash_like("valid_pass_2024"));
    }
}
