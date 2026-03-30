use pgrx::pg_sys;
use std::ptr;

// Simple LRU cache for command approvals (role + command -> approved boolean)
// Optimizes hot path by avoiding SPI calls for frequently checked permissions

const APPROVAL_CACHE_SIZE: usize = 1024; // 1K entries should cover most active roles

#[repr(C)]
#[derive(Copy, Clone)]
struct ApprovalEntry {
    role_oid: pg_sys::Oid,
    command_hash: u32, // hash of command string
    is_approved: bool,
    timestamp: i64, // For TTL/expiry
    _padding: [u8; 3],
}

impl Default for ApprovalEntry {
    fn default() -> Self {
        Self {
            role_oid: pg_sys::InvalidOid,
            command_hash: 0,
            is_approved: false,
            timestamp: 0,
            _padding: [0; 3],
        }
    }
}

#[repr(C)]
struct ApprovalCache {
    lock: pg_sys::slock_t,
    entries: [ApprovalEntry; APPROVAL_CACHE_SIZE],
}

static mut CACHE: *mut ApprovalCache = ptr::null_mut();

const CACHE_TTL_SECONDS: i64 = 60; // Cache entries valid for 60 seconds

pub fn shared_memory_bytes() -> usize {
    std::mem::size_of::<ApprovalCache>()
}

pub fn initialize() {
    unsafe {
        if !CACHE.is_null() {
            return;
        }

        let size = std::mem::size_of::<ApprovalCache>();
        let cache_ptr = pg_sys::ShmemInitStruct(
            c"sql_firewall_approval_cache".as_ptr(),
            size,
            &mut false,
        ) as *mut ApprovalCache;

        if cache_ptr.is_null() {
            pgrx::error!("sql_firewall: failed to initialize approval cache");
        }

        if (*cache_ptr).lock == 0 {
            pg_sys::SpinLockInit(&mut (*cache_ptr).lock);
            for entry in (*cache_ptr).entries.iter_mut() {
                *entry = ApprovalEntry::default();
            }
            pgrx::log!(
                "sql_firewall: approval cache allocated ({} bytes, {} entries)",
                size,
                APPROVAL_CACHE_SIZE
            );
        } else {
            pgrx::log!("sql_firewall: approval cache attached");
        }

        CACHE = cache_ptr;
    }
}

fn hash_command(command: &str) -> u32 {
    // Simple hash function for command strings
    let mut hash: u32 = 5381;
    for byte in command.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u32);
    }
    hash
}

fn get_current_timestamp() -> i64 {
    unsafe { pg_sys::GetCurrentTimestamp() }
}

/// Check if a (role, command) pair is approved in cache
/// Returns: Some(true) if approved, Some(false) if denied, None if not in cache or expired
pub fn get_approval(role_oid: pg_sys::Oid, command: &str) -> Option<bool> {
    if role_oid == pg_sys::InvalidOid {
        return None;
    }

    let command_hash = hash_command(command);
    let now = get_current_timestamp();
    let ttl_micros = CACHE_TTL_SECONDS * 1_000_000;

    unsafe {
        if CACHE.is_null() {
            return None;
        }

        let cache = &mut *CACHE;
        pg_sys::SpinLockAcquire(&mut cache.lock);

        // Simple hash-based lookup (no sophisticated collision handling)
        let index = (command_hash as usize) % APPROVAL_CACHE_SIZE;
        let entry = &cache.entries[index];

        let result = if entry.role_oid == role_oid && entry.command_hash == command_hash {
            // Check if entry is still valid (not expired)
            if now - entry.timestamp < ttl_micros {
                Some(entry.is_approved)
            } else {
                None // Expired
            }
        } else {
            None // Not found or different entry
        };

        pg_sys::SpinLockRelease(&mut cache.lock);
        result
    }
}

/// Update cache with approval status
pub fn set_approval(role_oid: pg_sys::Oid, command: &str, is_approved: bool) {
    if role_oid == pg_sys::InvalidOid {
        return;
    }

    let command_hash = hash_command(command);
    let now = get_current_timestamp();

    unsafe {
        if CACHE.is_null() {
            return;
        }

        let cache = &mut *CACHE;
        pg_sys::SpinLockAcquire(&mut cache.lock);

        let index = (command_hash as usize) % APPROVAL_CACHE_SIZE;
        cache.entries[index] = ApprovalEntry {
            role_oid,
            command_hash,
            is_approved,
            timestamp: now,
            _padding: [0; 3],
        };

        pg_sys::SpinLockRelease(&mut cache.lock);
    }
}

/// Invalidate all cache entries (call when approvals change)
pub fn invalidate_all() {
    unsafe {
        if CACHE.is_null() {
            return;
        }

        let cache = &mut *CACHE;
        pg_sys::SpinLockAcquire(&mut cache.lock);

        for entry in cache.entries.iter_mut() {
            *entry = ApprovalEntry::default();
        }

        pg_sys::SpinLockRelease(&mut cache.lock);
        pgrx::log!("sql_firewall: approval cache invalidated");
    }
}
