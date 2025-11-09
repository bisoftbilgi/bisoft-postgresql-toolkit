use pgrx::pg_sys;
use std::ptr;

const CACHE_ENTRIES: usize = 4096;

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CacheState {
    Unknown = 0,
    Approved = 1,
    Pending = 2,
    Blocked = 3,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct CacheEntry {
    fingerprint: u64,
    role_oid: pg_sys::Oid,
    command_code: u8,
    state: u8,
    hit_count: u32,
    last_seen: pg_sys::TimestampTz,
}

impl Default for CacheEntry {
    fn default() -> Self {
        Self {
            fingerprint: 0,
            role_oid: pg_sys::InvalidOid,
            command_code: 0,
            state: CacheState::Unknown as u8,
            hit_count: 0,
            last_seen: 0,
        }
    }
}

#[repr(C)]
struct FingerprintCache {
    lock: pg_sys::slock_t,
    entries: [CacheEntry; CACHE_ENTRIES],
}

static mut CACHE: *mut FingerprintCache = ptr::null_mut();

pub fn shared_memory_bytes() -> usize {
    std::mem::size_of::<FingerprintCache>()
}

pub unsafe fn init() {
    if !CACHE.is_null() {
        return;
    }

    let mut found = false;
    let cache_ptr = pg_sys::ShmemInitStruct(
        b"sql_firewall_fingerprint_cache\0".as_ptr() as *const i8,
        shared_memory_bytes(),
        &mut found as *mut bool,
    ) as *mut FingerprintCache;

    if cache_ptr.is_null() {
        pgrx::error!("sql_firewall_rs: failed to initialize fingerprint cache");
    }

    if !found {
        pg_sys::SpinLockInit(&mut (*cache_ptr).lock);
        for entry in (*cache_ptr).entries.iter_mut() {
            *entry = CacheEntry::default();
        }
        pgrx::log!(
            "sql_firewall_rs: fingerprint cache allocated ({} bytes)",
            shared_memory_bytes()
        );
    } else {
        pgrx::log!("sql_firewall_rs: fingerprint cache attached to existing segment");
    }

    CACHE = cache_ptr;
}

pub struct CacheSnapshot {
    pub state: CacheState,
}

struct SpinLockGuard<'a> {
    lock: &'a mut pg_sys::slock_t,
}

impl<'a> SpinLockGuard<'a> {
    unsafe fn new(lock: &'a mut pg_sys::slock_t) -> Self {
        pg_sys::SpinLockAcquire(lock);
        Self { lock }
    }
}

impl Drop for SpinLockGuard<'_> {
    fn drop(&mut self) {
        unsafe {
            pg_sys::SpinLockRelease(self.lock);
        }
    }
}

fn normalized_role(oid: Option<pg_sys::Oid>) -> pg_sys::Oid {
    oid.unwrap_or(pg_sys::InvalidOid)
}

fn matches(entry: &CacheEntry, role_oid: pg_sys::Oid, fingerprint: u64, command_code: u8) -> bool {
    entry.fingerprint == fingerprint
        && entry.command_code == command_code
        && entry.role_oid == role_oid
}

pub fn lookup(
    role_oid: Option<pg_sys::Oid>,
    fingerprint: u64,
    command_code: u8,
) -> Option<CacheSnapshot> {
    unsafe {
        if CACHE.is_null() {
            return None;
        }
        let cache = &mut *CACHE;
        let _guard = SpinLockGuard::new(&mut cache.lock);
        let role_oid = normalized_role(role_oid);
        cache
            .entries
            .iter()
            .find(|entry| {
                entry.fingerprint != 0 && matches(entry, role_oid, fingerprint, command_code)
            })
            .map(|entry| CacheSnapshot {
                state: match entry.state {
                    1 => CacheState::Approved,
                    2 => CacheState::Pending,
                    3 => CacheState::Blocked,
                    _ => CacheState::Unknown,
                },
            })
    }
}

pub fn remember(
    role_oid: Option<pg_sys::Oid>,
    fingerprint: u64,
    command_code: u8,
    state: CacheState,
    hit_count: u32,
) {
    unsafe {
        if CACHE.is_null() {
            return;
        }
        let cache = &mut *CACHE;
        let role_oid = normalized_role(role_oid);
        let now = pg_sys::GetCurrentTimestamp();
        let mut reused = false;
        {
            let _guard = SpinLockGuard::new(&mut cache.lock);
            if let Some(entry) = cache.entries.iter_mut().find(|entry| {
                entry.fingerprint != 0 && matches(entry, role_oid, fingerprint, command_code)
            }) {
                entry.state = state as u8;
                entry.hit_count = hit_count;
                entry.last_seen = now;
                reused = true;
            } else if let Some(slot) = cache
                .entries
                .iter_mut()
                .find(|entry| entry.fingerprint == 0)
            {
                *slot = CacheEntry {
                    fingerprint,
                    role_oid,
                    command_code,
                    state: state as u8,
                    hit_count,
                    last_seen: now,
                };
                reused = true;
            } else if let Some(oldest) =
                cache.entries.iter_mut().min_by_key(|entry| entry.last_seen)
            {
                *oldest = CacheEntry {
                    fingerprint,
                    role_oid,
                    command_code,
                    state: state as u8,
                    hit_count,
                    last_seen: now,
                };
                reused = true;
            }
        }

        if !reused {
            pgrx::warning!("sql_firewall_rs: fingerprint cache insertion failed (no slot)");
        }
    }
}

pub fn command_code(command: &str) -> u8 {
    match command {
        "SELECT" => 1,
        "INSERT" => 2,
        "UPDATE" => 3,
        "DELETE" => 4,
        _ => 0,
    }
}
