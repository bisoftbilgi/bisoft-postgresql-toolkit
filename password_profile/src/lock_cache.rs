use crate::sql::{spi_update, text_arg};
use crate::{encode_username, SpinLockGuard, LOCK_CACHE_SIZE, LOCK_USERNAME_BYTES, MICROS_PER_SEC};
use pgrx::pg_sys;
use pgrx::spi::Spi;
use std::error::Error;
use std::ptr;

#[repr(C)]
pub(crate) struct LockEntry {
    pub(crate) username: [u8; LOCK_USERNAME_BYTES],
    pub(crate) expires_at: pg_sys::TimestampTz,
}

impl LockEntry {
    #[allow(dead_code)]
    pub(crate) const fn new() -> Self {
        LockEntry {
            username: [0; LOCK_USERNAME_BYTES],
            expires_at: 0,
        }
    }
}

#[repr(C)]
pub(crate) struct LockCache {
    pub(crate) lock: pg_sys::slock_t,
    pub(crate) entries: [LockEntry; LOCK_CACHE_SIZE],
}

pub(crate) static mut LOCK_CACHE: *mut LockCache = ptr::null_mut();

pub(crate) fn shared_memory_bytes() -> usize {
    std::mem::size_of::<LockCache>()
}

pub(crate) unsafe fn init() {
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

pub(crate) unsafe fn set(username: &str, expires_at: pg_sys::TimestampTz) {
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

    enum CacheOp {
        Updated,
        Inserted,
        Evicted(String),
        OverwriteSlot0,
    }
    let operation: CacheOp;

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
            let old_username = std::str::from_utf8(&oldest_entry.username)
                .unwrap_or("(invalid)")
                .trim_end_matches('\0')
                .to_string();
            oldest_entry.username = encoded;
            oldest_entry.expires_at = expires_at;
            operation = CacheOp::Evicted(old_username);
        } else {
            cache.entries[0].username = encoded;
            cache.entries[0].expires_at = expires_at;
            operation = CacheOp::OverwriteSlot0;
        }
    }

    match operation {
        CacheOp::Updated => pgrx::log!(
            "password_profile: lock cache update existing user={} expires_at={}",
            username,
            expires_at
        ),
        CacheOp::Inserted => pgrx::log!(
            "password_profile: lock cache set user={} expires_at={}",
            username,
            expires_at
        ),
        CacheOp::Evicted(old_user) => {
            pgrx::warning!(
                "password_profile: LockCache full ({} entries), evicting oldest entry: {}",
                LOCK_CACHE_SIZE,
                old_user
            );
            pgrx::log!(
                "password_profile: lock cache evicted and set user={} expires_at={}",
                username,
                expires_at
            );
        }
        CacheOp::OverwriteSlot0 => pgrx::log!(
            "password_profile: lock cache overwrite slot0 user={} expires_at={}",
            username,
            expires_at
        ),
    }
}

pub(crate) unsafe fn clear(username: &str) {
    if LOCK_CACHE.is_null() {
        return;
    }
    let encoded = encode_username(username);
    let cache = &mut *LOCK_CACHE;

    {
        let _guard = SpinLockGuard::new(&mut cache.lock);

        for entry in cache.entries.iter_mut() {
            if entry.username[0] != 0 && entry.username == encoded {
                entry.username = [0; LOCK_USERNAME_BYTES];
                entry.expires_at = 0;
                break;
            }
        }
    }
}

pub(crate) unsafe fn remaining_seconds(username: &str) -> Option<i64> {
    if LOCK_CACHE.is_null() {
        return None;
    }

    // CRITICAL: NO catch_unwind - conflicts with PostgreSQL signal handling!
    // Spinlock operations are panic-safe via RAII guard
    let encoded = encode_username(username);
    let cache = &mut *LOCK_CACHE;
    let now = pg_sys::GetCurrentTimestamp();
    let mut remaining = None;

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

pub(crate) fn sync(username: &str, max_fails: i32) -> Result<(), Box<dyn Error>> {
    let my_db_id = unsafe { std::ptr::addr_of!(pg_sys::MyDatabaseId).read() };
    if my_db_id == pg_sys::InvalidOid {
        return Ok(());
    }

    let result: Option<(i64, i64)> = Spi::connect_mut(|client| -> pgrx::spi::Result<_> {
        let args = [text_arg(username)];
        let table = client.select(
            "SELECT fail_count::bigint,
                    GREATEST(
                        COALESCE(ROUND(EXTRACT(EPOCH FROM (lockout_until - now())))::bigint, 0),
                        0
                    )
             FROM password_profile.login_attempts
             WHERE username = $1",
            Some(1),
            &args,
        )?;

        let row_result = table.first().get_two::<i64, i64>()?;

        if let (Some(fails), Some(remaining_secs)) = row_result {
            if fails >= max_fails as i64 && remaining_secs <= 0 {
                spi_update(
                    client,
                    "DELETE FROM password_profile.login_attempts WHERE username = $1",
                    &args,
                )?;
            }
            Ok(Some((fails, remaining_secs)))
        } else {
            Ok(None)
        }
    })?;

    unsafe {
        match result {
            Some((fails, remaining_secs)) => {
                if fails >= max_fails as i64 && remaining_secs > 0 {
                    let expires_at =
                        pg_sys::GetCurrentTimestamp() + (remaining_secs * MICROS_PER_SEC as i64);
                    set(username, expires_at);
                } else if remaining_secs <= 0 {
                    clear(username);
                }
            }
            None => {
                clear(username);
            }
        }
    }

    Ok(())
}

pub(crate) fn collect_stats() -> Result<Vec<(String, i64, String)>, Box<dyn Error>> {
    let mut stats = Vec::new();

    unsafe {
        if !LOCK_CACHE.is_null() {
            let cache = &*LOCK_CACHE;
            let now = pg_sys::GetCurrentTimestamp();
            let _guard = SpinLockGuard::new(&mut (*LOCK_CACHE).lock);

            let active_count = cache
                .entries
                .iter()
                .filter(|e| e.username[0] != 0 && e.expires_at > now)
                .count() as i64;

            let used_count = cache.entries.iter().filter(|e| e.username[0] != 0).count() as i64;

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
            "Users currently locked (database state)".to_string(),
        ));
    }

    Ok(stats)
}
