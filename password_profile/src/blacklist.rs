use crate::sql::text_arg;
use crate::SpinLockGuard;
use pgrx::pg_sys;
use pgrx::spi::Spi;
use siphasher::sip::SipHasher13;
use std::hash::{Hash, Hasher};
use std::ptr;

const BLACKLIST_HASH_SIZE: usize = 10000;

#[repr(C)]
pub(crate) struct BlacklistCache {
    pub(crate) lock: pg_sys::slock_t,
    pub(crate) count: u32,
    pub(crate) sip_k0: u64,
    pub(crate) sip_k1: u64,
    pub(crate) hashes: [u64; BLACKLIST_HASH_SIZE],
}

pub(crate) static mut BLACKLIST_CACHE_SHM: *mut BlacklistCache = ptr::null_mut();

pub(crate) fn shared_memory_bytes() -> usize {
    std::mem::size_of::<BlacklistCache>()
}

pub(crate) unsafe fn init() {
    if !BLACKLIST_CACHE_SHM.is_null() {
        return;
    }

    let size = std::mem::size_of::<BlacklistCache>();
    let mut found_local = false;
    let cache_ptr = pg_sys::ShmemInitStruct(
        c"password_profile_blacklist_cache".as_ptr(),
        size,
        &mut found_local as *mut bool,
    ) as *mut BlacklistCache;
    let found = found_local;

    if cache_ptr.is_null() {
        pgrx::error!("password_profile: failed to initialize blacklist cache");
    }

    if !found {
        (*cache_ptr).lock = 0;
        pg_sys::SpinLockInit(&mut (*cache_ptr).lock);
        (*cache_ptr).count = 0;
        (*cache_ptr).sip_k0 = 0x736f6d6570736575;
        (*cache_ptr).sip_k1 = 0x646f72616e646f6d;
        (*cache_ptr).hashes = [0; BLACKLIST_HASH_SIZE];
        pgrx::log!(
            "password_profile: blacklist cache allocated ({} bytes)",
            size
        );
    } else {
        pgrx::log!("password_profile: blacklist cache attached to existing segment");
    }

    BLACKLIST_CACHE_SHM = cache_ptr;
}

pub(crate) fn contains(password: &str) -> bool {
    if unsafe { pg_sys::IsUnderPostmaster } {
        let db_check = Spi::get_one_with_args::<bool>(
            "SELECT EXISTS(SELECT 1 FROM password_profile.blacklist WHERE password = $1)",
            &[text_arg(password)],
        );

        if let Ok(Some(true)) = db_check {
            return true;
        }
    }

    unsafe {
        if BLACKLIST_CACHE_SHM.is_null() {
            pgrx::warning!("Blacklist cache not initialized");
            return false;
        }

        let cache = &*BLACKLIST_CACHE_SHM;

        let mut hasher = SipHasher13::new_with_keys(cache.sip_k0, cache.sip_k1);
        password.hash(&mut hasher);
        let password_hash = hasher.finish();

        let result = {
            let _guard = SpinLockGuard::new(&mut (*BLACKLIST_CACHE_SHM).lock);
            let count = cache.count as usize;
            let hashes = &cache.hashes[0..count];
            hashes.binary_search(&password_hash).is_ok()
        };

        result
    }
}
