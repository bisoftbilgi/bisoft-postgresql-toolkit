use crate::{encode_username, SpinLockGuard, LOCK_USERNAME_BYTES};
use pgrx::pg_sys;
use std::ptr;

#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SharedAuthEvent {
    pub(crate) username: [u8; LOCK_USERNAME_BYTES],
    pub(crate) timestamp: pg_sys::TimestampTz,
    pub(crate) is_failure: bool,
}

#[repr(C)]
struct AuthEventRing {
    lock: pg_sys::slock_t,
    head: u32,
    tail: u32,
    dropped: u64,
    events: [SharedAuthEvent; crate::AUTH_EVENT_RING_SIZE],
}

static mut AUTH_EVENT_RING: *mut AuthEventRing = ptr::null_mut();

pub(crate) fn shared_memory_bytes() -> usize {
    std::mem::size_of::<AuthEventRing>()
}

pub(crate) unsafe fn init() {
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

pub(crate) fn enqueue(username: &str, is_failure: bool) {
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
            let next_head = (ring.head + 1) % crate::AUTH_EVENT_RING_SIZE as u32;
            if next_head == ring.tail {
                ring.tail = (ring.tail + 1) % crate::AUTH_EVENT_RING_SIZE as u32;
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
            pgrx::warning!("password_profile: auth event ring full; oldest event dropped");
        }
    }
}

pub(crate) fn dequeue() -> Option<SharedAuthEvent> {
    unsafe {
        if AUTH_EVENT_RING.is_null() {
            return None;
        }

        let mut event = None;
        {
            let ring = &mut *AUTH_EVENT_RING;
            let _guard = SpinLockGuard::new(&mut ring.lock);
            if ring.tail != ring.head {
                event = Some(ring.events[ring.tail as usize]);
                ring.tail = (ring.tail + 1) % crate::AUTH_EVENT_RING_SIZE as u32;
            }
        }
        event
    }
}

pub(crate) fn username_from_bytes(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if end == 0 {
        return None;
    }
    std::str::from_utf8(&bytes[..end])
        .ok()
        .map(|s| s.to_string())
}
