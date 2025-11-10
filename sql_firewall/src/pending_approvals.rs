// ============================================================================
// Pending Approvals Queue - Shared Memory Ring Buffer
// ============================================================================
// Similar to password_profile's auth_event queue, but for firewall approvals.
// Allows recording pending approvals even when main transaction will rollback.

use pgrx::pg_sys;
use std::ptr;

const ROLE_NAME_BYTES: usize = 64;
const COMMAND_TYPE_BYTES: usize = 32;
const DATABASE_NAME_BYTES: usize = 64;

#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct PendingApproval {
    pub(crate) role_name: [u8; ROLE_NAME_BYTES],
    pub(crate) command_type: [u8; COMMAND_TYPE_BYTES],
    pub(crate) database_name: [u8; DATABASE_NAME_BYTES],
    pub(crate) timestamp: pg_sys::TimestampTz,
}

const PENDING_APPROVAL_RING_SIZE: usize = 1024;

#[repr(C)]
struct PendingApprovalRing {
    lock: pg_sys::slock_t,
    head: u32,
    tail: u32,
    dropped: u64,
    approvals: [PendingApproval; PENDING_APPROVAL_RING_SIZE],
}

static mut PENDING_APPROVAL_RING: *mut PendingApprovalRing = ptr::null_mut();

/// RAII guard for PostgreSQL SpinLock - automatically releases lock on drop (panic-safe)
struct SpinLockGuard {
    lock_ptr: *mut pg_sys::slock_t,
}

impl SpinLockGuard {
    unsafe fn new(lock_ptr: *mut pg_sys::slock_t) -> Self {
        pg_sys::SpinLockAcquire(lock_ptr);
        Self { lock_ptr }
    }
}

impl Drop for SpinLockGuard {
    fn drop(&mut self) {
        unsafe { pg_sys::SpinLockRelease(self.lock_ptr) }
    }
}

pub(crate) fn shared_memory_bytes() -> usize {
    std::mem::size_of::<PendingApprovalRing>()
}

/// Initialize shared memory ring buffer for pending approvals
pub(crate) unsafe fn init() {
    if !PENDING_APPROVAL_RING.is_null() {
        return;
    }

    let size = std::mem::size_of::<PendingApprovalRing>();
    let mut found = false;
    let ring_ptr = pg_sys::ShmemInitStruct(
        c"sql_firewall_pending_approval_ring".as_ptr(),
        size,
        &mut found as *mut bool,
    ) as *mut PendingApprovalRing;

    if ring_ptr.is_null() {
        pgrx::error!("sql_firewall: failed to initialize pending approval ring");
    }

    if !found {
        (*ring_ptr).lock = 0;
        pg_sys::SpinLockInit(&mut (*ring_ptr).lock);
        (*ring_ptr).head = 0;
        (*ring_ptr).tail = 0;
        (*ring_ptr).dropped = 0;
        (*ring_ptr).approvals.iter_mut().for_each(|approval| {
            approval.role_name = [0; ROLE_NAME_BYTES];
            approval.command_type = [0; COMMAND_TYPE_BYTES];
            approval.database_name = [0; DATABASE_NAME_BYTES];
            approval.timestamp = 0;
        });
        pgrx::log!(
            "sql_firewall: pending approval ring allocated ({} bytes)",
            size
        );
    } else {
        pgrx::log!("sql_firewall: pending approval ring attached to existing segment");
    }

    PENDING_APPROVAL_RING = ring_ptr;
}

fn encode_string(s: &str, buffer: &mut [u8]) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(buffer.len() - 1);
    buffer[..len].copy_from_slice(&bytes[..len]);
    buffer[len..].fill(0);
}

/// Enqueue a pending approval to shared memory ring buffer
/// This is safe to call even when transaction will rollback
pub(crate) fn enqueue(role_name: &str, command_type: &str, database_name: &str) {
    unsafe {
        if PENDING_APPROVAL_RING.is_null() {
            pgrx::warning!("sql_firewall: pending approval ring not initialized");
            return;
        }

        let mut role_encoded = [0u8; ROLE_NAME_BYTES];
        let mut command_encoded = [0u8; COMMAND_TYPE_BYTES];
        let mut database_encoded = [0u8; DATABASE_NAME_BYTES];
        encode_string(role_name, &mut role_encoded);
        encode_string(command_type, &mut command_encoded);
        encode_string(database_name, &mut database_encoded);

        let ring = &mut *PENDING_APPROVAL_RING;
        let mut dropped_event = false;

        {
            let _guard = SpinLockGuard::new(&mut ring.lock);
            let next_head = (ring.head + 1) % PENDING_APPROVAL_RING_SIZE as u32;
            
            // Ring buffer full - drop oldest
            if next_head == ring.tail {
                ring.tail = (ring.tail + 1) % PENDING_APPROVAL_RING_SIZE as u32;
                ring.dropped = ring.dropped.saturating_add(1);
                dropped_event = true;
            }

            ring.approvals[ring.head as usize] = PendingApproval {
                role_name: role_encoded,
                command_type: command_encoded,
                database_name: database_encoded,
                timestamp: pg_sys::GetCurrentTimestamp(),
            };
            ring.head = next_head;
        }

        if dropped_event {
            pgrx::warning!("sql_firewall: pending approval ring full; oldest approval dropped");
        }
    }
}

/// Dequeue a pending approval from shared memory ring buffer
/// Called by background worker to process approvals
pub(crate) fn dequeue() -> Option<PendingApproval> {
    unsafe {
        if PENDING_APPROVAL_RING.is_null() {
            return None;
        }

        let mut approval = None;
        {
            let ring = &mut *PENDING_APPROVAL_RING;
            let _guard = SpinLockGuard::new(&mut ring.lock);
            if ring.tail != ring.head {
                approval = Some(ring.approvals[ring.tail as usize]);
                ring.tail = (ring.tail + 1) % PENDING_APPROVAL_RING_SIZE as u32;
            }
        }
        approval
    }
}

/// Convert byte array to string
pub(crate) fn string_from_bytes(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if end == 0 {
        return None;
    }
    std::str::from_utf8(&bytes[..end])
        .ok()
        .map(|s| s.to_string())
}

/// Get ring buffer statistics for monitoring
#[allow(dead_code)]
pub(crate) fn get_stats() -> (u32, u32, u64) {
    unsafe {
        if PENDING_APPROVAL_RING.is_null() {
            return (0, 0, 0);
        }
        let ring = &*PENDING_APPROVAL_RING;
        let _guard = SpinLockGuard::new(&mut (*PENDING_APPROVAL_RING).lock);
        
        let pending = if ring.head >= ring.tail {
            ring.head - ring.tail
        } else {
            PENDING_APPROVAL_RING_SIZE as u32 - ring.tail + ring.head
        };
        
        (pending, PENDING_APPROVAL_RING_SIZE as u32, ring.dropped)
    }
}
