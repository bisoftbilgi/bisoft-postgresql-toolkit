// ============================================================================
// Firewall Events Queue - Shared Memory Ring Buffer
// ============================================================================
// Unified event queue for approvals, blocked queries, and fingerprint hits.
// Allows recording events even when main transaction will rollback.
// Supports configurable ring buffer size via GUC parameter.

use pgrx::pg_sys;
use std::ptr;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

const ROLE_NAME_BYTES: usize = 64;
const COMMAND_TYPE_BYTES: usize = 32;
const DATABASE_NAME_BYTES: usize = 64;
const QUERY_BYTES: usize = 2048;
const APPLICATION_NAME_BYTES: usize = 256;
const CLIENT_ADDR_BYTES: usize = 64;
const REASON_BYTES: usize = 512;
const FINGERPRINT_HEX_BYTES: usize = 32;
const NORMALIZED_QUERY_BYTES: usize = 1024;
const SAMPLE_QUERY_BYTES: usize = 512;

/// Event types that can be queued
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum EventType {
    Approval = 1,
    BlockedQuery = 2,
    FingerprintHit = 3,
}

/// Approval event - command type approval request
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ApprovalEvent {
    pub role_name: [u8; ROLE_NAME_BYTES],
    pub command_type: [u8; COMMAND_TYPE_BYTES],
    pub database_name: [u8; DATABASE_NAME_BYTES],
    pub is_approved: bool,
    pub timestamp: pg_sys::TimestampTz,
}

/// Blocked query event - for audit logging
#[repr(C)]
#[derive(Copy, Clone)]
pub struct BlockedQueryEvent {
    pub role_name: [u8; ROLE_NAME_BYTES],
    pub database_name: [u8; DATABASE_NAME_BYTES],
    pub query: [u8; QUERY_BYTES],
    pub query_truncated: bool,
    pub application_name: [u8; APPLICATION_NAME_BYTES],
    pub client_addr: [u8; CLIENT_ADDR_BYTES],
    pub command_type: [u8; COMMAND_TYPE_BYTES],
    pub reason: [u8; REASON_BYTES],
    pub timestamp: pg_sys::TimestampTz,
}

/// Fingerprint hit event - for fingerprint tracking
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FingerprintHitEvent {
    pub fingerprint_hex: [u8; FINGERPRINT_HEX_BYTES],
    pub normalized_query: [u8; NORMALIZED_QUERY_BYTES],
    pub role_name: [u8; ROLE_NAME_BYTES],
    pub command_type: [u8; COMMAND_TYPE_BYTES],
    pub sample_query: [u8; SAMPLE_QUERY_BYTES],
    pub is_approved: bool,
    pub timestamp: pg_sys::TimestampTz,
}

/// Unified firewall event (tagged union)
#[repr(C)]
pub struct FirewallEvent {
    pub generation: AtomicU64,  // RACE CONDITION FIX: Generation counter for detecting partial writes
    pub event_type: EventType,
    pub db_oid: pg_sys::Oid,  // Database OID for event routing
    pub data: FirewallEventData,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union FirewallEventData {
    pub approval: ApprovalEvent,
    pub blocked_query: BlockedQueryEvent,
    pub fingerprint_hit: FingerprintHitEvent,
}

/// Ring buffer structure (cursor-based log stream)
#[repr(C)]
struct FirewallEventRing {
    write_pos: AtomicU64,  // Ever-increasing write position (total events written)
    dropped_count: AtomicU64,
    last_drop_warning: AtomicI64,
    capacity: u32,
    // Events array follows (allocated dynamically)
    // No head/tail - each worker maintains its own read cursor
}

static mut EVENT_RING: *mut FirewallEventRing = ptr::null_mut();
static mut EVENT_ARRAY: *mut FirewallEvent = ptr::null_mut();

// SpinLock guard removed - no longer needed for cursor-based approach
// (AtomicU64 operations are lock-free)

/// Ring buffer capacity (fixed at compile time for shared memory allocation)
/// TODO Phase 2: Make this configurable via PGC_POSTMASTER GUC parameter
const RING_CAPACITY: usize = 1024;

/// Calculate shared memory bytes needed (called during postmaster startup)
pub(crate) fn shared_memory_bytes() -> usize {
    let capacity = RING_CAPACITY;
    let header_size = std::mem::size_of::<FirewallEventRing>();
    let event_size = std::mem::size_of::<FirewallEvent>();
    header_size + (capacity * event_size)
}

/// Initialize shared memory ring buffer for firewall events
pub(crate) unsafe fn init() {
    pgrx::log!("sql_firewall: pending_approvals::init() called");
    
    if !EVENT_RING.is_null() {
        // Check if capacity needs fixing
        if (*EVENT_RING).capacity == 0 {
            pgrx::warning!("sql_firewall: ring exists but capacity is ZERO - fixing!");
            (*EVENT_RING).capacity = RING_CAPACITY as u32;
        }
        pgrx::log!("sql_firewall: event ring already initialized (capacity={}), skipping", (*EVENT_RING).capacity);
        return;
    }

    let capacity = RING_CAPACITY;
    let size = shared_memory_bytes();
    pgrx::log!("sql_firewall: requesting shared memory for event ring - capacity={}, size={} bytes", capacity, size);
    
    let mut found = false;
    let ring_ptr = pg_sys::ShmemInitStruct(
        c"sql_firewall_event_ring".as_ptr(),
        size,
        &mut found as *mut bool,
    ) as *mut u8;

    pgrx::log!("sql_firewall: ShmemInitStruct returned, found={}, ptr={:?}", found, ring_ptr);

    if ring_ptr.is_null() {
        pgrx::error!("sql_firewall: failed to initialize firewall event ring");
    }

    EVENT_RING = ring_ptr as *mut FirewallEventRing;
    EVENT_ARRAY = ring_ptr.add(std::mem::size_of::<FirewallEventRing>()) as *mut FirewallEvent;
    
    pgrx::log!("sql_firewall: pointers set - EVENT_RING={:?}, EVENT_ARRAY={:?}", std::ptr::addr_of!(EVENT_RING), std::ptr::addr_of!(EVENT_ARRAY));

    if !found {
        pgrx::log!("sql_firewall: initializing ring header fields");
        (*EVENT_RING).write_pos = AtomicU64::new(0);
        (*EVENT_RING).capacity = capacity as u32;
        (*EVENT_RING).dropped_count = AtomicU64::new(0);
        (*EVENT_RING).last_drop_warning = AtomicI64::new(0);

        pgrx::log!("sql_firewall: zeroing event array - capacity={}", capacity);
        // Initialize event array to zero using ptr::write_bytes (safe for POD types)
        std::ptr::write_bytes(EVENT_ARRAY, 0, capacity);
        pgrx::log!("sql_firewall: event array zeroed successfully");

        pgrx::log!(
            "sql_firewall: event ring allocated ({} bytes, capacity={})",
            size,
            capacity
        );
    } else {
        // CRITICAL FIX: Ensure capacity is set even when ring already exists
        pgrx::log!("sql_firewall: ring already exists, verifying capacity");
        if (*EVENT_RING).capacity == 0 {
            pgrx::warning!("sql_firewall: existing ring has zero capacity, fixing");
            (*EVENT_RING).capacity = capacity as u32;
        }
        pgrx::log!(
            "sql_firewall: event ring attached to existing segment (capacity={})",
            (*EVENT_RING).capacity
        );
    }
}

fn encode_string(s: &str, buffer: &mut [u8]) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(buffer.len() - 1);
    buffer[..len].copy_from_slice(&bytes[..len]);
    buffer[len..].fill(0);
}

/// Emit rate-limited drop warning (max 1 per minute)
unsafe fn emit_drop_warning_if_needed() {
    let ring = &*EVENT_RING;
    let now = pg_sys::GetCurrentTimestamp() / 1_000_000; // Convert to seconds
    let last_warning = ring.last_drop_warning.load(Ordering::Relaxed);

    if now - last_warning >= 60 {
        // 1 minute
        if ring
            .last_drop_warning
            .compare_exchange(last_warning, now, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            let dropped = ring.dropped_count.load(Ordering::Relaxed);
            pgrx::warning!(
                "sql_firewall: Ring buffer full - {} events dropped in last minute. \
                 Consider increasing sql_firewall.ring_buffer_size (current: {})",
                dropped,
                ring.capacity
            );
        }
    }
}

/// Enqueue a firewall event to shared memory ring buffer (LOCK-FREE with generation counter)
/// Always succeeds - overwrites old data if buffer wraps around
unsafe fn enqueue_internal(event: FirewallEvent) -> bool {
    if EVENT_RING.is_null() || EVENT_ARRAY.is_null() {
        pgrx::warning!("sql_firewall: event ring not initialized");
        return false;
    }

    let ring = &*EVENT_RING;
    let capacity = ring.capacity as usize;
    let events = std::slice::from_raw_parts_mut(EVENT_ARRAY, capacity);

    // Atomically claim a write position (lock-free)
    let my_pos = ring.write_pos.fetch_add(1, Ordering::SeqCst);
    
    // Calculate circular index
    let idx = (my_pos as usize) % capacity;
    
    // RACE CONDITION FIX: Set generation to 0 before write, then to my_pos after
    // Readers can detect partial writes by checking generation consistency
    events[idx].generation.store(0, Ordering::Release);
    
    // Set generation in event structure
    event.generation.store(my_pos, Ordering::Relaxed);
    
    // Write event data (may be interrupted, but generation=0 in slot marks it invalid)
    std::ptr::write_volatile(&mut events[idx], event);
    
    // Mark as complete by setting final generation (releases the write)
    events[idx].generation.store(my_pos, Ordering::Release);
    
    true
}

/// Enqueue an approval event
pub(crate) fn enqueue_approval(
    role_name: &str,
    command_type: &str,
    database_name: &str,
    is_approved: bool,
) -> bool {
    unsafe {
        let mut role_encoded = [0u8; ROLE_NAME_BYTES];
        let mut command_encoded = [0u8; COMMAND_TYPE_BYTES];
        let mut database_encoded = [0u8; DATABASE_NAME_BYTES];
        encode_string(role_name, &mut role_encoded);
        encode_string(command_type, &mut command_encoded);
        encode_string(database_name, &mut database_encoded);

        let db_oid = pg_sys::MyDatabaseId;
        
        let event = FirewallEvent {
            generation: AtomicU64::new(0),  // Will be set by enqueue_internal
            event_type: EventType::Approval,
            db_oid,
            data: FirewallEventData {
                approval: ApprovalEvent {
                    role_name: role_encoded,
                    command_type: command_encoded,
                    database_name: database_encoded,
                    is_approved,
                    timestamp: pg_sys::GetCurrentTimestamp(),
                },
            },
        };

        enqueue_internal(event)
    }
}

/// Enqueue a blocked query event
pub(crate) fn enqueue_blocked_query(
    role_name: &str,
    database_name: &str,
    query: &str,
    application_name: Option<&str>,
    client_addr: Option<&str>,
    command_type: &str,
    reason: Option<&str>,
) -> bool {
    unsafe {
        let mut role_encoded = [0u8; ROLE_NAME_BYTES];
        let mut database_encoded = [0u8; DATABASE_NAME_BYTES];
        let mut query_encoded = [0u8; QUERY_BYTES];
        let mut app_encoded = [0u8; APPLICATION_NAME_BYTES];
        let mut addr_encoded = [0u8; CLIENT_ADDR_BYTES];
        let mut command_encoded = [0u8; COMMAND_TYPE_BYTES];
        let mut reason_encoded = [0u8; REASON_BYTES];

        encode_string(role_name, &mut role_encoded);
        encode_string(database_name, &mut database_encoded);
        encode_string(command_type, &mut command_encoded);

        // Check if query is truncated
        let query_truncated = query.len() >= QUERY_BYTES;
        encode_string(query, &mut query_encoded);

        if let Some(app) = application_name {
            encode_string(app, &mut app_encoded);
        }
        if let Some(addr) = client_addr {
            encode_string(addr, &mut addr_encoded);
        }
        if let Some(r) = reason {
            encode_string(r, &mut reason_encoded);
        }

        let db_oid = pg_sys::MyDatabaseId;

        let event = FirewallEvent {
            generation: AtomicU64::new(0),  // Will be set by enqueue_internal
            event_type: EventType::BlockedQuery,
            db_oid,
            data: FirewallEventData {
                blocked_query: BlockedQueryEvent {
                    role_name: role_encoded,
                    database_name: database_encoded,
                    query: query_encoded,
                    query_truncated,
                    application_name: app_encoded,
                    client_addr: addr_encoded,
                    command_type: command_encoded,
                    reason: reason_encoded,
                    timestamp: pg_sys::GetCurrentTimestamp(),
                },
            },
        };

        enqueue_internal(event)
    }
}

/// Enqueue a fingerprint hit event
pub(crate) fn enqueue_fingerprint(
    fingerprint_hex: &str,
    normalized_query: &str,
    role_name: &str,
    command_type: &str,
    sample_query: &str,
    is_approved: bool,
) -> bool {
    unsafe {
        let mut fp_encoded = [0u8; FINGERPRINT_HEX_BYTES];
        let mut normalized_encoded = [0u8; NORMALIZED_QUERY_BYTES];
        let mut role_encoded = [0u8; ROLE_NAME_BYTES];
        let mut command_encoded = [0u8; COMMAND_TYPE_BYTES];
        let mut sample_encoded = [0u8; SAMPLE_QUERY_BYTES];

        encode_string(fingerprint_hex, &mut fp_encoded);
        encode_string(normalized_query, &mut normalized_encoded);
        encode_string(role_name, &mut role_encoded);
        encode_string(command_type, &mut command_encoded);
        encode_string(sample_query, &mut sample_encoded);

        let db_oid = pg_sys::MyDatabaseId;

        let event = FirewallEvent {
            generation: AtomicU64::new(0),  // Will be set by enqueue_internal
            event_type: EventType::FingerprintHit,
            db_oid,
            data: FirewallEventData {
                fingerprint_hit: FingerprintHitEvent {
                    fingerprint_hex: fp_encoded,
                    normalized_query: normalized_encoded,
                    role_name: role_encoded,
                    command_type: command_encoded,
                    sample_query: sample_encoded,
                    is_approved,
                    timestamp: pg_sys::GetCurrentTimestamp(),
                },
            },
        };

        enqueue_internal(event)
    }
}

/// Get current write position (cursor-based read)
pub(crate) fn get_write_pos() -> u64 {
    unsafe {
        if EVENT_RING.is_null() {
            return 0;
        }
        (*EVENT_RING).write_pos.load(Ordering::SeqCst)
    }
}

/// Get buffer capacity
pub(crate) fn get_capacity() -> usize {
    unsafe {
        if EVENT_RING.is_null() {
            return 0;
        }
        (*EVENT_RING).capacity as usize
    }
}

/// Read event at specific position (cursor-based read - NO DEQUEUE)
/// Workers maintain their own cursors and call this to peek events
pub(crate) fn read_at_index(pos: u64) -> Option<FirewallEvent> {
    unsafe {
        if EVENT_RING.is_null() || EVENT_ARRAY.is_null() {
            return None;
        }

        let ring = &*EVENT_RING;
        let capacity = ring.capacity as usize;
        let events = std::slice::from_raw_parts(EVENT_ARRAY, capacity);

        // Calculate circular index
        let idx = (pos as usize) % capacity;
        
        // RACE CONDITION FIX: Check generation before and after read
        // If generation changes or is 0, the event is being written - skip it
        let gen_before = events[idx].generation.load(Ordering::Acquire);
        if gen_before == 0 {
            // Event is being written, skip
            return None;
        }
        
        // Read event
        let event = std::ptr::read_volatile(&events[idx]);
        
        // Verify generation hasn't changed (no concurrent write)
        let gen_after = events[idx].generation.load(Ordering::Acquire);
        if gen_before != gen_after {
            // Concurrent write detected, discard read
            return None;
        }
        
        // Verify generation matches expected position (detect buffer wraps)
        if gen_after != pos {
            // Event has been overwritten by newer data
            return None;
        }
        
        Some(event)
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
pub(crate) fn get_stats() -> (u64, usize, u64) {
    unsafe {
        if EVENT_RING.is_null() {
            return (0, 0, 0);
        }
        let ring = &*EVENT_RING;
        let write_pos = ring.write_pos.load(Ordering::Relaxed);
        let capacity = ring.capacity as usize;
        let dropped = ring.dropped_count.load(Ordering::Relaxed);

        (write_pos, capacity, dropped)
    }
}

/// LEGACY: Compatibility function for old code (delegates to enqueue_approval with is_approved=false)
#[allow(dead_code)]
pub(crate) fn enqueue(role_name: &str, command_type: &str, database_name: &str) {
    enqueue_approval(role_name, command_type, database_name, false);
}
