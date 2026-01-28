use pgrx::pg_sys;
use std::ptr;

const MICROS_PER_SEC: i64 = 1_000_000;
const GLOBAL_ENTRIES: usize = 512;
const COMMAND_ENTRIES: usize = 1024;

#[repr(C)]
#[derive(Copy, Clone)]
struct GlobalEntry {
    role_oid: pg_sys::Oid,
    window_start: pg_sys::TimestampTz,
    count: u32,
}

impl Default for GlobalEntry {
    fn default() -> Self {
        Self {
            role_oid: pg_sys::InvalidOid,
            window_start: 0,
            count: 0,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
struct CommandEntry {
    role_oid: pg_sys::Oid,
    command_code: u8,
    window_start: pg_sys::TimestampTz,
    count: u32,
}

impl Default for CommandEntry {
    fn default() -> Self {
        Self {
            role_oid: pg_sys::InvalidOid,
            command_code: 0,
            window_start: 0,
            count: 0,
        }
    }
}

#[repr(C)]
struct RateState {
    lock: pg_sys::slock_t,
    global_entries: [GlobalEntry; GLOBAL_ENTRIES],
    command_entries: [CommandEntry; COMMAND_ENTRIES],
}

static mut RATE_STATE_PTR: *mut RateState = ptr::null_mut();

pub fn shared_memory_bytes() -> usize {
    std::mem::size_of::<RateState>()
}

pub unsafe fn init() {
    if !RATE_STATE_PTR.is_null() {
        return;
    }
    let mut found = false;
    let ptr = pg_sys::ShmemInitStruct(
        b"sql_firewall_rate_state\0".as_ptr() as *const std::ffi::c_char,
        shared_memory_bytes(),
        &mut found as *mut bool,
    ) as *mut RateState;

    if ptr.is_null() {
        pgrx::error!("sql_firewall_rs: failed to allocate rate-limit state");
    }

    if !found {
        pg_sys::SpinLockInit(&mut (*ptr).lock);
        for entry in (*ptr).global_entries.iter_mut() {
            *entry = GlobalEntry::default();
        }
        for entry in (*ptr).command_entries.iter_mut() {
            *entry = CommandEntry::default();
        }
        pgrx::log!(
            "sql_firewall_rs: rate-limit state allocated ({} bytes)",
            shared_memory_bytes()
        );
    } else {
        pgrx::log!("sql_firewall_rs: rate-limit state attached to existing segment");
    }

    RATE_STATE_PTR = ptr;
}

pub struct RateDecision {
    pub attempts: u32,
    pub limit: i32,
    pub window_secs: i32,
}

pub fn check_global(
    role_oid: Option<pg_sys::Oid>,
    limit: i32,
    window_secs: i32,
) -> Option<RateDecision> {
    let role_oid = role_oid?;
    if limit <= 0 || window_secs <= 0 {
        return None;
    }

    unsafe {
        let state = RATE_STATE_PTR;
        if state.is_null() {
            return None;
        }
        let now = pg_sys::GetCurrentTimestamp();
        let mut decision = None;
        let _guard = SpinLockGuard::new(&mut (*state).lock);
        let entry = get_or_create_global(&mut (*state).global_entries, role_oid, now);
        if window_reset(now, entry.window_start, window_secs) {
            entry.window_start = now;
            entry.count = 0;
        }
        entry.count = entry.count.saturating_add(1);
        if entry.count > limit as u32 {
            decision = Some(RateDecision {
                attempts: entry.count,
                limit,
                window_secs,
            });
        }
        decision
    }
}

pub fn check_command(
    role_oid: Option<pg_sys::Oid>,
    command_code: u8,
    limit: i32,
    window_secs: i32,
) -> Option<RateDecision> {
    let role_oid = role_oid?;
    if limit <= 0 || window_secs <= 0 || command_code == 0 {
        return None;
    }

    unsafe {
        let state = RATE_STATE_PTR;
        if state.is_null() {
            return None;
        }
        let now = pg_sys::GetCurrentTimestamp();
        let mut decision = None;
        let _guard = SpinLockGuard::new(&mut (*state).lock);
        let entry =
            get_or_create_command(&mut (*state).command_entries, role_oid, command_code, now);
        if window_reset(now, entry.window_start, window_secs) {
            entry.window_start = now;
            entry.count = 0;
        }
        entry.count = entry.count.saturating_add(1);
        if entry.count > limit as u32 {
            decision = Some(RateDecision {
                attempts: entry.count,
                limit,
                window_secs,
            });
        }
        decision
    }
}

fn window_reset(
    now: pg_sys::TimestampTz,
    window_start: pg_sys::TimestampTz,
    window_secs: i32,
) -> bool {
    window_start == 0 || now.saturating_sub(window_start) >= (window_secs as i64) * MICROS_PER_SEC
}

fn get_or_create_global<'a>(
    entries: &'a mut [GlobalEntry],
    role_oid: pg_sys::Oid,
    now: pg_sys::TimestampTz,
) -> &'a mut GlobalEntry {
    if let Some(idx) = entries.iter().position(|entry| entry.role_oid == role_oid) {
        return &mut entries[idx];
    }
    if let Some(idx) = entries
        .iter()
        .position(|entry| entry.role_oid == pg_sys::InvalidOid)
    {
        entries[idx] = GlobalEntry {
            role_oid,
            window_start: now,
            count: 0,
        };
        return &mut entries[idx];
    }
    let oldest_idx = entries
        .iter()
        .enumerate()
        .min_by_key(|(_, entry)| entry.window_start)
        .map(|(idx, _)| idx)
        .unwrap_or(0);
    let entry = &mut entries[oldest_idx];
    *entry = GlobalEntry {
        role_oid,
        window_start: now,
        count: 0,
    };
    entry
}

fn get_or_create_command<'a>(
    entries: &'a mut [CommandEntry],
    role_oid: pg_sys::Oid,
    command_code: u8,
    now: pg_sys::TimestampTz,
) -> &'a mut CommandEntry {
    if let Some(idx) = entries
        .iter()
        .position(|entry| entry.role_oid == role_oid && entry.command_code == command_code)
    {
        return &mut entries[idx];
    }
    if let Some(idx) = entries
        .iter()
        .position(|entry| entry.role_oid == pg_sys::InvalidOid)
    {
        entries[idx] = CommandEntry {
            role_oid,
            command_code,
            window_start: now,
            count: 0,
        };
        return &mut entries[idx];
    }
    let oldest_idx = entries
        .iter()
        .enumerate()
        .min_by_key(|(_, entry)| entry.window_start)
        .map(|(idx, _)| idx)
        .unwrap_or(0);
    let entry = &mut entries[oldest_idx];
    *entry = CommandEntry {
        role_oid,
        command_code,
        window_start: now,
        count: 0,
    };
    entry
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
            // CRITICAL: Always release lock, even during panic/unwind
            // This prevents deadlock if error occurs while holding lock
            pg_sys::SpinLockRelease(self.lock);
        }
    }
}
