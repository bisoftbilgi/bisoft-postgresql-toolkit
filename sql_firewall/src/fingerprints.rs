use crate::{
    context::ExecutionContext,
    fingerprint_cache::{self, CacheState},
    guc::{self, FirewallMode},
    spi_checks,
    sql::{name_arg, text_arg},
};
use pgrx::{
    pg_sys,
    spi::{Spi, SpiTupleTable},
};

pub struct FingerprintSummary {
    pub normalized: String,
    pub hash: u64,
    pub sample: String,
}

impl FingerprintSummary {
    pub fn new(query: &str) -> Self {
        let normalized = normalize_query(query);
        let hash = if normalized.is_empty() {
            0
        } else {
            fnv1a_hash(normalized.as_bytes())
        };
        let sample = truncate_query(query, 512);
        Self {
            normalized,
            hash,
            sample,
        }
    }

    pub fn hex(&self) -> String {
        format!("{:016x}", self.hash)
    }
}

pub fn enforce(
    ctx: &ExecutionContext,
    command: &str,
    mode: FirewallMode,
    query: &str,
) -> Option<String> {
    if !unsafe { pg_sys::IsTransactionState() } {
        return None;
    }
    if !guc::fingerprint_learning_enabled() {
        return None;
    }
    let role = ctx.role.as_deref()?;
    let summary = FingerprintSummary::new(query);
    if summary.hash == 0 {
        return None;
    }
    let fingerprint_hex = summary.hex();
    let command_code = fingerprint_cache::command_code(command);

    if let Some(snapshot) = fingerprint_cache::lookup(ctx.role_oid, summary.hash, command_code) {
        match snapshot.state {
            CacheState::Approved => {
                return None;
            }
            CacheState::Blocked => {
                spi_checks::log_activity(
                    ctx,
                    command,
                    "BLOCKED",
                    Some("Fingerprint blocked"),
                    query,
                );
                return Some(format!(
                    "sql_firewall: Fingerprint '{}' is blocked for role '{}'.",
                    fingerprint_hex, role
                ));
            }
            CacheState::Pending | CacheState::Unknown => {}
        }
    }

    let fingerprint_exists = record_fingerprint_hit(&fingerprint_hex, &summary, role, command);
    
    let (hit_count, mut approved) = match fingerprint_exists {
        Some((raw_hit, is_app)) => (raw_hit.max(1), is_app),
        None => (1, false),  // New fingerprint, not approved yet
    };

    // PHASE 3: Learn mode auto-approves via ASYNC worker queue (ZERO LATENCY)
    if !approved && mode == FirewallMode::Learn {
        // Immediately mark as approved in cache (zero latency)
        approved = true;
        
        // Enqueue fingerprint to worker for DB persistence (async)
        let enqueued = crate::pending_approvals::enqueue_fingerprint(
            &fingerprint_hex,
            &summary.normalized,
            role,
            command,
            &summary.sample,
            true, // is_approved = true (auto-approved in learn mode)
        );
        
        if !enqueued {
            pgrx::warning!(
                "sql_firewall: Learn mode - failed to enqueue fingerprint (ring buffer full): fp={}, role={}",
                fingerprint_hex, role
            );
        } else {
            pgrx::debug1!(
                "sql_firewall: Learn mode - fingerprint queued for async approval: fp={}, role={}, command={}",
                fingerprint_hex, role, command
            );
        }
        
        spi_checks::log_activity(
            ctx,
            command,
            "LEARNED (FINGERPRINT AUTO)",
            Some("Learn mode - fingerprint auto-approved"),
            query,
        );
    }

    let cache_state = if approved {
        CacheState::Approved
    } else {
        CacheState::Pending
    };
    let hit_count = hit_count.max(1);

    fingerprint_cache::remember(
        ctx.role_oid,
        summary.hash,
        command_code,
        cache_state,
        hit_count as u32,
    );

    if approved {
        return None;
    }

    match mode {
        FirewallMode::Learn => {
            // PHASE 2: Learn mode should NEVER reach here (all fingerprints auto-approved above)
            // This is a defensive fallback
            pgrx::warning!(
                "sql_firewall: Learn mode fingerprint not approved - this should not happen! fp={}, role={}",
                fingerprint_hex, role
            );
            None // Allow in Learn mode even if something went wrong
        }
        FirewallMode::Permissive => {
            spi_checks::log_activity(
                ctx,
                command,
                "ALLOWED (PERMISSIVE - FINGERPRINT)",
                Some("Fingerprint pending approval"),
                query,
            );
            None
        }
        FirewallMode::Enforce => {
            // PHASE 2: Enqueue pending fingerprint to worker for admin review
            let enqueued = crate::pending_approvals::enqueue_fingerprint(
                &fingerprint_hex,
                &summary.normalized,
                role,
                command,
                query,
                false, // is_approved = false (pending admin approval)
            );
            
            if !enqueued {
                pgrx::warning!(
                    "sql_firewall: Failed to enqueue pending fingerprint (ring buffer full): fp={}, role={}",
                    fingerprint_hex, role
                );
            }
            
            spi_checks::log_activity(
                ctx,
                command,
                "BLOCKED",
                Some("Fingerprint pending approval"),
                query,
            );
            
            Some(format!(
                "sql_firewall: Fingerprint '{}' for role '{}' is pending approval. \
                 Admin can approve via: UPDATE sql_firewall_query_fingerprints SET is_approved=true \
                 WHERE fingerprint='{}' AND role_name='{}'",
                fingerprint_hex, role, fingerprint_hex, role
            ))
        }
    }
}

fn record_fingerprint_hit(
    fingerprint_hex: &str,
    _summary: &FingerprintSummary,
    role: &str,
    command: &str,
) -> Option<(i32, bool)> {
    // SIMPLIFIED: Only read existing fingerprint, no INSERT/UPDATE
    // Worker will handle persistence via enqueue_fingerprint()
    Spi::connect_mut(|client| {
        match client.select(
            "SELECT hit_count, is_approved
             FROM public.sql_firewall_query_fingerprints
             WHERE fingerprint = $1 AND role_name = $2 AND command_type = $3",
            Some(1),
            &[text_arg(fingerprint_hex), name_arg(role), text_arg(command)],
        ) {
            Ok(table) => extract_hit_row(table),
            Err(err) => {
                // Table doesn't exist or query failed - return None (new fingerprint)
                if err.to_string().contains("does not exist") {
                    None
                } else {
                    pgrx::warning!("sql_firewall: fingerprint fetch failed: {err}");
                    None
                }
            }
        }
    })
}

fn extract_hit_row(mut table: SpiTupleTable<'_>) -> Option<(i32, bool)> {
    if table.is_empty() {
        return None;
    }
    table = table.first();
    match table.get_two::<i32, bool>() {
        Ok((Some(hit), Some(approved))) => Some((hit, approved)),
        Ok(_) => None,
        Err(err) => {
            pgrx::warning!("sql_firewall: fingerprint row decode failed: {err}");
            None
        }
    }
}

fn normalize_query(query: &str) -> String {
    let mut output = String::with_capacity(query.len());
    let mut chars = query.chars().peekable();
    let mut last_was_space = true;
    let mut in_single = false;
    let mut in_double = false;
    let mut in_line_comment = false;
    let mut in_block_comment = false;

    while let Some(ch) = chars.next() {
        if in_line_comment {
            if ch == '\n' {
                in_line_comment = false;
                last_was_space = true;
            }
            continue;
        }
        if in_block_comment {
            if ch == '*' {
                if let Some('/') = chars.peek().copied() {
                    chars.next();
                    in_block_comment = false;
                }
            }
            continue;
        }

        if in_single {
            if ch == '\'' {
                if matches!(chars.peek(), Some('\'')) {
                    chars.next();
                } else {
                    in_single = false;
                }
            }
            continue;
        }
        if in_double {
            if ch == '"' {
                if matches!(chars.peek(), Some('"')) {
                    chars.next();
                } else {
                    in_double = false;
                }
            }
            continue;
        }

        match ch {
            '\'' => {
                output.push('?');
                last_was_space = false;
                in_single = true;
            }
            '"' => {
                output.push('?');
                last_was_space = false;
                in_double = true;
            }
            '-' => {
                if matches!(chars.peek(), Some('-')) {
                    chars.next();
                    in_line_comment = true;
                    continue;
                }
                push_normalized_char(&mut output, ch, &mut last_was_space);
            }
            '/' => {
                if matches!(chars.peek(), Some('*')) {
                    chars.next();
                    in_block_comment = true;
                    continue;
                }
                push_normalized_char(&mut output, ch, &mut last_was_space);
            }
            '$' => {
                if matches!(chars.peek(), Some(next) if next.is_ascii_digit()) {
                    output.push('?');
                    last_was_space = false;
                    while matches!(chars.peek(), Some(next) if next.is_ascii_digit()) {
                        chars.next();
                    }
                } else {
                    push_normalized_char(&mut output, ch, &mut last_was_space);
                }
            }
            _ if ch.is_ascii_digit() => {
                output.push('?');
                last_was_space = false;
                while matches!(chars.peek(), Some(next) if next.is_ascii_digit() || *next == '.') {
                    chars.next();
                }
            }
            _ if ch.is_whitespace() => {
                if !last_was_space {
                    output.push(' ');
                    last_was_space = true;
                }
            }
            _ => {
                push_normalized_char(&mut output, ch, &mut last_was_space);
            }
        }
    }

    output.trim().to_string()
}

fn push_normalized_char(buffer: &mut String, ch: char, last_was_space: &mut bool) {
    buffer.push(ch.to_ascii_uppercase());
    *last_was_space = false;
}

fn truncate_query(query: &str, max_len: usize) -> String {
    if query.len() <= max_len {
        query.to_owned()
    } else {
        format!("{}...", &query[..max_len])
    }
}

fn fnv1a_hash(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut hash = OFFSET;
    for b in bytes {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}
